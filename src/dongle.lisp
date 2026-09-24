;;; The CC2531 and TI's packet-sniffer firmware, over libusb.
;;;
;;; The firmware's whole interface is six vendor requests on endpoint 0 and one bulk
;;; IN endpoint, 0x83, that carries the stream parsed in stream.lisp:
;;;
;;;   0xC0  GET_IDENT  IN, 8 bytes: 31 25 31 05 02 00 01 00 on the dongle this was
;;;                    written against. What the fields mean is not documented and
;;;                    is not guessed at here; it is shown as hex.
;;;   0xC5  SET_POWER  OUT, wIndex 4 powers the radio, 0 powers it down
;;;   0xC6  GET_POWER  IN, 1 byte: the power register
;;;   0xD0  SET_START  OUT: start forwarding frames on the bulk endpoint
;;;   0xD1  SET_END    OUT: stop
;;;   0xD2  SET_CHAN   OUT, one data byte: the channel's low byte at wIndex 0, its
;;;                    high byte at wIndex 1 -- two requests, not one
;;;
;;; The same dongle flashed with the Z-Stack coordinator firmware that zigbee2mqtt
;;; uses enumerates as 0451:16A8, a CDC serial port, and none of the above applies.
;;; FIND-DONGLES reports those too, so `list' can say why a dongle will not sniff.

(in-package #:zigbee-sniffer)

(export '(+vendor-id+ +sniffer-product-id+ +z-stack-product-id+ +bulk-endpoint+
          find-dongles dongle-firmware device-location parse-device-location
          find-sniffer with-sniffer
          get-ident get-power radio-on radio-off set-channel start-capture stop-capture
          with-capture capture-channel receive-message change-channel capture-failure))

(defconstant +vendor-id+ #x0451)
(defconstant +sniffer-product-id+ #x16ae)
(defconstant +z-stack-product-id+ #x16a8)
(defconstant +bulk-endpoint+ #x83)

(defconstant +get-ident+ #xc0)
(defconstant +set-power+ #xc5)
(defconstant +get-power+ #xc6)
(defconstant +set-start+ #xd0)
(defconstant +set-end+   #xd1)
(defconstant +set-chan+  #xd2)

(defconstant +power-on+ #x04)

;;; --- finding one -------------------------------------------------------

(defun dongle-firmware (device)
  "What DEVICE is running, going by its product ID: :SNIFFER, :Z-STACK or NIL."
  (and (= (libusb:device-vendor-id device) +vendor-id+)
       (case (libusb:device-product-id device)
         (#.+sniffer-product-id+ :sniffer)
         (#.+z-stack-product-id+ :z-stack))))

(defun find-dongles (&key (context (libusb:default-context)))
  "Every CC2531 on the machine, with either firmware. The caller unrefs them."
  (libusb:list-devices :context context :filter #'dongle-firmware))

(defun device-location (device)
  "BUS:ADDRESS, as lsusb prints it and as --device takes it."
  (format nil "~3,'0D:~3,'0D"
          (libusb:device-bus-number device) (libusb:device-address device)))

(defun parse-device-location (string)
  "(VALUES BUS ADDRESS) from \"1:22\" or \"001:022\", or signal."
  (let ((colon (position #\: string)))
    (or (and colon
             (let ((bus (parse-integer string :end colon :junk-allowed t))
                   (address (parse-integer string :start (1+ colon) :junk-allowed t)))
               (and bus address (values bus address))))
        (error "~S is not a device location; expected BUS:ADDRESS, as in 001:022." string))))

;;; --- one open dongle ---------------------------------------------------

(defun vendor-out (handle request &key (index 0) (data #()))
  (libusb:control-transfer handle :direction :out :type :vendor :recipient :device
                                  :request request :index index :data data
                                  :timeout 1000))

(defun vendor-in (handle request length)
  (libusb:control-transfer handle :type :vendor :recipient :device
                                  :request request :length length :timeout 1000))

(defun get-ident (handle)
  "The firmware's 8-byte identity, as an octet vector."
  (vendor-in handle +get-ident+ 8))

(defun get-power (handle)
  "The radio's power register: 4 when it is on."
  (aref (vendor-in handle +get-power+ 1) 0))

(defun radio-on (handle)
  "Power the radio and wait for the dongle to confirm it. Returns the register.

The wait is not optional: SET_POWER returns as soon as the request is accepted,
and a channel set before the radio has come up is silently ignored."
  (vendor-out handle +set-power+ :index +power-on+)
  (loop repeat 50
        for power = (get-power handle)
        when (= power +power-on+) return power
        do (sleep 0.05)
        finally (error "The CC2531 radio did not power up (power register ~D)." power)))

(defun radio-off (handle)
  (vendor-out handle +set-power+ :index 0))

(defun set-channel (handle channel)
  (unless (channel-p channel)
    (error "802.15.4 channels are 11 to 26, not ~S." channel))
  (vendor-out handle +set-chan+ :index 0 :data (vector (ldb (byte 8 0) channel)))
  (vendor-out handle +set-chan+ :index 1 :data (vector (ldb (byte 8 8) channel))))

(defun start-capture (handle) (vendor-out handle +set-start+))
(defun stop-capture (handle) (vendor-out handle +set-end+))

(defun find-sniffer (context location)
  "The sniffer-firmware dongle at LOCATION, or the only one if LOCATION is NIL."
  (let ((dongles (find-dongles :context context)))
    (unwind-protect
         (let ((candidates
                 (remove-if-not
                  (lambda (device)
                    (and (eq :sniffer (dongle-firmware device))
                         (or (null location)
                             (multiple-value-bind (bus address)
                                 (parse-device-location location)
                               (and (= bus (libusb:device-bus-number device))
                                    (= address (libusb:device-address device)))))))
                  dongles)))
           (cond ((and location (null candidates))
                  (error "No CC2531 with sniffer firmware at ~A. `zigbee-sniffer list' ~
                          shows what is attached." location))
                 ((null candidates)
                  (error "No CC2531 with sniffer firmware (~4,'0x:~4,'0x) is attached.~@[ ~
                          ~D dongle~:P ~:*~[~;is~:;are~] running Z-Stack instead.~]"
                         +vendor-id+ +sniffer-product-id+
                         (let ((z (count :z-stack dongles :key #'dongle-firmware)))
                           (and (plusp z) z))))
                 ((rest candidates)
                  (error "~D sniffer dongles are attached (~{~A~^, ~}); choose one with ~
                          --device." (length candidates)
                         (mapcar #'device-location candidates)))
                 (t (setf dongles (remove (first candidates) dongles))
                    (first candidates))))
      (mapc #'libusb:unref-device dongles))))

(defmacro with-sniffer ((handle &key location) &body body)
  "Open the sniffer dongle at LOCATION (or the only one), claim its interface, and
bind HANDLE for BODY. Its own libusb context, released however BODY ends -- and the
radio stopped and powered down on the way, so an interrupted capture does not
leave a dongle streaming into a buffer nobody reads."
  (let ((context (gensym "CONTEXT")) (device (gensym "DEVICE")))
    `(libusb:with-context (,context)
       (let ((,device (find-sniffer ,context ,location)))
         (unwind-protect
              (libusb:with-device-handle (,handle ,device)
                (libusb:with-claimed-interface (,handle 0)
                  (unwind-protect (progn ,@body)
                    (ignore-errors (stop-capture ,handle))
                    (ignore-errors (radio-off ,handle)))))
           (libusb:unref-device ,device))))))

;;; --- streaming ---------------------------------------------------------

(defstruct (capture (:constructor %make-capture))
  handle
  channel
  (mailbox (sb-concurrency:make-mailbox :name "cc2531 messages"))
  (transfers '())
  (stopping nil)
  ;; Set from the event thread when a transfer ends in something other than
  ;; completion or timeout -- the dongle unplugged, most often. Read by
  ;; RECEIVE-MESSAGE, which signals it on the caller's thread.
  (failure nil))

(defparameter *in-flight* 8
  "Bulk transfers queued on the endpoint at once.

More than one matters for a sniffer: with a single transfer there is a window
between a completion and its resubmission during which the dongle has nowhere to
put a frame, and what it does then is drop it silently. Eight 256-byte transfers is
far more slack than 802.15.4's 250 kbit/s can use.")

(defun transfer-completed (capture transfer)
  "Completion callback, on libusb's event thread. Queue the bytes and resubmit.

Deliberately does nothing else: parsing and writing happen on the caller's thread,
so the output stream has one writer and the endpoint is never without a transfer
for longer than a copy takes."
  (let ((status (libusb:transfer-status transfer)))
    (case status
      (:completed
       (sb-concurrency:send-message (capture-mailbox capture)
                                    (libusb:transfer-data transfer)))
      (:timed-out)
      (:cancelled (return-from transfer-completed))
      (t (setf (capture-failure capture)
               (format nil "bulk transfer ended ~(~A~)~:[~; -- the dongle was unplugged~]"
                       status (eq status :no-device)))
         (return-from transfer-completed)))
    (unless (capture-stopping capture)
      (handler-case (libusb:submit-transfer transfer)
        (error (condition)
          (setf (capture-failure capture) (princ-to-string condition)))))))

(defun open-capture (handle channel)
  (let ((capture (%make-capture :handle handle :channel channel)))
    (radio-on handle)
    (set-channel handle channel)
    (dotimes (i *in-flight*)
      (push (libusb:make-usb-transfer
             handle :type :bulk :endpoint +bulk-endpoint+ :length 256 :timeout 0
                    :function (lambda (transfer) (transfer-completed capture transfer)))
            (capture-transfers capture)))
    (start-capture handle)
    (mapc #'libusb:submit-transfer (capture-transfers capture))
    capture))

(defun close-capture (capture)
  "Stop the radio, then cancel, drain and free every transfer.

The radio first, so nothing new arrives while the transfers are being cancelled.
Then the flag, so a completing callback stops resubmitting -- but one already past
the check can still resubmit once after its cancel, hence cancelling in rounds
until nothing is left in flight. Freeing a transfer libusb still owns is a
use-after-free, so the rounds are not tidiness."
  (setf (capture-stopping capture) t)
  (ignore-errors (stop-capture (capture-handle capture)))
  (let ((transfers (capture-transfers capture)))
    (loop repeat 5
          for in-flight = (remove :submitted transfers
                                  :key #'libusb:transfer-state :test-not #'eq)
          while in-flight
          do (dolist (transfer in-flight)
               (ignore-errors (libusb:cancel-transfer transfer :drain t :timeout 2))))
    (dolist (transfer transfers)
      (ignore-errors (libusb:free-usb-transfer transfer)))))

(defmacro with-capture ((capture handle &key channel) &body body)
  "Stream from HANDLE on CHANNEL for BODY, with CAPTURE bound for RECEIVE-MESSAGE.

libusb's events are handled on a thread of their own for the duration, so BODY is
free to block, write, and be interrupted: every transfer is stopped and freed, and
the event thread joined, however BODY ends."
  (let ((h (gensym "HANDLE")))
    `(let ((,h ,handle))
       (libusb:with-event-pump ((libusb:handle-context ,h) :tick 0.1)
         (let ((,capture (open-capture ,h ,channel)))
           (unwind-protect (progn ,@body)
             (close-capture ,capture)))))))

(defun receive-message (capture &key (timeout 0.25))
  "The next raw message from the dongle, or NIL if none came within TIMEOUT seconds.
Signals if the stream has failed."
  (let ((failure (capture-failure capture)))
    (when failure (error "Capture failed: ~A." failure)))
  (sb-concurrency:receive-message (capture-mailbox capture) :timeout timeout))

(defun change-channel (capture channel)
  "Retune a running capture. Messages already queued from the old channel are
discarded, so none is attributed to the new one."
  (let ((handle (capture-handle capture)))
    (stop-capture handle)
    ;; A frame the dongle had already handed to USB before SET_END can still
    ;; complete. Let it land, then throw it and everything before it away.
    (sleep 0.05)
    (sb-concurrency:receive-pending-messages (capture-mailbox capture))
    (set-channel handle channel)
    (setf (capture-channel capture) channel)
    (start-capture handle)))
