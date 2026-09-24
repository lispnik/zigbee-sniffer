(in-package #:zigbee-sniffer.cli)

;;; --- options shared between subcommands --------------------------------

(defun device-option ()
  (clingon:make-option :string
                       :description "the dongle to use, as BUS:ADDRESS from `zigbee-sniffer list' (default: the only one attached)"
                       :short-name #\d :long-name "device" :key :device))

(defun channel-option (&key (initial-value 25))
  (clingon:make-option :integer
                       :description "802.15.4 channel, 11-26"
                       :short-name #\c :long-name "channel"
                       :initial-value initial-value :key :channel))

(defun check-channel (channel)
  (unless (channel-p channel)
    (error "802.15.4 channels are 11 to 26, not ~A." channel))
  channel)

(defun parse-channels (string)
  "\"11-26\", \"15,20,25\" or a mix of the two, as a list of channels."
  (loop for part in (uiop:split-string string :separator ",")
        for dash = (position #\- part)
        for from = (parse-integer part :end dash)
        for to = (if dash (parse-integer part :start (1+ dash)) from)
        nconc (loop for channel from from to to
                    collect (check-channel channel))))

;;; --- time --------------------------------------------------------------

(defun format-time (microseconds &key date)
  "Local wall-clock time for MICROSECONDS since the Unix epoch:
HH:MM:SS.uuuuuu, with the date in front when DATE is true."
  (multiple-value-bind (seconds us) (floor microseconds 1000000)
    (multiple-value-bind (sec min hour day month year)
        (decode-universal-time (+ seconds +unix-epoch-universal-time+))
      (format nil "~:[~*~;~{~4,'0D-~2,'0D-~2,'0D ~}~]~2,'0D:~2,'0D:~2,'0D.~6,'0D"
              date (list year month day) hour min sec us))))

(defun monotonic-seconds ()
  (/ (get-internal-real-time) (float internal-time-units-per-second 1d0)))

;;; --- frames ------------------------------------------------------------

(defun frame-summary (frame &key channel microseconds)
  "One line describing FRAME, tcpdump-style."
  (let ((header (decode-mac-header (frame-mac frame))))
    (with-output-to-string (s)
      (format s "~A  ch~D ~4D dBm lqi ~3D  ~:[BAD-CRC ~;~]"
              (format-time microseconds) channel
              (frame-rssi frame) (frame-correlation frame) (frame-crc-ok frame))
      (if (null header)
          (format s "(truncated header)")
          (progn
            (format s "~8A" (frame-type-name (mac-header-frame-type header)))
            (when (mac-header-sequence header)
              (format s " seq ~3D" (mac-header-sequence header)))
            (let ((pan (or (mac-header-destination-pan header)
                           (mac-header-source-pan header))))
              (when pan (format s "  pan 0x~(~4,'0x~)" pan)))
            (let ((source (mac-header-source header))
                  (destination (mac-header-destination header)))
              (cond ((and source destination)
                    (format s "  ~A -> ~A" (format-address source)
                            (format-address destination)))
                    (source (format s "  src ~A" (format-address source)))
                    (destination (format s "  dst ~A" (format-address destination)))))
            (when (mac-header-security header) (format s "  secured"))))
      (format s "  ~D B" (length (frame-mac frame))))))

(defun hexdump (octets &key (stream *standard-output*) (indent "    "))
  (loop for start from 0 below (length octets) by 16
        for end = (min (length octets) (+ start 16))
        do (format stream "~A~4,'0X  ~{~(~2,'0x~)~^ ~}~%" indent start
                   (coerce (subseq octets start end) 'list))))

(defun hex (octets)
  (format nil "~{~2,'0X~^ ~}" (coerce octets 'list)))

;;; --- stats -------------------------------------------------------------

(defstruct stats
  (frames 0) (bad-crc 0) (written 0) (heartbeats 0) (malformed 0) (unknown 0)
  (rssi-sum 0) (rssi-max nil)
  (pans '()) (sources '()))

(defun count-frame (stats frame)
  (incf (stats-frames stats))
  (incf (stats-rssi-sum stats) (frame-rssi frame))
  (setf (stats-rssi-max stats) (max (frame-rssi frame)
                                    (or (stats-rssi-max stats) (frame-rssi frame))))
  (if (not (frame-crc-ok frame))
      (incf (stats-bad-crc stats))
      ;; Only from frames that passed CRC: a corrupt frame can decode as a PAN or a
      ;; device that does not exist.
      (let ((header (decode-mac-header (frame-mac frame))))
        (when header
          (dolist (pan (list (mac-header-destination-pan header)
                             (mac-header-source-pan header)))
            (when (and pan (/= pan #xffff))
              (pushnew pan (stats-pans stats))))
          (let ((source (mac-header-source header)))
            (when source
              (pushnew source (stats-sources stats) :test #'equal)))))))

(defun stats-rssi-mean (stats)
  (and (plusp (stats-frames stats))
       (/ (stats-rssi-sum stats) (float (stats-frames stats)))))

;;; --- stopping ----------------------------------------------------------
;;;
;;; C-c and SIGTERM ask a capture to stop rather than killing it, so the transfers
;;; are cancelled, the radio is powered down and the summary is printed -- which
;;; also makes `timeout 60 zigbee-sniffer capture ...' a clean run rather than an
;;; aborted one. The handler only sets a flag, which the receive loop polls; it can
;;; run on any thread, including libusb's, so it must not do more than that. A
;;; second signal while the first is being honoured exits at once.

(sb-ext:defglobal **stop-requested** nil)

(defun request-stop (signal info context)
  (declare (ignore signal info context))
  (if **stop-requested**
      (sb-ext:exit :code 130 :abort t)
      (setf **stop-requested** t)))

(defun call-with-stop-signals (function)
  (setf **stop-requested** nil)
  (sb-sys:enable-interrupt sb-unix:sigint #'request-stop)
  (sb-sys:enable-interrupt sb-unix:sigterm #'request-stop)
  (funcall function))

(defmacro with-stop-signals (() &body body)
  `(call-with-stop-signals (lambda () ,@body)))

(defun stop-requested-p () **stop-requested**)
