;;; The dongle's stream format, read off the wire rather than out of a datasheet.
;;;
;;; Every bulk read on endpoint 0x83 yields one message: a 3-byte header of a type
;;; byte and a little-endian body length, then the body. Type 0x01 is a 1-byte timer
;;; heartbeat. Type 0x00 is a captured frame: a 32-bit little-endian timestamp in
;;; units of 1/32 us, a length byte, and that many bytes of 802.15.4 -- except that
;;; the radio has overwritten the frame's two-byte FCS with a signed RSSI byte and a
;;; status byte whose top bit is CRC-OK and whose low seven are the correlation value.
;;;
;;; A real 72-byte message, a beacon captured on channel 25:
;;;
;;;   00            type: a captured frame
;;;   45 00         69 bytes follow
;;;   9A 58 09 00   timestamp 612506 ticks, so 19140.8 us
;;;   40            64 bytes of MAC frame and trailing status
;;;   80 C0 ... 10  62 bytes of 802.15.4
;;;   F2            RSSI byte -14
;;;   D4            top bit set: the CRC checked out; correlation 84
;;;
;;; That parse is not a guess. In a twelve-message capture one frame arrived with a
;;; single flipped byte and its status byte was 0x54 rather than 0xD4 -- CRC-OK clear,
;;; exactly where this layout says it should be.

(in-package #:zigbee-sniffer)

(defconstant +rssi-offset+ 73
  "Subtracted from the radio's RSSI byte to give dBm.

The byte is the CC2530-family RSSI register value, which the datasheet defines as
offset from the power at the antenna by about 73 dB. The value is the datasheet's
typical figure, not a calibration of this dongle.

It matters more than it looks. Uncorrected, a capture of a neighbour's thermostat
reads -17 dBm -- the level of a transmitter a few centimetres away -- while losing a
third of its frames to CRC failures. Corrected, it reads -90 dBm, a few dB above the
radio's sensitivity, which is exactly where a third of frames failing CRC belongs.")

(defstruct frame
  "One captured 802.15.4 frame, as the dongle reported it."
  (ticks 0 :type (unsigned-byte 32))    ; the dongle's 1/32 us counter
  (mac #() :type vector)                ; the MAC frame, less its FCS
  (rssi 0 :type integer)                ; dBm, with +RSSI-OFFSET+ applied
  (correlation 0 :type (integer 0 127)) ; the radio's LQI stand-in
  (crc-ok nil))

(defun little-endian (octets start count)
  (loop for i below count
        sum (ash (aref octets (+ start i)) (* 8 i))))

(defun parse-message (octets)
  "Parse one bulk read from the dongle.

Returns (VALUES KIND DETAIL):
  :FRAME      a FRAME
  :HEARTBEAT  NIL -- the dongle's periodic timer tick
  :MALFORMED  a string saying what did not add up
  :UNKNOWN    the type byte, for a message type this parser has never seen

Nothing is read past what the message's own lengths promise, and nothing that
disagrees with them is trusted: a short read is :MALFORMED, not a frame with its
tail missing."
  (let ((length (length octets)))
    (when (< length 3)
      (return-from parse-message (values :malformed (format nil "~D-byte message" length))))
    (let ((type (aref octets 0))
          (body-length (little-endian octets 1 2)))
      (when (< length (+ 3 body-length))
        (return-from parse-message
          (values :malformed (format nil "header promises ~D bytes of body, ~D arrived"
                                     body-length (- length 3)))))
      (case type
        (1 (values :heartbeat nil))
        (0
         (when (< body-length 5)
           (return-from parse-message
             (values :malformed (format nil "~D-byte frame body" body-length))))
         (let ((ticks (little-endian octets 3 4))
               (frame-length (aref octets 7)))
           ;; Two of those bytes are RSSI and status, so fewer than three is not a
           ;; frame at all.
           (cond ((< frame-length 3)
                  (values :malformed (format nil "~D-byte frame" frame-length)))
                 ((< body-length (+ 5 frame-length))
                  (values :malformed
                          (format nil "frame length ~D overruns a ~D-byte body"
                                  frame-length body-length)))
                 (t
                  (let* ((end (+ 8 frame-length))
                         (rssi-byte (aref octets (- end 2)))
                         (status (aref octets (- end 1))))
                    (values :frame
                            (make-frame :ticks ticks
                                        :mac (subseq octets 8 (- end 2))
                                        :rssi (- (if (> rssi-byte 127)
                                                     (- rssi-byte 256)
                                                     rssi-byte)
                                                 +rssi-offset+)
                                        :correlation (logand status #x7f)
                                        :crc-ok (logbitp 7 status))))))))
        (t (values :unknown type))))))

;;; --- the dongle's clock ------------------------------------------------

(defconstant +unix-epoch-universal-time+ 2208988800
  "Universal time at 1970-01-01T00:00:00Z.")

(defun unix-microseconds-now ()
  (multiple-value-bind (seconds microseconds) (sb-ext:get-time-of-day)
    (+ (* seconds 1000000) microseconds)))

(defstruct (dongle-clock (:constructor make-dongle-clock (&key base-us)))
  (base-us nil)                         ; host time at the first frame
  (first-tick nil)
  (previous-tick 0)
  (wraps 0))

(defun dongle-clock-microseconds (clock ticks)
  "Unix time in microseconds for a dongle counter reading TICKS.

BASE-US, if the clock was made with one, is the Unix time of the first frame;
otherwise the host clock is read when the first frame arrives.

The dongle counts 1/32 us in 32 bits, so it wraps every 134 seconds; a reading
lower than the last one means it has. Anchoring to the host clock only at the
first frame keeps the intervals between frames exactly as the radio measured them
rather than as a Lisp process happened to notice them.

Call it for every frame in arrival order, including ones that will not be written:
skipping a frame must not be able to hide a wrap."
  (with-accessors ((first dongle-clock-first-tick)
                   (previous dongle-clock-previous-tick)
                   (wraps dongle-clock-wraps)) clock
    (unless first
      ;; The host clock is read here, at the first frame, not when the clock was
      ;; made: a quiet channel can take seconds to produce one, and every
      ;; timestamp in the capture would be early by that much.
      (setf first ticks previous ticks)
      (unless (dongle-clock-base-us clock)
        (setf (dongle-clock-base-us clock) (unix-microseconds-now))))
    (when (< ticks previous)
      (incf wraps))
    (setf previous ticks)
    (+ (dongle-clock-base-us clock)
       (floor (- (+ ticks (* wraps (expt 2 32))) first) 32))))

;;; --- channels ----------------------------------------------------------

(defun channel-p (channel)
  "True for an 802.15.4 2.4 GHz O-QPSK channel, the only band the CC2531 has."
  (and (integerp channel) (<= 11 channel 26)))

(defun channel-frequency-mhz (channel)
  (+ 2405 (* 5 (- channel 11))))
