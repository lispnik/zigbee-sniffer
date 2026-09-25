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

The CC253x user guide (SWRU191F, 23.9.7) documents the two octets that replace the
FCS: RSSI, signed, then CRC_OK in bit 7 with the correlation value in bits 6-0. The
CC2531 data sheet (SWRS086A) gives the RSSI/CCA offset as 73 dB, with an absolute
uncalibrated accuracy of +/-4 dB -- so every dBm figure here is good to about 4 dB,
and none is a calibration of this particular dongle.

It matters more than it looks. Uncorrected, a capture of a neighbour's thermostat
reads -17 dBm -- the level of a transmitter a few centimetres away -- while losing a
third of its frames to CRC failures. Corrected, it reads -90 dBm, a few dB above the
radio's sensitivity, which is exactly where a third of frames failing CRC belongs.")

(defstruct frame
  "One captured 802.15.4 frame, as the dongle reported it."
  (ticks 0 :type (unsigned-byte 32))    ; the dongle's 1/32 us counter
  (mac #() :type vector)                ; the MAC frame, less its FCS
  ;; RSSI and correlation are NIL for a frame read from a pcap that did not record
  ;; them (the plain 802.15.4 link types).
  (rssi 0 :type (or null integer))      ; dBm, with +RSSI-OFFSET+ applied
  (correlation 0 :type (or null (integer 0 255))) ; the radio's LQI stand-in
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

;;; --- reassembly --------------------------------------------------------
;;;
;;; The bulk endpoint is a byte stream, not a message stream. Most reads carry
;;; exactly one message, which is how the one-read-one-message assumption survived
;;; the first captures -- but over an hour on a busy channel about one message in a
;;; hundred arrives split across two consecutive reads, at any offset: 48 + 24 bytes
;;; of one 72-byte beacon message, 13 + 64 of a 77-byte MLE one. Parsed per read,
;;; both halves are malformed and the frame is lost; worse, a tail can happen to
;;; parse, and becomes a frame of arbitrary bytes.
;;;
;;; So the reads are concatenated in arrival order -- libusb completes transfers on
;;; one endpoint in submission order, and the mailbox keeps it -- and messages are
;;; cut from the front by their own length fields. A header that cannot be right is
;;; skipped a byte at a time until one that can be is found, and the bytes skipped
;;; are counted rather than hidden.

(defconstant +max-frame-length+ 127
  "The largest 802.15.4 PSDU, FCS included -- and so the largest frame-length byte.")

(defstruct (message-assembler (:constructor make-message-assembler ()))
  (buffer (make-array 512 :element-type '(unsigned-byte 8) :fill-pointer 0 :adjustable t))
  (skipped 0))                          ; octets discarded to regain alignment

(defun plausible-header-p (buffer)
  "Whether BUFFER starts with a header that could be a message: :YES, :NO, or :MORE
if it cannot tell yet."
  (let ((length (length buffer)))
    (cond ((< length 3) :more)
          (t (let ((type (aref buffer 0))
                   (body-length (little-endian buffer 1 2)))
               (case type
                 ;; Every heartbeat seen has had a 1-byte body.
                 (1 (if (<= 1 body-length 4) :yes :no))
                 (0 (cond ((not (<= 8 body-length (+ 5 +max-frame-length+))) :no)
                          ((< length 8) :more)
                          ;; The frame-length byte must agree with the body length.
                          ((= (aref buffer 7) (- body-length 5)) :yes)
                          (t :no)))
                 (t :no)))))))

(defun assembler-feed (assembler octets)
  "Append one bulk read to ASSEMBLER. Returns the complete messages now available,
oldest first; a partial message stays buffered for the next read."
  (let ((buffer (message-assembler-buffer assembler))
        (messages '()))
    (loop for octet across octets do (vector-push-extend octet buffer))
    (loop
      (ecase (plausible-header-p buffer)
        (:more (return))
        (:no
         ;; Drop one byte and look again.
         (replace buffer buffer :start2 1)
         (decf (fill-pointer buffer))
         (incf (message-assembler-skipped assembler)))
        (:yes
         (let ((end (+ 3 (little-endian buffer 1 2))))
           (when (< (length buffer) end) (return))
           (push (subseq buffer 0 end) messages)
           (replace buffer buffer :start2 end)
           (decf (fill-pointer buffer) end)))))
    (nreverse messages)))

(defun assembler-reset (assembler)
  "Discard any partial message, as after retuning: its tail would belong to a
frame from the old channel."
  (setf (fill-pointer (message-assembler-buffer assembler)) 0))
