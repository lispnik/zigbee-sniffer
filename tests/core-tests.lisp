(in-package #:zigbee-sniffer/tests)

(in-suite zigbee-sniffer)

(defun octets (hex)
  "An octet vector from a hex string; whitespace ignored."
  (let ((clean (remove-if-not (lambda (c) (digit-char-p c 16)) hex)))
    (coerce (loop for i from 0 below (length clean) by 2
                  collect (parse-integer clean :start i :end (+ i 2) :radix 16))
            '(vector (unsigned-byte 8)))))

;;; Real frames, captured on channel 25 with a CC2531 on 2026-09-24.

(defparameter *beacon-mac*
  (octets "80c037d26ecbe312feff2dd000444f0000020000000003010000000000006ed2
           ee00fe12e3cb0000000014000100ffffffff00ff520004000010400f0010")
  "A beacon from a Resideo device: 2003 frame, no destination, extended source.
It sets frame-control bit 7, reserved in 2003, which is why Wireshark calls it
malformed -- the bytes passed the radio's CRC.")

(defparameter *mle-mac*
  (octets "41d89feeaaffffd4c775ff47fe810a7f3b01f04d4c4d4ccecd0015479a000000
           0000161709b83c001195b0bb9b8b9b730ccd62e74f016b9ca0e4c3fb2bd13426
           c4260135d9d0ef0c")
  "A Thread MLE advertisement: 2006 data frame, PAN ID compression, broadcast
short destination, extended source.")

(defun frame-message (mac &key (ticks 612506) (rssi-byte #xf2) (status #xd4))
  "MAC wrapped as the dongle sends it: type 0, body length, ticks, frame length,
MAC, RSSI byte and status byte."
  (let* ((frame-length (+ (length mac) 2))
         (body-length (+ 5 frame-length)))
    (concatenate '(vector (unsigned-byte 8))
                 (vector 0 (ldb (byte 8 0) body-length) (ldb (byte 8 8) body-length))
                 (loop for shift from 0 below 32 by 8 collect (ldb (byte 8 shift) ticks))
                 (vector frame-length)
                 mac
                 (vector rssi-byte status))))

;;; --- the stream --------------------------------------------------------

(test the-documented-beacon-message-parses
  (let ((message (frame-message *beacon-mac*)))
    (is (= 72 (length message)))
    (is (equalp (octets "00 45 00 9A 58 09 00 40") (subseq message 0 8)))
    (multiple-value-bind (kind frame) (parse-message message)
      (is (eq :frame kind))
      (is (= 612506 (frame-ticks frame)))
      (is (equalp *beacon-mac* (frame-mac frame)))
      (is (= (- -14 +rssi-offset+) (frame-rssi frame)))
      (is (= #x54 (frame-correlation frame)))
      (is-true (frame-crc-ok frame)))))

(test the-crc-bit-is-the-top-bit-of-the-status-byte
  ;; The frame from the original capture that arrived with one flipped byte.
  (multiple-value-bind (kind frame) (parse-message (frame-message *beacon-mac* :status #x54))
    (is (eq :frame kind))
    (is-false (frame-crc-ok frame))
    (is (= #x54 (frame-correlation frame)))))

(test rssi-is-signed-and-offset
  (flet ((rssi (byte) (frame-rssi (nth-value 1 (parse-message
                                                 (frame-message *beacon-mac* :rssi-byte byte))))))
    (is (= (- 0 +rssi-offset+) (rssi 0)))
    (is (= (- 127 +rssi-offset+) (rssi 127)))
    (is (= (- -128 +rssi-offset+) (rssi 128)))
    (is (= (- -1 +rssi-offset+) (rssi 255)))))

(test heartbeats-are-recognised
  (is (eq :heartbeat (parse-message (octets "01 01 00 07")))))

(test unknown-types-are-reported-not-parsed
  (multiple-value-bind (kind type) (parse-message (octets "07 01 00 00"))
    (is (eq :unknown kind))
    (is (= 7 type))))

(test nothing-is-read-past-the-promised-lengths
  (let ((message (frame-message *beacon-mac*)))
    ;; Every truncation of a good message is malformed, never a short frame.
    (loop for end from 0 below (length message)
          do (is (eq :malformed (parse-message (subseq message 0 end)))
                 "a ~D-byte prefix parsed as something" end)))
  ;; A frame length that overruns its own body.
  (let ((message (copy-seq (frame-message *beacon-mac*))))
    (setf (aref message 7) 200)
    (is (eq :malformed (parse-message message))))
  ;; A frame too short to hold RSSI and status.
  (is (eq :malformed (parse-message (octets "00 07 00 00 00 00 00 02 AA BB")))))

;;; --- the clock ---------------------------------------------------------

(test the-clock-counts-from-the-first-frame
  (let ((clock (make-dongle-clock :base-us 1000000)))
    (is (= 1000000 (dongle-clock-microseconds clock 3200)))
    (is (= 1000100 (dongle-clock-microseconds clock 6400)))))

(test the-clock-survives-a-counter-wrap
  (let ((clock (make-dongle-clock :base-us 0))
        (top (1- (expt 2 32))))
    (is (= 0 (dongle-clock-microseconds clock (- top 31))))
    ;; 64 ticks later, across the wrap: 2 us.
    (is (= 2 (dongle-clock-microseconds clock 32)))
    ;; And still monotonic after a second wrap.
    (dongle-clock-microseconds clock (- top 31))
    (is (= (floor (+ (expt 2 32) 64) 32)
           (dongle-clock-microseconds clock 32)))))

;;; --- 802.15.4 ----------------------------------------------------------

(test a-beacon-header-decodes
  (let ((header (decode-mac-header *beacon-mac*)))
    (is (eq :beacon (mac-header-frame-type header)))
    (is (= 0 (mac-header-version header)))
    (is (= 55 (mac-header-sequence header)))
    (is (= #x6ed2 (mac-header-source-pan header)))
    (is (null (mac-header-destination header)))
    (is (null (mac-header-destination-pan header)))
    (is (string= "00:d0:2d:ff:fe:12:e3:cb" (format-address (mac-header-source header))))
    (is (= 13 (mac-header-length header)))))

(test a-compressed-data-header-decodes
  (let ((header (decode-mac-header *mle-mac*)))
    (is (eq :data (mac-header-frame-type header)))
    (is (= 1 (mac-header-version header)))
    (is (= 159 (mac-header-sequence header)))
    (is-true (mac-header-pan-compression header))
    (is (= #xaaee (mac-header-destination-pan header)))
    (is (= #xffff (mac-header-destination header)))
    ;; Compression: the source's PAN is the destination's, and is reported as such.
    (is (= #xaaee (mac-header-source-pan header)))
    (is (string= "0a:81:fe:47:ff:75:c7:d4" (format-address (mac-header-source header))))
    (is (string= "0xffff" (format-address (mac-header-destination header))))
    (is (= 15 (mac-header-length header)))))

(test an-ack-is-three-octets-of-header
  (let ((header (decode-mac-header (octets "02 00 2A"))))
    (is (eq :ack (mac-header-frame-type header)))
    (is (= 42 (mac-header-sequence header)))
    (is (null (mac-header-source header)))))

(test a-truncated-header-is-nil-not-a-guess
  (loop for end from 0 below 15
        do (is (null (decode-mac-header (subseq *mle-mac* 0 end)))
               "a ~D-byte prefix of a 15-byte header decoded" end)))

(test a-2015-frame-uses-table-7-2
  ;; Data, version 2, short destination and short source, PAN compression: the
  ;; destination PAN is present and the source PAN is not.
  (let ((header (decode-mac-header (octets "41 A8 05 34 12 CD AB 78 56"))))
    (is (= 2 (mac-header-version header)))
    (is (= #x1234 (mac-header-destination-pan header)))
    (is (= #xabcd (mac-header-destination header)))
    (is (= #x5678 (mac-header-source header))))
  ;; Version 2 with the sequence number suppressed.
  (let ((header (decode-mac-header (octets "41 A9 34 12 CD AB 78 56"))))
    (is (null (mac-header-sequence header)))
    (is (= #x5678 (mac-header-source header)))))

;;; --- pcap --------------------------------------------------------------

(test single-floats-encode-as-ieee-754
  (loop for value in (list 0f0 -0f0 1f0 -1f0 -24f0 -90.5f0 0.1f0
                           most-positive-single-float least-positive-normalized-single-float
                           least-positive-single-float)
        do (is (= (ldb (byte 32 0) (sb-kernel:single-float-bits value))
                  (ldb (byte 32 0) (encode-single-float value)))
               "~S" value)))

(test the-tap-header-is-what-tshark-read
  ;; Byte for byte the header of the first record of the channel-25 capture, which
  ;; tshark decoded as FCS None, RSS -24.00 dBm, channel 25 page 0, LQI 90.
  (is (equalp (octets "00002400 000001000000000001000400 0000c0c1 03000300 19000000
                       0a000100 5a000000")
              (tap-header :channel 25 :rssi -24 :lqi 90))))

(test a-pcap-record-carries-the-frame-after-the-tap-header
  (let* ((frame (nth-value 1 (parse-message (frame-message *mle-mac*))))
         (bytes (flexi-free-output
                 (lambda (stream)
                   (write-pcap-header stream)
                   (write-pcap-frame stream frame :channel 25
                                                  :microseconds 1790286934925614)))))
    (is (equalp (octets "d4c3b2a1 0200 0400 00000000 00000000 00010000 1b010000")
                (subseq bytes 0 24)))
    ;; ts_sec, ts_usec, then caplen = len = 36 + the MAC.
    (is (equalp (octets "56 9c b5 6a  ae 1f 0e 00") (subseq bytes 24 32)))
    (is (= (+ 36 (length *mle-mac*))
           (ldb (byte 16 0) (logior (aref bytes 32) (ash (aref bytes 33) 8)))))
    (is (equalp *mle-mac* (subseq bytes (+ 40 36))))))

(defun flexi-free-output (function)
  "The octets FUNCTION writes to a binary stream, via a temporary file: standard CL
has no in-memory binary output stream."
  (uiop:with-temporary-file (:stream stream :pathname path
                             :element-type '(unsigned-byte 8) :direction :output)
    (funcall function stream)
    :close-stream
    (with-open-file (in path :element-type '(unsigned-byte 8))
      (let ((octets (make-array (file-length in) :element-type '(unsigned-byte 8))))
        (read-sequence octets in)
        octets))))
