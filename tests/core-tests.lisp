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

;;; --- reassembly --------------------------------------------------------
;;;
;;; The fragments are real: consecutive bulk reads from the channel-25 capture of
;;; 2026-09-24 18:28, each pair logged as two malformed messages before the stream
;;; was reassembled.

(defparameter *split-beacon*
  (list (octets "00 45 00 0F 43 28 90 40 80 C0 2F D2 6E CB E3 12 FE FF 2D D0 00 44 4F 00
                 00 02 00 00 00 00 03 01 00 00 00 00 00 00 6E D2 EE 00 FE 12 E3 CB 00 00")
        (octets "00 00 14 00 01 00 FF FF FF FF 00 FF 52 00 04 00 00 10 40 0F 00 10 EE E4"))
  "A 72-byte beacon message that arrived as 48 + 24.")

(defparameter *split-mle*
  (list (octets "00 4A 00 2C 5F 15 C8 45 41 D8 2D 6D 02")
        (octets "FF FF 0F 61 F2 41 53 FF F3 5E 7F 3B 01 F0 4D 4C 4D 4C BA 69 00 15 71 2B
                 09 00 00 00 00 09 0A 9C CF F3 6B 3C DD 46 8A 49 AA 8F 63 75 27 A4 33 91
                 C7 AE 0D E3 50 70 68 53 DA 13 E3 4D D1 22 E9 E3"))
  "A 77-byte MLE message that arrived as 13 + 64.")

(defparameter *split-noise*
  (list (octets "00 6D 00 8F 07 88 FD 68 68 D8 DE DD F8 F9 FF FF BF 8F AF AA FE BA EE AD
                 9E 4D E0 CF AD AD DF DA 0F E9 DF FA 2F 69 15 00 0C E0 6D 09 AA FB BD BE
                 FD EC A3 EA FF D3 2A 8D FE 18 66 EF A8 FB 2F EE DE 9D 1C CF BF BB FE CF
                 CD E8 D2 EE 68 90 D0 6A E9 DC 58 F1 42 A0 ED 9D AC 14 E1 AA CF 64 35 9D
                 D2 31 42 3A")
        (octets "F2 2B 4D 2F 1F 3E 29 BA B7 FB DB FB"))
  "A 112-byte message of random-looking bytes, split 100 + 12, whose status byte
claims CRC-OK at -110 dBm.")

(defun feed-all (reads)
  (let ((assembler (make-message-assembler)))
    (values (loop for read in reads nconc (assembler-feed assembler read))
            assembler)))

(test split-messages-are-rejoined
  (dolist (pieces (list *split-beacon* *split-mle* *split-noise*))
    (multiple-value-bind (messages assembler) (feed-all pieces)
      (is (= 1 (length messages)))
      (is (equalp (apply #'concatenate '(vector (unsigned-byte 8)) pieces)
                  (first messages)))
      (is (zerop (message-assembler-skipped assembler)))
      (is (eq :frame (parse-message (first messages)))))))

(test a-rejoined-beacon-is-the-beacon
  (let ((frame (nth-value 1 (parse-message (first (feed-all *split-beacon*))))))
    (is-true (frame-crc-ok frame))
    (is (= -91 (frame-rssi frame)))
    (is (eq :beacon (mac-header-frame-type (decode-mac-header (frame-mac frame)))))
    (is (null (frame-implausibility frame)))))

(test a-partial-message-waits-for-the-rest
  (let ((assembler (make-message-assembler)))
    (is (null (assembler-feed assembler (first *split-beacon*))))
    (is (= 1 (length (assembler-feed assembler (second *split-beacon*)))))))

(test several-messages-in-one-read-all-come-out
  (let* ((heartbeat (octets "01 01 00 07"))
         (beacon (frame-message *beacon-mac*))
         (read (concatenate '(vector (unsigned-byte 8)) heartbeat beacon heartbeat)))
    (is (equalp (list heartbeat beacon heartbeat) (feed-all (list read))))))

(test any-split-of-a-stream-reassembles-to-the-same-messages
  (let* ((messages (list (frame-message *beacon-mac*) (octets "01 01 00 07")
                         (frame-message *mle-mac* :ticks 99) (octets "01 01 00 2A")
                         (frame-message (octets "02 00 2A"))))
         (stream (apply #'concatenate '(vector (unsigned-byte 8)) messages))
         (*random-state* (sb-ext:seed-random-state 1802154)))
    (dotimes (trial 200)
      (let ((reads (loop with start = 0
                         while (< start (length stream))
                         collect (let ((end (min (length stream)
                                                 (+ start 1 (random 80)))))
                                   (prog1 (subseq stream start end)
                                     (setf start end))))))
        (is (equalp messages (feed-all reads)))))))

(test garbage-is-skipped-and-counted
  (multiple-value-bind (messages assembler)
      (feed-all (list (octets "FF 07 00 45")
                      (frame-message *beacon-mac*)))
    (is (= 1 (length messages)))
    (is (eq :frame (parse-message (first messages))))
    (is (= 4 (message-assembler-skipped assembler)))))

(test a-reset-drops-a-partial-message
  (let ((assembler (make-message-assembler)))
    (assembler-feed assembler (first *split-beacon*))
    (assembler-reset assembler)
    (is (equalp (list (frame-message *mle-mac*))
                (assembler-feed assembler (frame-message *mle-mac*))))))

;;; --- plausibility ------------------------------------------------------

(defun frame-with (mac &key (rssi -85))
  (make-frame :mac mac :rssi rssi :correlation 100 :crc-ok t))

(test real-frames-are-plausible
  (is (null (frame-implausibility (frame-with *beacon-mac*))))
  (is (null (frame-implausibility (frame-with *mle-mac* :rssi -97))))
  (is (null (frame-implausibility (frame-with (octets "02 00 2A"))))))

(test the-noise-frame-is-implausible
  (let ((frame (nth-value 1 (parse-message (first (feed-all *split-noise*))))))
    (is-true (frame-crc-ok frame) "the radio did claim CRC-OK")
    (is (= -110 (frame-rssi frame)))
    (is (eq :rssi (frame-implausibility frame)))))

(test impossible-frames-are-implausible
  (is (eq :rssi (frame-implausibility (frame-with *beacon-mac* :rssi 53))))
  (is (eq :rssi (frame-implausibility (frame-with *beacon-mac* :rssi -146))))
  ;; Frame types 4-7: reserved, multipurpose, fragment, extended.
  (dolist (type '(4 5 6 7))
    (let ((mac (copy-seq *mle-mac*)))
      (setf (aref mac 0) (logior (logand (aref mac 0) #xf8) type))
      (is (eq :frame-type (frame-implausibility (frame-with mac))))))
  ;; A 2006 acknowledgement carrying addresses, as seen from 0a:81:... at +22 dBm.
  (is (eq :ack (frame-implausibility (frame-with (octets "02 00 2A 01 02")))))
  ;; A 2006 beacon addressed to broadcast: the secured MLE data frame 41 D9 ... with
  ;; its frame type corrupted from data to beacon.
  (is (eq :beacon (frame-implausibility
                   (frame-with (octets "48 D8 37 EE AA FF FF D4 C7 75 FF 47 FE 81 0A 00")))))
  ;; Frame version 3 is reserved.
  (is (eq :version (frame-implausibility (frame-with (octets "41 30 2A EE AA FF FF 34 12")))))
  (is (eq :header (frame-implausibility (frame-with (octets "41"))))))
