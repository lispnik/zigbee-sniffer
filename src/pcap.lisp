;;; pcap output in the IEEE 802.15.4 TAP encapsulation.
;;;
;;; LINKTYPE_IEEE802_15_4_TAP rather than the plain 802.15.4 link types (195 with
;;; FCS, 230 without), which carry the frame and nothing else and would throw away
;;; the two things the radio tells us about every frame: how strong it was and how
;;; well it correlated. TAP prefixes each frame with a small TLV header that
;;; Wireshark reads into named fields.
;;;
;;; The FCS type is declared as None rather than 16-bit CRC, because there is no FCS
;;; left to declare -- the radio overwrote it with RSSI and status. Recomputing a CRC
;;; over the bytes we received and presenting it as the frame's own would be
;;; inventing data, and would be a lie precisely for the frames where it matters, the
;;; corrupt ones.
;;;
;;; The TLV numbers and layout were not taken on trust: a candidate file was fed to
;;; tshark until it named every field, which is how the LQI type is 10 and not the 9
;;; or 11 that were tried alongside it.

(in-package #:zigbee-sniffer)

(defconstant +linktype-ieee802-15-4-tap+ 283)
(defconstant +tap-tlv-fcs-type+ 0)
(defconstant +tap-tlv-rss+ 1)
(defconstant +tap-tlv-channel+ 3)
(defconstant +tap-tlv-lqi+ 10)
(defconstant +tap-fcs-none+ 0)

(defun write-u16 (stream value)
  (write-byte (ldb (byte 8 0) value) stream)
  (write-byte (ldb (byte 8 8) value) stream))

(defun write-u32 (stream value)
  (write-u16 stream (ldb (byte 16 0) value))
  (write-u16 stream (ldb (byte 16 16) value)))

(defun write-pcap-header (stream &key (snaplen 256))
  (write-u32 stream #xa1b2c3d4)         ; magic: little-endian, microsecond timestamps
  (write-u16 stream 2)                  ; version major
  (write-u16 stream 4)                  ; version minor
  (write-u32 stream 0)                  ; thiszone
  (write-u32 stream 0)                  ; sigfigs
  (write-u32 stream snaplen)
  (write-u32 stream +linktype-ieee802-15-4-tap+))

(defun encode-single-float (value)
  "The IEEE 754 binary32 bit pattern of VALUE, as an integer.

By hand from INTEGER-DECODE-FLOAT so the core needs neither CFFI nor an
implementation's internals. Finite values only; TAP's RSS field never needs more."
  (let ((value (float value 1f0)))
    (multiple-value-bind (mantissa exponent sign) (integer-decode-float value)
      (let ((sign-bit (if (minusp sign) #x80000000 0)))
        (cond ((zerop mantissa) sign-bit)
              ;; Subnormal: fewer than 24 significant bits, biased exponent 0.
              ((< mantissa #x800000) (logior sign-bit mantissa))
              (t (logior sign-bit
                         (ash (+ exponent 150) 23)
                         (ldb (byte 23 0) mantissa))))))))

(defun tap-tlv (type value)
  "One TAP TLV: type and length as little-endian 16-bit, then VALUE padded to 4 bytes."
  (let* ((padding (mod (- (length value)) 4))
         (octets (make-array (+ 4 (length value) padding)
                             :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref octets 0) (ldb (byte 8 0) type)
          (aref octets 1) (ldb (byte 8 8) type)
          (aref octets 2) (ldb (byte 8 0) (length value))
          (aref octets 3) (ldb (byte 8 8) (length value)))
    (replace octets value :start1 4)
    octets))

(defun tap-header (&key channel rssi lqi)
  "The TAP pseudo-header that precedes a frame in the capture file."
  (let* ((rss (encode-single-float rssi))
         (tlvs (concatenate '(vector (unsigned-byte 8))
                            (tap-tlv +tap-tlv-fcs-type+ (vector +tap-fcs-none+))
                            (tap-tlv +tap-tlv-rss+
                                     (loop for shift from 0 below 32 by 8
                                           collect (ldb (byte 8 shift) rss)))
                            ;; Channel number (16 bits), then page 0.
                            (tap-tlv +tap-tlv-channel+
                                     (vector (ldb (byte 8 0) channel)
                                             (ldb (byte 8 8) channel) 0))
                            (tap-tlv +tap-tlv-lqi+ (vector lqi))))
         (total (+ 4 (length tlvs))))
    ;; Version 0, reserved 0, then the header length including the TLVs.
    (concatenate '(vector (unsigned-byte 8))
                 (vector 0 0 (ldb (byte 8 0) total) (ldb (byte 8 8) total))
                 tlvs)))

(defun write-pcap-frame (stream frame &key channel microseconds)
  "Write FRAME as one pcap record, stamped MICROSECONDS since the Unix epoch.

The LQI field carries the radio's correlation value, 0-127, which is what the
CC2531 has in place of an 802.15.4 LQI."
  (let ((octets (concatenate '(vector (unsigned-byte 8))
                             (tap-header :channel channel
                                         :rssi (frame-rssi frame)
                                         :lqi (frame-correlation frame))
                             (frame-mac frame))))
    (multiple-value-bind (seconds us) (floor microseconds 1000000)
      (write-u32 stream seconds)
      (write-u32 stream us))
    (write-u32 stream (length octets))
    (write-u32 stream (length octets))
    (write-sequence octets stream)))

;;; --- reading -----------------------------------------------------------

(defstruct (pcap-record (:conc-name record-))
  microseconds channel rssi lqi mac)

(defun read-pcap (path)
  "The IEEE 802.15.4 records in the pcap file at PATH, as a list of PCAP-RECORDs.

Reads what this tool writes -- LINKTYPE_IEEE802_15_4_TAP, whose TLVs give RSS,
channel and LQI -- and the plain 802.15.4 link types, 195 (with a two-octet FCS,
which is stripped) and 230 (without), for which those fields are NIL. Either byte
order; microsecond or nanosecond timestamps."
  (let ((octets (with-open-file (in path :element-type '(unsigned-byte 8))
                  (let ((v (make-array (file-length in) :element-type '(unsigned-byte 8))))
                    (read-sequence v in)
                    v))))
    (when (< (length octets) 24) (error "~A is too short to be a pcap file." path))
    (let* ((magic (little-endian octets 0 4))
           (swapped (member magic '(#xd4c3b2a1 #x4d3cb2a1)))
           (nanoseconds (member magic '(#xa1b23c4d #x4d3cb2a1))))
      (unless (member magic '(#xa1b2c3d4 #xd4c3b2a1 #xa1b23c4d #x4d3cb2a1))
        (error "~A is not a pcap file (magic ~8,'0X); pcapng is not supported." path magic))
      (flet ((u32 (i) (if swapped (big-endian octets i 4) (little-endian octets i 4))))
        (let ((linktype (u32 20)))
          (unless (member linktype '(195 230 283))
            (error "~A has link type ~D, not IEEE 802.15.4 (195, 230 or 283)." path linktype))
          (loop with position = 24
                while (<= (+ position 16) (length octets))
                collect (let* ((seconds (u32 position)) (fraction (u32 (+ position 4)))
                               (length (u32 (+ position 8)))
                               (data (subseq octets (+ position 16)
                                             (min (length octets) (+ position 16 length)))))
                          (incf position (+ 16 length))
                          (let ((record (make-pcap-record
                                         :microseconds (+ (* seconds 1000000)
                                                          (if nanoseconds (floor fraction 1000) fraction)))))
                            (case linktype
                              (195 (setf (record-mac record) (subseq data 0 (max 0 (- (length data) 2)))))
                              (230 (setf (record-mac record) data))
                              (283 (read-tap record data)))
                            record))))))))

(defun read-tap (record data)
  "Fill RECORD from a TAP pseudo-header and the frame after it."
  (let ((header-length (little-endian data 2 2)) (fcs-type 0))
    (loop with position = 4
          while (<= (+ position 4) header-length)
          do (let* ((type (little-endian data position 2))
                    (length (little-endian data (+ position 2) 2))
                    (value (+ position 4)))
               (case type
                 (0 (setf fcs-type (aref data value)))
                 (1 (setf (record-rssi record)
                          (round (decode-single-float (little-endian data value 4)))))
                 (3 (setf (record-channel record) (little-endian data value 2)))
                 (10 (setf (record-lqi record) (aref data value))))
               (incf position (+ 4 length (mod (- length) 4)))))
    (let ((mac (subseq data header-length)))
      (setf (record-mac record)
            (subseq mac 0 (max 0 (- (length mac) (case fcs-type (1 2) (2 4) (t 0)))))))))

(defun decode-single-float (bits)
  "The inverse of ENCODE-SINGLE-FLOAT, for finite values."
  (let ((sign (if (logbitp 31 bits) -1 1))
        (exponent (ldb (byte 8 23) bits))
        (mantissa (ldb (byte 23 0) bits)))
    (* sign (if (zerop exponent)
                (scale-float (float mantissa 1f0) -149)
                (scale-float (float (logior mantissa #x800000) 1f0) (- exponent 150))))))
