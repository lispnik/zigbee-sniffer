;;; The IEEE 802.15.4 MAC header: enough to say what a frame is and who sent it.
;;;
;;; This is for the live summary line and the survey, not a dissector -- Wireshark
;;; is the dissector, and the pcap carries every byte. So it stops at the addressing
;;; fields, and says so (NIL) rather than guessing when a frame is too short to hold
;;; the header its own frame control field describes.

(in-package #:zigbee-sniffer)

(defstruct mac-header
  frame-type          ; :beacon :data :ack :command :multipurpose :fragment :extended :reserved
  version             ; 0 = 2003, 1 = 2006, 2 = 2015
  security frame-pending ack-request pan-compression
  sequence            ; NIL when suppressed (2015 frames only)
  destination-pan destination     ; PAN IDs and short addresses are integers,
  source-pan source               ; extended addresses (:extended . integer)
  length)             ; octets of header decoded

(defparameter *frame-types*
  #(:beacon :data :ack :command :reserved :multipurpose :fragment :extended))

(defun frame-type-name (frame-type)
  (case frame-type
    (:beacon "Beacon") (:data "Data") (:ack "Ack") (:command "Command")
    (:multipurpose "Multipurpose") (:fragment "Fragment") (:extended "Extended")
    (t "Reserved")))

(defun pan-ids-present (version destination-mode source-mode pan-compression)
  "(VALUES DESTINATION-PAN-P SOURCE-PAN-P) for a frame's addressing modes.

2003 and 2006 frames follow one rule: each address present carries its PAN ID
unless PAN ID compression elides the source's. 2015 frames replace that rule with
IEEE 802.15.4-2015 table 7-2, which also depends on which address kinds are present."
  (let ((dst (/= destination-mode 0))
        (src (/= source-mode 0)))
    (if (< version 2)
        (values dst (and src (not pan-compression)))
        (cond ((and (not dst) (not src)) (values pan-compression nil))
              ((and dst (not src))       (values (not pan-compression) nil))
              ((and (not dst) src)       (values nil (not pan-compression)))
              ;; Both present.
              ((and (= destination-mode 3) (= source-mode 3))
               (values (not pan-compression) nil))
              (t (values t (not pan-compression)))))))

(defun decode-mac-header (octets)
  "Decode the MAC header at the start of OCTETS, or return NIL if it will not fit.

Multipurpose, fragment and extended frames have a different frame control layout;
for those only the frame type is reported."
  (when (< (length octets) 2)
    (return-from decode-mac-header nil))
  (let* ((fcf (logior (aref octets 0) (ash (aref octets 1) 8)))
         (frame-type (aref *frame-types* (ldb (byte 3 0) fcf))))
    (unless (member frame-type '(:beacon :data :ack :command))
      (return-from decode-mac-header
        (make-mac-header :frame-type frame-type :length 2)))
    (let* ((version (ldb (byte 2 12) fcf))
           (pan-compression (logbitp 6 fcf))
           (sequence-suppressed (and (>= version 2) (logbitp 8 fcf)))
           (destination-mode (ldb (byte 2 10) fcf))
           (source-mode (ldb (byte 2 14) fcf))
           (position 2)
           (header (make-mac-header :frame-type frame-type
                                    :version version
                                    :security (logbitp 3 fcf)
                                    :frame-pending (logbitp 4 fcf)
                                    :ack-request (logbitp 5 fcf)
                                    :pan-compression pan-compression)))
      ;; Mode 1 is reserved in 2003/2006; there is no length to give it.
      (when (or (= destination-mode 1) (= source-mode 1))
        (return-from decode-mac-header nil))
      (flet ((take (count)
               (when (> (+ position count) (length octets))
                 (return-from decode-mac-header nil))
               (prog1 (little-endian octets position count)
                 (incf position count)))
             (address-length (mode) (ecase mode (0 0) (2 2) (3 8))))
        (unless sequence-suppressed
          (setf (mac-header-sequence header) (take 1)))
        (multiple-value-bind (destination-pan-p source-pan-p)
            (pan-ids-present version destination-mode source-mode pan-compression)
          (when destination-pan-p
            (setf (mac-header-destination-pan header) (take 2)))
          (unless (zerop destination-mode)
            (let ((address (take (address-length destination-mode))))
              (setf (mac-header-destination header)
                    (if (= destination-mode 3) (cons :extended address) address))))
          (when source-pan-p
            (setf (mac-header-source-pan header) (take 2)))
          (unless (zerop source-mode)
            (let ((address (take (address-length source-mode))))
              (setf (mac-header-source header)
                    (if (= source-mode 3) (cons :extended address) address))))
          ;; With PAN ID compression in a 2003/2006 frame the source shares the
          ;; destination's PAN. Reporting it saves every caller the rule.
          (when (and (< version 2) pan-compression (mac-header-source header)
                     (null (mac-header-source-pan header)))
            (setf (mac-header-source-pan header) (mac-header-destination-pan header)))))
      (setf (mac-header-length header) position)
      header)))

(defun format-address (address)
  "An address as Wireshark writes it: 0x1234 for short, colon-separated big-endian
octets for extended, and \"-\" for none."
  (cond ((null address) "-")
        ((consp address)
         (format nil "~{~(~2,'0x~)~^:~}"
                 (loop for shift from 56 downto 0 by 8
                       collect (ldb (byte 8 shift) (cdr address)))))
        (t (format nil "0x~(~4,'0x~)" address))))
