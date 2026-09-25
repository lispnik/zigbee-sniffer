(in-package #:zigbee-sniffer)

;;; --- plausibility ------------------------------------------------------
;;;
;;; The status byte's CRC-OK bit is not the last word. Over an hour on channel 25,
;;; about 3% of frames marked CRC-OK were plainly not what was transmitted: MLE
;;; advertisements and beacons with bits flipped throughout, frames of random bytes,
;;; and RSSI readings from -200 to +53 dBm -- which the radio cannot measure. Many
;;; carried the identical trailing pair -34 dBm / LQI 63 under different "sources",
;;; so for those even the status bytes are not the radio's. A 16-bit CRC colliding
;;; accounts for about 0.02 such frames an hour; the dongle's firmware is the likelier
;;; source. Whatever the cause, these are the checks that catch them.

(defconstant +min-plausible-rssi+ -100
  "Below the CC2531's sensitivity (-97 dBm typical), allowing a few dB of spread.")
(defconstant +max-plausible-rssi+ 10
  "Above what the radio can report before saturating.")

(defun frame-implausibility (frame)
  "NIL if FRAME could be a real 2.4 GHz 802.15.4 frame, else a keyword saying why:
:RSSI, :FRAME-TYPE (multipurpose, fragment, extended or reserved, none of which
2.4 GHz O-QPSK devices send), :VERSION (the reserved frame version 3), :ACK (a
2003/2006 acknowledgement is exactly three octets), :BEACON (a 2003/2006 beacon
has no destination address), :RESERVED-BITS (frame control bits 8 and 9, reserved
before 2015), :PAN-ID-COMPRESSION (set in a 2003/2006 frame without both
addresses), :COMMAND (a MAC command identifier 2003/2006 does not define),
:MLE-KEY (an MLE key index that is not the key sequence mod 128 plus one, as Thread
derives it) or :HEADER (too short to hold
the header its frame control field describes)."
  (let ((header (decode-mac-header (frame-mac frame))))
    (cond ((and (frame-rssi frame)
                (not (<= +min-plausible-rssi+ (frame-rssi frame) +max-plausible-rssi+)))
           :rssi)
          ((null header) :header)
          ((not (member (mac-header-frame-type header) '(:beacon :data :ack :command)))
           :frame-type)
          ((= 3 (mac-header-version header)) :version)
          ((and (eq :ack (mac-header-frame-type header))
                (< (mac-header-version header) 2)
                (/= 3 (length (frame-mac frame))))
           :ack)
          ;; Seen as a fingerprint: Thread routers' secured MLE data frames with the
          ;; frame type corrupted to beacon, all at an identical -11 dBm / LQI 119.
          ((and (eq :beacon (mac-header-frame-type header))
                (< (mac-header-version header) 2)
                (mac-header-destination header))
           :beacon)
          ;; Frame control bit 7 is reserved too, but is left alone: the Resideo
          ;; beacons on channels 12, 24 and 25 set it, and they are real.
          ((and (< (mac-header-version header) 2)
                (or (logbitp 0 (aref (frame-mac frame) 1)) (logbitp 1 (aref (frame-mac frame) 1))))
           :reserved-bits)
          ((and (< (mac-header-version header) 2)
                (mac-header-pan-compression header)
                (not (and (mac-header-source header) (mac-header-destination header))))
           :pan-id-compression)
          ((and (eq :command (mac-header-frame-type header))
                (< (mac-header-version header) 2)
                (let ((command (find-layer (decode-frame (frame-mac frame)) "command")))
                  (and command (string= "reserved" (field command "name")))))
           :command)
          ((let ((mle (find-layer (decode-frame (frame-mac frame)) "mle")))
             (and mle (eq :false (field mle "key_index_consistent"))))
           :mle-key)
          (t nil))))
