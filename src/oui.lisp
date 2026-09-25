;;; Who made the radio: vendor names for extended (EUI-64) addresses.
;;;
;;; Two sources. data/oui-802154.tsv, the MA-L assignments of vendors that make
;;; 802.15.4 radios and devices, is read into the image when this file loads, so
;;; vendor names work on any machine. The full IEEE registry is used in preference
;;; wherever the system has one -- the Debian/Raspberry Pi OS ieee-data package puts
;;; it at /usr/share/ieee-data/oui.csv -- or wherever ZIGBEE_SNIFFER_OUI or
;;; --oui-file points, in IEEE CSV or Wireshark manuf format.
;;;
;;; A locally administered address (bit 1 of the first octet set) has no vendor by
;;; definition: Thread in particular gives every device a random extended address per
;;; network. Those are reported as random rather than looked up, because an OUI
;;; lookup of random bits returns a real company that had nothing to do with it.

(in-package #:zigbee-sniffer)

(defun parse-oui (string)
  "The 24-bit OUI in STRING -- \"00:D0:2D\", \"00-D0-2D\" or \"00D02D\" -- or NIL."
  (let ((digits (remove-if-not (lambda (c) (digit-char-p c 16)) string)))
    (and (= 6 (length digits))
         (every (lambda (c) (or (digit-char-p c 16) (member c '(#\: #\- #\Space #\Tab))))
                string)
         (parse-integer digits :radix 16))))

(defun read-oui-tsv (path)
  (let ((table (make-hash-table)))
    (with-open-file (in path :external-format :utf-8)
      (loop for line = (read-line in nil) while line
            unless (or (zerop (length line)) (char= #\# (char line 0)))
              do (let* ((tab (position #\Tab line))
                        (oui (and tab (parse-oui (subseq line 0 tab)))))
                   (when oui (setf (gethash oui table) (subseq line (1+ tab)))))))
    table))

(defparameter *builtin-ouis*
  (read-oui-tsv (asdf:system-relative-pathname "zigbee-sniffer/core" "data/oui-802154.tsv"))
  "The embedded table, read at load time and so saved into the binary.")

(defun csv-fields (line)
  "The fields of one CSV LINE, honouring double quotes."
  (let ((fields '()) (field (make-string-output-stream)) (quoted nil))
    (loop for i from 0 below (length line)
          for c = (char line i)
          do (cond ((and quoted (char= c #\") (< (1+ i) (length line))
                         (char= #\" (char line (1+ i))))
                    (write-char c field) (incf i))
                   ((char= c #\") (setf quoted (not quoted)))
                   ((and (char= c #\,) (not quoted))
                    (push (get-output-stream-string field) fields))
                   (t (write-char c field))))
    (push (get-output-stream-string field) fields)
    (nreverse fields)))

(defun read-oui-registry (path)
  "An OUI table from PATH: IEEE oui.csv (Registry,Assignment,Organization Name,...)
or Wireshark manuf (OUI<TAB>short<TAB>long). Entries other than 24-bit MA-L
assignments are skipped."
  (let ((table (make-hash-table)))
    (with-open-file (in path :external-format :utf-8)
      (loop for line = (read-line in nil) while line
            do (cond ((and (> (length line) 5) (string= "MA-L," line :end2 5))
                      (let ((fields (csv-fields line)))
                        (let ((oui (parse-oui (second fields))))
                          (when oui (setf (gethash oui table) (string-trim " " (third fields)))))))
                     ((and (plusp (length line)) (char/= #\# (char line 0)) (position #\Tab line))
                      (let* ((parts (uiop:split-string line :separator '(#\Tab)))
                             (oui (parse-oui (string-trim " " (first parts)))))
                        (when oui
                          (setf (gethash oui table)
                                (string-trim " " (or (third parts) (second parts))))))))))
    table))

(defparameter *oui-registry-paths*
  '("/usr/share/ieee-data/oui.csv" "/var/lib/ieee-data/oui.csv"
    "/usr/share/wireshark/manuf" "/opt/homebrew/share/wireshark/manuf"))

(defvar *oui-file* nil
  "An OUI registry to use instead of the system's, as --oui-file sets it.")

(defvar *oui-registry* :unloaded)

(defun oui-registry ()
  "The full registry, loaded on first use, or NIL if this machine has none."
  (when (eq *oui-registry* :unloaded)
    (setf *oui-registry*
          (let ((path (find-if #'probe-file
                               (remove nil (list* *oui-file* (uiop:getenv "ZIGBEE_SNIFFER_OUI")
                                                  *oui-registry-paths*)))))
            (and path (ignore-errors (read-oui-registry path))))))
  *oui-registry*)

(defun locally-administered-p (extended-address)
  (logbitp 57 extended-address))        ; bit 1 of the first (most significant) octet

(defun oui-vendor (extended-address)
  "The registered vendor of a universally administered EUI-64, or NIL."
  (unless (locally-administered-p extended-address)
    (let ((oui (ldb (byte 24 40) extended-address)))
      (or (let ((registry (oui-registry))) (and registry (gethash oui registry)))
          (gethash oui *builtin-ouis*)))))
