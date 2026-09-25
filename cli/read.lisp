(in-package #:zigbee-sniffer.cli)

;;; `zigbee-sniffer read FILE...' -- decode saved captures, as `capture' would have
;;; printed them.
;;;
;;; Reads this tool's own pcaps (IEEE 802.15.4 TAP, with RSSI, channel and LQI) and
;;; the plain 802.15.4 link types 195 and 230 that other sniffers write. A pcap
;;; carries no CRC verdict -- this tool writes only frames that passed unless told
;;; otherwise -- so the plausibility checks are the ones applied here.

(defun pcap-frame (record)
  (make-frame :mac (record-mac record) :rssi (record-rssi record)
              :correlation (record-lqi record) :crc-ok t))

(defun read/handler (command)
  (use-oui-option command)
  (let ((files (clingon:command-arguments command))
        (keep (clingon:getopt command :implausible))
        (format (clingon:getopt command :format))
        (decode (clingon:getopt command :decode))
        (hex-p (clingon:getopt command :hex))
        (shown 0) (excluded 0))
    (unless files
      (error "Name one or more pcap files to read."))
    (handler-case
        (dolist (path files)
          (dolist (record (read-pcap path))
            (let* ((frame (pcap-frame record))
                   (verdict (frame-implausibility frame)))
              (if (and verdict (not keep))
                  (incf excluded)
                  (progn
                    (incf shown)
                    (emit-frame *standard-output* frame
                                :channel (record-channel record)
                                :microseconds (record-microseconds record)
                                :verdict verdict :format format :decode decode :hex hex-p))))))
      ;; `| head': the reader is done, and so are we.
      (stream-error () (return-from read/handler)))
    (finish-output)
    (format *error-output* "~&~D frame~:P shown~[~:;, ~:*~D implausible excluded (--implausible keeps them)~]~%"
            shown excluded)))

(register-subcommand
 (clingon:make-command
  :name "read"
  :description "decode saved pcap files: every layer, as text or JSON lines"
  :usage "[-V] [--format text|jsonl] [--implausible] FILE.pcap..."
  :options (append (list (clingon:make-option :flag
                                              :description "include frames that fail the plausibility checks, marked"
                                              :long-name "implausible" :key :implausible))
                   (output-options))
  :handler (reporting-errors #'read/handler)))
