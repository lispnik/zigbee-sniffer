(in-package #:zigbee-sniffer.cli)

;;; `zigbee-sniffer inventory FILE...' -- every network and device in saved captures.
;;;
;;; Per PAN: what protocol it speaks, and per device, what it sent, how often, how
;;; strongly, whom it addressed, its vendor or that its address is random, its IPv6
;;; link-local address, and for Thread the router or child an RLOC16 names and the
;;; key sequence in use. Devices only ever addressed are listed separately: they
;;; exist, but are out of range or asleep. Addresses seen fewer than --min-frames
;;; times and never addressed are counted, not listed -- that is what a real address
;;; with a corrupt byte looks like.

(defun print-inventory (report stream)
  (let ((first (field report "first_us")) (last (field report "last_us")))
    (format stream "~&~%Inventory: ~D frame~:P~@[ on channel ~{~D~^, ~}~]~@[, ~A~]~@[ to ~A~]~%"
            (field report "frames")
            (and (field report "channels") (rest (field report "channels")))
            (and first (format-time first :date t))
            (and last (format-time last :date t))))
  (dolist (network (rest (field report "networks")))
    (if (equal (field network "pan") "none")
        (format stream "~%No PAN or addresses: ~D frame~:P (~{~A~^, ~})~%" (field network "frames")
                (loop for (k . v) in (rest (field network "carrying")) collect (format nil "~A ~D" k v)))
        (format stream "~%PAN ~A: ~A, ~D frame~:P~%"
                (field network "pan") (field network "protocol") (field network "frames")))
    (dolist (device (rest (field network "devices")))
      (format stream "  ~A~@[  ~A~]~@[  ~A~]~%"
              (field device "address")
              (or (field device "vendor") (and (search "local" (or (field device "administration") "")) "random"))
              (field device "thread_rloc16"))
      (format stream "      ~D sent~@[ in ~D burst~:P~]~[~:;, ~:*~D addressed to it~]~@[, RSSI median ~D dBm~]~@[ (5-95%: ~D~]~@[ to ~D)~]~@[, every ~,1F s (median)~]~%"
              (field device "frames_sent")
              (let ((bursts (field device "bursts")))
                (and bursts (/= bursts (field device "frames_sent")) bursts))
              (field device "frames_addressed_to")
              (field device "rssi_median") (field device "rssi_p5") (field device "rssi_p95")
              (field device "median_interval_s"))
      (when (field device "first_seen_us")
        (format stream "      heard ~A to ~A~%" (format-time (field device "first_seen_us"))
                (format-time (field device "last_seen_us"))))
      (when (field device "sent")
        (format stream "      sent: ~{~A~^, ~}~%"
                (loop for (k . v) in (rest (field device "sent")) collect (format nil "~A ~D" k v))))
      (when (field device "unicast_peers")
        (format stream "      unicast to: ~{~A~^, ~}~%"
                (loop for (k . v) in (rest (field device "unicast_peers")) collect (format nil "~A (~D)" k v))))
      (when (field device "thread_key_sequences")
        (format stream "      Thread key sequence~P ~:*~{~D~^, ~}~%" (rest (field device "thread_key_sequences"))))
      (when (field device "ipv6_link_local")
        (format stream "      link-local ~A~%" (field device "ipv6_link_local")))
      (let ((beacon (field device "beacon")))
        (when beacon (format stream "      beacon payload: ~A~%" (value-text beacon)))))
    (let ((unheard (field network "addressed_but_not_heard")))
      (when unheard
        (format stream "  addressed but never heard:~%")
        (dolist (device (rest unheard))
          (format stream "      ~A~@[  ~A~]~@[  ~A~]  (addressed ~D time~:P)~%"
                  (field device "address")
                  (or (field device "vendor") (and (search "local" (or (field device "administration") "")) "random"))
                  (field device "thread_rloc16") (field device "frames_addressed_to")))))
    (when (field network "one_off_addresses")
      (format stream "  ~D one-off address~:*~[es~;~:;es~] not listed (typically a real address with a corrupt byte)~%"
              (field network "one_off_addresses"))))
  (when (field report "stray_pans")
    (format stream "~%~D stray PAN~:P with fewer frames than --min-frames not listed (typically a real PAN ID with a corrupt byte)~%"
            (field report "stray_pans"))))

(defun inventory/handler (command)
  (use-oui-option command)
  (let ((files (clingon:command-arguments command))
        (inventory (make-inventory))
        (excluded 0))
    (unless files
      (error "Name one or more pcap files."))
    (dolist (path files)
      (dolist (record (read-pcap path))
        (let ((frame (pcap-frame record)))
          (if (frame-implausibility frame)
              (incf excluded)
              (inventory-add inventory frame :microseconds (record-microseconds record)
                                             :channel (record-channel record))))))
    (let ((report (inventory-report inventory :min-frames (clingon:getopt command :min-frames))))
      (ecase (clingon:getopt command :format)
        (:text (print-inventory report *standard-output*)
               (format t "~%~D implausible frame~:P excluded.~%" excluded))
        (:json (write-json report) (terpri))))))

(register-subcommand
 (clingon:make-command
  :name "inventory"
  :description "list the networks and devices in saved pcap files"
  :usage "[--min-frames N] [--format text|json] FILE.pcap..."
  :options (list (clingon:make-option :integer
                                      :description "list a device only if it sent at least this many frames (or was addressed)"
                                      :long-name "min-frames" :initial-value 3 :key :min-frames)
                 (clingon:make-option :enum
                                      :description "text or json"
                                      :long-name "format" :items '(("text" . :text) ("json" . :json))
                                      :initial-value "text" :key :format)
                 (oui-option))
  :handler (reporting-errors #'inventory/handler)))
