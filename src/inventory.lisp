;;; What is on the air: networks and devices, from decoded frames.
;;;
;;; Fed one frame at a time -- live from a capture, or from pcap files afterwards --
;;; and reported as an object (INVENTORY-REPORT), so the CLI can print it or write it
;;; as JSON. Only frames that passed CRC and every plausibility check go in.
;;;
;;; Everything reported is read off the frames. The one thing it will not do is match
;;; a Thread RLOC16 to an extended address: nothing in the clear links them, and
;;; guessing by signal strength is for a human reading the report, not for the report.

(in-package #:zigbee-sniffer)

(defstruct device
  address                               ; as FORMAT-ADDRESS writes it
  address-object
  (frames 0)                            ; transmitted by it
  (addressed 0)                         ; addressed to it
  first-us last-us
  (rssi '())
  (times '())
  (kinds (make-hash-table :test #'equal))    ; what it sent -> count
  (peers (make-hash-table :test #'equal))    ; unicast destinations -> count
  (key-sequences '())
  beacon)                               ; the last decoded beacon payload

(defstruct network
  pan
  (frames 0)
  (kinds (make-hash-table :test #'equal))
  (protocols (make-hash-table :test #'equal))
  (devices (make-hash-table :test #'equal)))

(defstruct (inventory (:constructor make-inventory ()))
  (networks (make-hash-table))
  (frames 0) (excluded 0)
  first-us last-us
  (channels '()))

(defun frame-kind (layers)
  "A short name for what a frame carries, for counting."
  (let ((mac (find-layer layers "mac"))
        (beacon (find-layer layers "beacon"))
        (command (find-layer layers "command"))
        (mle (find-layer layers "mle"))
        (nwk (find-layer layers "zigbee-nwk"))
        (udp (find-layer layers "udp"))
        (icmp (find-layer layers "icmpv6"))
        (data (find-layer layers "data")))
    (cond (beacon (format nil "beacon (~A)"
                          (or (field (field beacon "payload") "protocol") "no payload")))
          (command (format nil "command: ~A" (field command "name")))
          (mle (if (eq (field mle "secured") :true)
                   "MLE (encrypted)"
                   (format nil "MLE ~A" (field mle "command"))))
          (nwk (format nil "Zigbee NWK ~A~:[~; (encrypted)~]" (field nwk "frame_type") (field nwk "security")))
          (icmp (format nil "ICMPv6 ~A" (or (field icmp "name") (field icmp "type"))))
          (udp (format nil "UDP ~A" (or (field udp "service") (field udp "destination_port"))))
          ((find-layer layers "6lowpan") "6LoWPAN")
          ((and data (eq (field data "encrypted") :true)) "MAC-encrypted data")
          (t (field mac "frame_type")))))

(defun network-protocol (kind)
  (cond ((search "MLE" kind) "Thread")
        ((search "thread" kind) "Thread")
        ((search "Zigbee" kind) "Zigbee")
        ((search "zigbee" kind) "Zigbee")
        ((search "beacon (unrecognised" kind) "proprietary beacons")
        ((or (search "UDP" kind) (search "6LoWPAN" kind) (search "ICMPv6" kind)) "6LoWPAN")))

(defun inventory-add (inventory frame &key microseconds channel)
  "Count FRAME, which the caller has already checked."
  (let* ((layers (decode-frame (frame-mac frame)))
         (mac (find-layer layers "mac")))
    (incf (inventory-frames inventory))
    (when microseconds
      (setf (inventory-first-us inventory) (min microseconds (or (inventory-first-us inventory) microseconds))
            (inventory-last-us inventory) (max microseconds (or (inventory-last-us inventory) microseconds))))
    (when channel (pushnew channel (inventory-channels inventory)))
    (when mac
      (let* ((pan-text (or (field mac "source_pan") (field mac "destination_pan")))
             (pan (if pan-text (parse-integer pan-text :start 2 :radix 16) :none))
             (network (or (gethash pan (inventory-networks inventory))
                          (setf (gethash pan (inventory-networks inventory)) (make-network :pan pan))))
             (kind (frame-kind layers))
             (source (field mac "source"))
             (destination (field mac "destination")))
        (incf (network-frames network))
        (incf (gethash kind (network-kinds network) 0))
        (let ((protocol (network-protocol kind)))
          (when protocol (incf (gethash protocol (network-protocols network) 0))))
        (flet ((device (object)
                 (let ((key (or (field object "extended") (field object "short"))))
                   (or (gethash key (network-devices network))
                       (setf (gethash key (network-devices network))
                             (make-device :address key :address-object object))))))
          (when source
            (let ((device (device source)))
              (incf (device-frames device))
              (when microseconds
                (push microseconds (device-times device))
                (setf (device-first-us device) (min microseconds (or (device-first-us device) microseconds))
                      (device-last-us device) (max microseconds (or (device-last-us device) microseconds))))
              (push (frame-rssi frame) (device-rssi device))
              (incf (gethash kind (device-kinds device) 0))
              (let ((sequence (field (find-layer layers "mle") "key_sequence")))
                (when sequence (pushnew sequence (device-key-sequences device))))
              (let ((beacon (field (find-layer layers "beacon") "payload")))
                (when beacon (setf (device-beacon device) beacon)))
              (when (and destination (not (field destination "meaning")))
                (incf (gethash (or (field destination "extended") (field destination "short"))
                               (device-peers device) 0)))))
          (when (and destination (not (field destination "meaning")))
            (incf (device-addressed (device destination)))))))))

(defun percentile (list fraction)
  (when list
    (let ((sorted (sort (copy-list list) #'<)))
      (nth (min (1- (length sorted)) (floor (* fraction (length sorted)))) sorted))))

(defun median (list) (percentile list 1/2))

(defun hash-counts (table)
  "TABLE as an object of key -> count, largest first."
  (let ((pairs '()))
    (maphash (lambda (k v) (push (cons k v) pairs)) table)
    (cons :object (sort pairs #'> :key #'cdr))))

(defun thread-rloc16 (short)
  "What a short address means as a Thread RLOC16."
  (let* ((value (parse-integer short :start 2 :radix 16))
         (router (ash value -10))
         (child (ldb (byte 9 0) value)))
    (if (zerop child)
        (format nil "router ~D" router)
        (format nil "child ~D of router ~D" child router))))

(defparameter *burst-gap-us* 100000
  "Frames closer together than this are one transmission repeated: Thread routers
send each advertisement two or three times a few milliseconds apart. Intervals are
measured between bursts.")

(defun inventory-report (inventory &key (min-frames 3))
  "The inventory as an object. What corruption the checks cannot catch looks like
a real address or PAN with a byte wrong, seen once, so: a device that sent fewer
than MIN-FRAMES frames is counted but not listed unless it was also addressed at
least twice; a device never heard is listed only if addressed at least twice; and
a network with fewer than MIN-FRAMES frames is counted, not listed."
  (let ((networks '()) (stray 0))
    (maphash
     (lambda (pan network)
       (let* ((protocols (hash-counts (network-protocols network)))
              (protocol (car (second protocols)))
              (thread (equal protocol "Thread"))
              (heard '()) (unheard '()) (one-off 0))
         (maphash
          (lambda (key device)
            (declare (ignore key))
            (let* ((times (sort (copy-list (device-times device)) #'<))
                   (gaps (remove-if (lambda (gap) (< gap *burst-gap-us*))
                                    (mapcar #'- (rest times) times)))
                   (object (device-address-object device))
                   (entry (obj "address" (device-address device)
                               "vendor" (field object "vendor")
                               "administration" (field object "administration")
                               "thread_rloc16" (and thread (field object "short")
                                                    (thread-rloc16 (field object "short")))
                               "ipv6_link_local" (and (member protocol '("Thread" "6LoWPAN") :test #'equal)
                                                      (field object "ipv6_link_local"))
                               "frames_sent" (device-frames device)
                               "frames_addressed_to" (device-addressed device)
                               "rssi_median" (median (device-rssi device))
                               ;; Percentiles, not extremes: one corrupt frame that passed
                               ;; every check would otherwise set the range.
                               "rssi_p5" (percentile (device-rssi device) 1/20)
                               "rssi_p95" (percentile (device-rssi device) 19/20)
                               "first_seen_us" (device-first-us device)
                               "last_seen_us" (device-last-us device)
                               "median_interval_s" (and gaps (/ (median gaps) 1000000.0))
                               "bursts" (and times (1+ (length gaps)))
                               "sent" (and (plusp (device-frames device)) (hash-counts (device-kinds device)))
                               "unicast_peers" (and (plusp (hash-table-count (device-peers device)))
                                                    (hash-counts (device-peers device)))
                               "thread_key_sequences" (and (device-key-sequences device)
                                                           (arr (sort (copy-list (device-key-sequences device)) #'<)))
                               "beacon" (device-beacon device))))
              (cond ((plusp (device-frames device))
                     (if (and (< (device-frames device) min-frames) (< (device-addressed device) 2))
                         (incf one-off)
                         (push entry heard)))
                    ((>= (device-addressed device) 2) (push entry unheard))
                    (t (incf one-off)))))
          (network-devices network))
         (if (and (< (network-frames network) min-frames) (not (eq pan :none)))
             (incf stray)
         (push (obj "pan" (if (eq pan :none) "none" (hex16 pan))
                    "protocol" (or protocol "unknown")
                    "frames" (network-frames network)
                    "protocols" protocols
                    "devices" (arr (sort heard #'> :key (lambda (e) (field e "frames_sent"))))
                    "addressed_but_not_heard" (and unheard (arr unheard))
                    "one_off_addresses" (and (plusp one-off) one-off)
                    "carrying" (hash-counts (network-kinds network)))
               networks))))
     (inventory-networks inventory))
    (obj "frames" (inventory-frames inventory)
         "channels" (and (inventory-channels inventory) (arr (sort (copy-list (inventory-channels inventory)) #'<)))
         "first_us" (inventory-first-us inventory)
         "last_us" (inventory-last-us inventory)
         "networks" (arr (sort networks #'> :key (lambda (n) (field n "frames"))))
         "stray_pans" (and (plusp stray) stray))))
