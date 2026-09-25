(in-package #:zigbee-sniffer/tests)

(in-suite zigbee-sniffer)

;;; Decoding. The real frames are from the channel-25 captures; the synthetic ones
;;; cover what those captures never carried -- Zigbee, Thread beacons, MLE in the
;;; clear, MAC commands -- and every field asserted here was checked against tshark
;;; 4.4.6's dissectors when the tests were written. So was every field of the
;;; 13,488 plausible frames in the two channel-25 captures: MAC addresses and PANs,
;;; IPv6 source and destination, UDP ports, MLE security suite, frame counters and
;;; command identifiers, with no disagreement.

(defun layer (layers name) (find-layer layers name))
(defun path (object &rest keys)
  (loop for key in keys while object do (setf object (field object key)))
  object)

(test ipv6-addresses-are-written-per-rfc-5952
  (flet ((text (hex) (zigbee-sniffer::ipv6-string (octets hex))))
    (is (string= "fe80::881:fe47:ff75:c7d4" (text "fe800000000000000881fe47ff75c7d4")))
    (is (string= "ff02::1" (text "ff020000000000000000000000000001")))
    (is (string= "::" (text "00000000000000000000000000000000")))
    (is (string= "2001:db8::1" (text "20010db8000000000000000000000001")))
    ;; A single zero group is not compressed; the first of two equal runs is.
    (is (string= "2001:db8:0:1:1:1:1:1" (text "20010db8000000010001000100010001")))
    (is (string= "2001:0:0:1::1" (text "20010000000000010000000000000001")))))

(test the-resideo-beacon-decodes
  (let* ((layers (decode-frame *beacon-mac*))
         (mac (layer layers "mac")) (beacon (layer layers "beacon")))
    (is (string= "beacon" (field mac "frame_type")))
    (is (string= "0x6ed2" (field mac "source_pan")))
    (is (string= "00:d0:2d:ff:fe:12:e3:cb" (path mac "source" "extended")))
    (is (string= "Resideo" (path mac "source" "vendor")) "from the built-in table")
    (is (string= "universal" (path mac "source" "administration")))
    (is (eq :true (field beacon "pan_coordinator")))
    (is (= 45 (field beacon "payload_length")))
    (is (search "unrecognised" (path beacon "payload" "protocol")))))

(test a-thread-mle-advertisement-decodes
  (let ((layers (decode-frame *mle-mac*)))
    (is (equal '("mac" "6lowpan" "ipv6" "udp" "mle")
               (mapcar (lambda (l) (field l "layer")) layers)))
    (let ((mac (layer layers "mac")) (ipv6 (layer layers "ipv6"))
          (udp (layer layers "udp")) (mle (layer layers "mle")))
      (is (string= "local (random)" (path mac "source" "administration")))
      (is (null (path mac "source" "vendor")) "a random address has no vendor")
      (is (string= "broadcast" (path mac "destination" "meaning")))
      ;; The source address is elided and rebuilt from the MAC source.
      (is (string= "fe80::881:fe47:ff75:c7d4" (field ipv6 "source")))
      (is (string= "ff02::1" (field ipv6 "destination")))
      (is (= 255 (field ipv6 "hop_limit")))
      (is (= 19788 (field udp "source_port")))
      (is (string= "MLE" (field udp "service")))
      (is (eq :true (field mle "secured")))
      (is (= 5 (path mle "security" "level")))
      (is (= #x9a47 (path mle "security" "frame_counter")))
      ;; Key source 00 00 00 16, sent most significant first: key sequence 22,
      ;; and Thread's key index (22 mod 128) + 1.
      (is (= 22 (field mle "key_sequence")))
      (is (= 23 (path mle "security" "key_index")))
      (is (eq :true (field mle "key_index_consistent"))))))

(defparameter *zigbee-beacon*
  (octets "00 80 5A 34 12 00 00 FF CF 00 00  00 22 84 11 22 33 44 55 66 77 88 FF FF FF 00"))
(defparameter *zigbee-secured-data*
  (octets "41 88 07 34 12 00 00 34 12  48 02 00 00 34 12 1E 07
           28 01 00 00 00 88 77 66 55 44 33 22 11 00  AA BB CC DD EE FF 00 11 22 33  01 02 03 04"))
(defparameter *zigbee-aps-broadcast*
  (octets "41 88 08 34 12 FF FF 00 00  08 00 FD FF 00 00 1E 01  08 01 06 00 04 01 01 2A  01 02 03"))
(defparameter *thread-beacon*
  (octets "00 C0 01 CE FA 11 22 33 44 55 66 77 88  FF 0F 00 00
           03 21 4F 70 65 6E 54 68 72 65 61 64 00 00 00 00 00 00 DE AD 00 BE EF 00 CA FE"))
(defparameter *mle-discovery-response*
  (octets "41 CC 09 CE FA 01 02 03 04 05 06 07 08 11 12 13 14 15 16 17 18
           7F 33 F0 4D 4C 4D 4C 00 00  FF 11
           1A 15 81 01 20 02 08 DE AD 00 BE EF 00 CA FE 03 06 4D 79 48 6F 6D 65"))

(test a-zigbee-beacon-decodes
  (let ((payload (path (layer (decode-frame *zigbee-beacon*) "beacon") "payload")))
    (is (string= "zigbee" (field payload "protocol")))
    (is (= 2 (field payload "stack_profile")))
    (is (eq :true (field payload "router_capacity")))
    (is (= 0 (field payload "device_depth")))
    (is (string= "88:77:66:55:44:33:22:11" (field payload "extended_pan_id")))))

(test a-secured-zigbee-nwk-frame-decodes-to-its-ciphertext
  (let* ((layers (decode-frame *zigbee-secured-data*))
         (nwk (layer layers "zigbee-nwk")) (data (layer layers "data")))
    (is (string= "0x1234" (path nwk "source" "short")))
    (is (string= "0x0000" (path nwk "destination" "short")))
    (is (= 30 (field nwk "radius")))
    (is (string= "network key" (path nwk "security" "key_id")))
    (is (= 1 (path nwk "security" "frame_counter")))
    (is (string= "11:22:33:44:55:66:77:88" (path nwk "security" "source" "extended")))
    (is (eq :true (field data "encrypted")))
    (is (= 10 (field data "length")))
    (is (= 4 (field data "mic_length")))))

(test an-unsecured-zigbee-frame-decodes-to-aps
  (let ((aps (layer (decode-frame *zigbee-aps-broadcast*) "zigbee-aps")))
    (is (string= "broadcast" (field aps "delivery")))
    (is (= 1 (field aps "destination_endpoint")) "broadcast delivery still names an endpoint")
    (is (string= "0x0006" (field aps "cluster")))
    (is (string= "Home Automation" (field aps "profile_name")))
    (is (= 42 (field aps "counter")))))

(test a-thread-beacon-decodes
  (let ((payload (path (layer (decode-frame *thread-beacon*) "beacon") "payload")))
    (is (string= "thread" (field payload "protocol")))
    (is (string= "OpenThread" (field payload "network_name")))
    (is (string= "de:ad:00:be:ef:00:ca:fe" (field payload "extended_pan_id")))
    (is (eq :true (field payload "joining_permitted")))
    (is (= 2 (field payload "version")))))

(test an-unsecured-mle-discovery-response-names-its-network
  (let* ((layers (decode-frame *mle-discovery-response*))
         (mle (layer layers "mle"))
         (meshcop (rest (path (second (field mle "tlvs")) "meshcop"))))
    (is (string= "fe80::1a17:1615:1413:1211" (field (layer layers "ipv6") "source")))
    (is (string= "discovery response" (field mle "command")))
    (is (string= "MyHome" (field (find "network name" meshcop :key (lambda (o) (field o "type")) :test #'equal)
                                 "value")))
    (is (string= "de:ad:00:be:ef:00:ca:fe"
                 (field (find "extended PAN ID" meshcop :key (lambda (o) (field o "type")) :test #'equal)
                        "value")))))

(test mac-commands-decode
  (let ((request (layer (decode-frame (octets "23 C8 0B 34 12 00 00 FF FF 01 02 03 04 05 06 07 08 01 8E"))
                        "command"))
        (response (layer (decode-frame (octets "63 CC 0C 34 12 01 02 03 04 05 06 07 08
                                                11 12 13 14 15 16 17 18 02 5A 1B 00"))
                         "command")))
    (is (string= "association request" (field request "name")))
    (is (eq :true (path request "capability" "allocate_address")))
    (is (eq :false (path request "capability" "security_capable")))
    (is (string= "association response" (field response "name")))
    (is (string= "0x1b5a" (field response "assigned_short")))
    (is (string= "success" (field response "status")))))

(test a-truncated-inner-layer-keeps-the-layers-above-it
  (let* ((cut (subseq *mle-discovery-response* 0 45))
         (layers (decode-frame cut)))
    (is (layer layers "mac"))
    (is (layer layers "ipv6"))
    (is (layer layers "udp"))
    (is (or (layer layers "error") (field (layer layers "mle") "error")))))

(test decoding-never-signals
  ;; Every prefix of every fixture decodes to something, without an error escaping.
  (dolist (frame (list *beacon-mac* *mle-mac* *zigbee-beacon* *zigbee-secured-data*
                       *zigbee-aps-broadcast* *thread-beacon* *mle-discovery-response*))
    (loop for end from 0 to (length frame)
          do (is (listp (decode-frame (subseq frame 0 end)))))))

(test json-is-escaped
  (is (string= "{\"a\":\"x\\\"y\\\\z\\n\",\"b\":[1,true,false,null]}"
               (with-output-to-string (s)
                 (write-json (obj "a" (format nil "x\"y\\z~%") "b" (arr (list 1 :true :false :null))) s)))))

(test a-pcap-reads-back-what-was-written
  (let* ((frame (nth-value 1 (parse-message (frame-message *mle-mac*))))
         (bytes (flexi-free-output
                 (lambda (stream)
                   (write-pcap-header stream)
                   (write-pcap-frame stream frame :channel 25 :microseconds 1790286934925614)))))
    (uiop:with-temporary-file (:stream out :pathname path :element-type '(unsigned-byte 8))
      (write-sequence bytes out)
      :close-stream
      (let ((record (first (read-pcap path))))
        (is (= 1790286934925614 (record-microseconds record)))
        (is (= 25 (record-channel record)))
        (is (= (frame-rssi frame) (record-rssi record)))
        (is (= (frame-correlation frame) (record-lqi record)))
        (is (equalp *mle-mac* (record-mac record)))))))

(test the-inventory-counts-devices-and-names-rloc16s
  (let ((inventory (make-inventory)))
    (dotimes (i 5)
      (inventory-add inventory (frame-with *mle-mac*) :microseconds (* i 20000000) :channel 25))
    (inventory-add inventory (frame-with (octets "41 88 01 EE AA 00 D8 00 B0 00 00"))
                   :microseconds 1 :channel 25)
    (inventory-add inventory (frame-with (octets "41 88 02 EE AA 00 D8 00 B0 00 00"))
                   :microseconds 2 :channel 25)
    (inventory-add inventory (frame-with (octets "41 88 03 EE AA 00 D8 00 B0 00 00"))
                   :microseconds 3 :channel 25)
    (let* ((report (inventory-report inventory))
           (network (second (field report "networks")))
           (devices (rest (field network "devices"))))
      (is (string= "0xaaee" (field network "pan")))
      (is (string= "Thread" (field network "protocol")))
      (let ((advertiser (find "0a:81:fe:47:ff:75:c7:d4" devices
                              :key (lambda (d) (field d "address")) :test #'equal)))
        (is (= 5 (field advertiser "frames_sent")))
        (is (= 20.0 (field advertiser "median_interval_s")))
        (is (equal '(22) (rest (field advertiser "thread_key_sequences")))))
      (let ((router (find "0xb000" devices :key (lambda (d) (field d "address")) :test #'equal))
            (unheard (rest (field network "addressed_but_not_heard"))))
        (is (string= "router 44" (field router "thread_rloc16")))
        (is (string= "router 54" (field (first unheard) "thread_rloc16")))))))
