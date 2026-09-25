;;; Decoding a frame all the way down: MAC, then whatever the payload turns out to be.
;;;
;;; DECODE-FRAME returns a list of layers, each an ordered object built with OBJ, so
;;; one structure feeds the one-line summary, the indented tree and JSON alike:
;;;
;;;   mac       frame control, addresses (with vendor or "random", and the IPv6
;;;             link-local address each implies), security auxiliary header,
;;;             2015 header IEs
;;;   beacon    superframe, GTS, pending addresses, and a Zigbee or Thread beacon
;;;             payload when the protocol ID says which
;;;   command   MAC command and its arguments
;;;   6lowpan   mesh, fragment and IPHC headers
;;;   ipv6      addresses rebuilt from IPHC -- from the MAC addresses when elided
;;;   udp / icmpv6
;;;   mle       Thread's link-establishment protocol: its security header, or the
;;;             command and TLVs when sent in the clear
;;;   zigbee-nwk / zigbee-aps
;;;   data      whatever is left: its length, and whether it is ciphertext
;;;
;;; Decoding stops, and says why, at the first thing it cannot read: ciphertext, a
;;; subsequent fragment, a header that runs off the end. It never guesses past one.

(in-package #:zigbee-sniffer)

;;; --- the object model --------------------------------------------------

(defun obj (&rest keys-and-values)
  "An ordered object (:OBJECT (KEY . VALUE)...). Pairs whose value is NIL are
omitted, so optional fields are simply left out; use :TRUE and :FALSE for booleans."
  (cons :object
        (loop for (key value) on keys-and-values by #'cddr
              when value collect (cons key value))))

(defun bool (x) (if x :true :false))
(defun arr (items) (cons :array items))

(defun field (object key)
  "KEY's value in OBJECT, or NIL."
  (cdr (assoc key (rest object) :test #'string=)))

(defun find-layer (layers name)
  (find name layers :key (lambda (layer) (field layer "layer")) :test #'equal))

(defun hex-string (octets &key (start 0) (end (length octets)))
  (with-output-to-string (s)
    (loop for i from start below end do (format s "~(~2,'0x~)" (aref octets i)))))

(defun colon-hex (octets)
  "OCTETS in transmission order, colon-separated, as extended PAN IDs are written."
  (format nil "~{~(~2,'0x~)~^:~}" (coerce octets 'list)))

(defun hex16 (n) (format nil "0x~(~4,'0x~)" n))
(defun hex8 (n) (format nil "0x~(~2,'0x~)" n))

(define-condition truncated (error) ((what :initarg :what :reader truncated-what))
  (:report (lambda (c s) (format s "truncated ~A" (truncated-what c)))))

(defmacro with-cursor ((octets position) &body body)
  "BODY with TAKE (n) reading N little-endian octets as an integer, TAKE-BYTES (n)
reading them as a vector, and REMAINING, all over OCTETS from POSITION on."
  `(macrolet ((take (n &optional (what "field"))
                `(progn (when (> (+ ,',position ,n) (length ,',octets))
                          (error 'truncated :what ,what))
                        (prog1 (little-endian ,',octets ,',position ,n)
                          (incf ,',position ,n))))
              (take-bytes (n &optional (what "field"))
                `(progn (when (> (+ ,',position ,n) (length ,',octets))
                          (error 'truncated :what ,what))
                        (prog1 (subseq ,',octets ,',position (+ ,',position ,n))
                          (incf ,',position ,n))))
              (remaining () `(- (length ,',octets) ,',position)))
     ,@body))

;;; --- addresses ---------------------------------------------------------

(defun ipv6-string (octets)
  "RFC 5952 text for a 16-octet IPv6 address."
  (let* ((groups (loop for i from 0 below 16 by 2
                       collect (logior (ash (aref octets i) 8) (aref octets (1+ i)))))
         (best-start nil) (best-length 1))
    ;; The longest run of two or more zero groups becomes "::" (the first, on a tie).
    (loop with start = nil
          for i from 0 to 8
          for zero = (and (< i 8) (zerop (nth i groups)))
          do (cond ((and zero (null start)) (setf start i))
                   ((and (not zero) start)
                    (when (> (- i start) best-length)
                      (setf best-start start best-length (- i start)))
                    (setf start nil))))
    (flet ((hexes (list) (format nil "~{~(~x~)~^:~}" list)))
      (if best-start
          (format nil "~A::~A" (hexes (subseq groups 0 best-start))
                  (hexes (subseq groups (+ best-start best-length))))
          (hexes groups)))))

(defun octets-of (integer count)
  "INTEGER as COUNT big-endian octets."
  (let ((v (make-array count :element-type '(unsigned-byte 8))))
    (dotimes (i count v)
      (setf (aref v i) (ldb (byte 8 (* 8 (- count 1 i))) integer)))))

(defun interface-id (address)
  "The IPv6 interface identifier a MAC ADDRESS implies (RFC 4944 / 6282): an EUI-64
with its universal/local bit inverted, or 0000:00ff:fe00:XXXX for a short address."
  (if (consp address)
      (let ((iid (octets-of (cdr address) 8)))
        (setf (aref iid 0) (logxor (aref iid 0) 2))
        iid)
      (concatenate '(vector (unsigned-byte 8))
                   (vector 0 0 0 #xff #xfe 0) (octets-of address 2))))

(defun link-local (address)
  (concatenate '(vector (unsigned-byte 8))
               (vector #xfe #x80 0 0 0 0 0 0) (interface-id address)))

(defun address-object (address)
  "An address with what can be said about it without context."
  (cond ((consp address)
         (let* ((value (cdr address))
                (local (locally-administered-p value)))
           (obj "extended" (format-address address)
                "vendor" (oui-vendor value)
                "administration" (if local "local (random)" "universal")
                "group" (and (logbitp 56 value) :true)
                "ipv6_link_local" (ipv6-string (link-local address)))))
        (t (obj "short" (hex16 address)
                "meaning" (case address (#xffff "broadcast") (#xfffe "no short address"))))))

;;; --- MAC ---------------------------------------------------------------

(defun mic-length (level) (aref #(0 4 8 16 0 4 8 16) level))

(defun decode-aux-security (octets position &key (frame-counter t))
  "The IEEE 802.15.4 auxiliary security header at POSITION.
Returns (VALUES OBJECT NEW-POSITION LEVEL). Also used by MLE, which borrows it."
  (with-cursor (octets position)
    (let* ((control (take 1 "security control"))
           (level (ldb (byte 3 0) control))
           (key-id-mode (ldb (byte 2 3) control))
           (suppressed (and (not frame-counter) (logbitp 5 control)))
           (counter (unless suppressed (take 4 "frame counter")))
           ;; The key source is sent most significant octet first -- for Thread,
           ;; 00 00 00 17 is key sequence 23 -- unlike every other field here.
           (key-source (case key-id-mode
                         (2 (big-endian (take-bytes 4 "key source") 0 4))
                         (3 (big-endian (take-bytes 8 "key source") 0 8))))
           (key-index (when (plusp key-id-mode) (take 1 "key index"))))
      (values (obj "level" level
                   "level_name" (aref #("none" "MIC-32" "MIC-64" "MIC-128"
                                        "ENC" "ENC-MIC-32" "ENC-MIC-64" "ENC-MIC-128")
                                      level)
                   "key_id_mode" key-id-mode
                   "frame_counter" counter
                   "key_source" (and key-source (format nil "0x~(~v,'0x~)"
                                                        (if (= key-id-mode 2) 8 16) key-source))
                   "key_index" key-index)
              position
              level))))

(defun decode-header-ies (octets position)
  "2015 header IEs up to a termination IE. (VALUES LIST POSITION PAYLOAD-IES-P)."
  (let ((ies '()))
    (with-cursor (octets position)
      (loop while (>= (remaining) 2)
            do (let* ((descriptor (take 2 "IE descriptor"))
                      (length (ldb (byte 7 0) descriptor))
                      (id (ldb (byte 8 7) descriptor)))
                 (take-bytes length "IE")
                 (cond ((= id #x7e) (return-from decode-header-ies (values (nreverse ies) position t)))
                       ((= id #x7f) (return-from decode-header-ies (values (nreverse ies) position nil)))
                       (t (push (obj "id" (hex8 id) "length" length) ies)))))
      (values (nreverse ies) position nil))))

;;; --- beacons -----------------------------------------------------------

(defun decode-beacon-payload (octets)
  "A beacon payload, when its protocol ID is one we know."
  (when (plusp (length octets))
    (case (aref octets 0)
      (0 (when (>= (length octets) 15)
           (let ((b1 (aref octets 1)) (b2 (aref octets 2)))
             (obj "protocol" "zigbee"
                  "stack_profile" (ldb (byte 4 0) b1)
                  "protocol_version" (ldb (byte 4 4) b1)
                  "router_capacity" (bool (logbitp 2 b2))
                  "device_depth" (ldb (byte 4 3) b2)
                  "end_device_capacity" (bool (logbitp 7 b2))
                  "extended_pan_id" (format-address (cons :extended (loop for i from 3 below 11
                                                                           sum (ash (aref octets i) (* 8 (- i 3))))))
                  "tx_offset" (little-endian octets 11 3)
                  "update_id" (aref octets 14)))))
      (3 (when (>= (length octets) 26)
           (let ((flags (aref octets 1)))
             (obj "protocol" "thread"
                  "version" (ldb (byte 4 4) flags)
                  "native_commissioner" (bool (logbitp 3 flags))
                  "joining_permitted" (bool (logbitp 0 flags))
                  "network_name" (string-right-trim '(#\Nul) (map 'string #'code-char (subseq octets 2 18)))
                  "extended_pan_id" (colon-hex (subseq octets 18 26))))))
      (t nil))))

(defun decode-beacon (octets position)
  (with-cursor (octets position)
    (let* ((superframe (take 2 "superframe specification"))
           (gts (take 1 "GTS specification"))
           (gts-count (ldb (byte 3 0) gts)))
      (when (plusp gts-count)
        (take 1 "GTS directions")
        (take-bytes (* 3 gts-count) "GTS list"))
      (let* ((pending (take 1 "pending address specification"))
             (shorts (loop repeat (ldb (byte 3 0) pending) collect (take 2 "pending address")))
             (longs (loop repeat (ldb (byte 3 4) pending)
                          collect (cons :extended (take 8 "pending address"))))
             (payload (take-bytes (remaining))))
        (obj "layer" "beacon"
             "beacon_order" (ldb (byte 4 0) superframe)
             "superframe_order" (ldb (byte 4 4) superframe)
             "final_cap_slot" (ldb (byte 4 8) superframe)
             "battery_life_extension" (bool (logbitp 12 superframe))
             "pan_coordinator" (bool (logbitp 14 superframe))
             "association_permit" (bool (logbitp 15 superframe))
             "gts_descriptors" gts-count
             "pending_addresses" (and (or shorts longs)
                                      (arr (mapcar #'format-address (append shorts longs))))
             "payload_length" (length payload)
             "payload" (or (decode-beacon-payload payload)
                           (and (plusp (length payload))
                                (obj "protocol" (format nil "unrecognised (first octet ~A)"
                                                        (hex8 (aref payload 0)))
                                     "hex" (hex-string payload)))))))))

;;; --- MAC commands ------------------------------------------------------

(defparameter *mac-commands*
  #(nil "association request" "association response" "disassociation notification"
    "data request" "PAN ID conflict notification" "orphan notification"
    "beacon request" "coordinator realignment" "GTS request"))

(defun decode-command (octets position)
  (with-cursor (octets position)
    (let* ((id (take 1 "command identifier"))
           (name (and (< id (length *mac-commands*)) (aref *mac-commands* id))))
      (apply #'obj "layer" "command" "id" (hex8 id) "name" (or name "reserved")
             (case id
               (1 (let ((cap (take 1 "capability information")))
                    (list "capability"
                          (obj "full_function_device" (bool (logbitp 1 cap))
                               "mains_powered" (bool (logbitp 2 cap))
                               "receiver_on_when_idle" (bool (logbitp 3 cap))
                               "security_capable" (bool (logbitp 6 cap))
                               "allocate_address" (bool (logbitp 7 cap))))))
               (2 (let ((short (take 2 "short address")) (status (take 1 "status")))
                    (list "assigned_short" (hex16 short)
                          "status" (case status (0 "success") (1 "PAN at capacity")
                                     (2 "access denied") (t (hex8 status))))))
               (3 (let ((reason (take 1 "reason")))
                    (list "reason" (case reason (1 "coordinator wishes device to leave")
                                     (2 "device wishes to leave") (t (hex8 reason))))))
               (t '()))))))

;;; --- 6LoWPAN, IPv6, UDP --------------------------------------------------

(defconstant +mle-port+ 19788)
(defconstant +tmf-port+ 61631)

(defun decode-iphc (octets position source destination)
  "RFC 6282 IPHC at POSITION. SOURCE and DESTINATION are the MAC addresses, for
addresses the header elides. (VALUES 6LOWPAN-FIELDS IPV6-OBJECT NEXT-HEADER
NHC-P POSITION)."
  (with-cursor (octets position)
    (let* ((b0 (take 1 "IPHC")) (b1 (take 1 "IPHC"))
           (tf (ldb (byte 2 3) b0)) (nh (logbitp 2 b0)) (hlim (ldb (byte 2 0) b0))
           (cid (logbitp 7 b1)) (sac (logbitp 6 b1)) (sam (ldb (byte 2 4) b1))
           (m (logbitp 3 b1)) (dac (logbitp 2 b1)) (dam (ldb (byte 2 0) b1))
           (contexts (when cid (take 1 "context identifier")))
           (tc-flow (case tf (0 (take 4 "traffic class")) (1 (take 3 "traffic class"))
                      (2 (take 1 "traffic class")) (3 nil)))
           (next-header (unless nh (take 1 "next header")))
           (hop-limit (case hlim (0 (take 1 "hop limit")) (1 1) (2 64) (3 255))))
      (labels ((prefixed (prefix tail) (concatenate '(vector (unsigned-byte 8)) prefix tail))
               (fe80 (tail)
                 (let ((v (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                   (setf (aref v 0) #xfe (aref v 1) #x80)
                   (replace v tail :start1 (- 16 (length tail)))))
               (stateless (mode mac-address)
                 (ecase mode
                   (0 (take-bytes 16 "address"))
                   (1 (fe80 (take-bytes 8 "address")))
                   (2 (fe80 (concatenate '(vector (unsigned-byte 8)) (vector 0 0 0 #xff #xfe 0)
                                         (take-bytes 2 "address"))))
                   (3 (if mac-address (link-local mac-address)
                          (error 'truncated :what "address with no MAC address to derive it from")))))
               (stateful (mode mac-address context)
                 ;; The prefix lives in a context we cannot know; show the part we have.
                 (let ((iid (ecase mode
                              (0 nil)
                              (1 (take-bytes 8 "address"))
                              (2 (concatenate '(vector (unsigned-byte 8)) (vector 0 0 0 #xff #xfe 0)
                                              (take-bytes 2 "address")))
                              (3 (and mac-address (interface-id mac-address))))))
                   (if (zerop mode)
                       "::"
                       (format nil "<context ~D prefix>::~A" context
                               (subseq (ipv6-string (prefixed (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)
                                                              iid))
                                       2)))))
               (multicast (mode)
                 (ecase mode
                   (0 (take-bytes 16 "address"))
                   (1 (let ((b (take-bytes 6 "address")))
                        (prefixed (vector #xff (aref b 0)) (concatenate '(vector (unsigned-byte 8))
                                                                         (make-array 9 :initial-element 0)
                                                                         (subseq b 1)))))
                   (2 (let ((b (take-bytes 4 "address")))
                        (prefixed (vector #xff (aref b 0)) (concatenate '(vector (unsigned-byte 8))
                                                                         (make-array 11 :initial-element 0)
                                                                         (subseq b 1)))))
                   (3 (let ((b (take 1 "address")))
                        (prefixed (vector #xff #x02) (concatenate '(vector (unsigned-byte 8))
                                                                   (make-array 13 :initial-element 0)
                                                                   (vector b))))))))
        (let* ((src (if sac
                        (stateful sam source (if contexts (ldb (byte 4 4) contexts) 0))
                        (ipv6-string (stateless sam source))))
               (dst (cond ((and m (not dac)) (ipv6-string (multicast dam)))
                          ((and m dac) (format nil "<unicast-prefix multicast> ~A"
                                               (hex-string (take-bytes 6 "address"))))
                          (dac (stateful dam destination (if contexts (ldb (byte 4 0) contexts) 0)))
                          (t (ipv6-string (stateless dam destination))))))
          (values (obj "dispatch" "IPHC"
                       "elided" (arr (remove nil (list (and (= sam 3) (not sac) "source (from MAC)")
                                                       (and (= dam 3) (not m) (not dac) "destination (from MAC)")
                                                       (and nh "next header (NHC)")))))
                  (obj "layer" "ipv6" "source" src "destination" dst
                       "hop_limit" hop-limit
                       "traffic_class_flow" (and tc-flow (format nil "0x~(~x~)" tc-flow))
                       "next_header" (cond (nh "compressed (NHC)") (t (next-header-name next-header))))
                  next-header nh position))))))

(defun next-header-name (n)
  (case n (0 "hop-by-hop") (6 "TCP") (17 "UDP") (43 "routing") (44 "fragment")
    (58 "ICMPv6") (60 "destination options") (t (format nil "~D" n))))

(defparameter *icmpv6-types*
  '((1 . "destination unreachable") (2 . "packet too big") (3 . "time exceeded")
    (4 . "parameter problem") (128 . "echo request") (129 . "echo reply")
    (130 . "multicast listener query") (131 . "multicast listener report")
    (133 . "router solicitation") (134 . "router advertisement")
    (135 . "neighbor solicitation") (136 . "neighbor advertisement")
    (143 . "multicast listener report v2")))

(defun udp-port-name (port)
  (case port (#.+mle-port+ "MLE") (#.+tmf-port+ "Thread TMF (CoAP)") (5683 "CoAP")
    (5684 "CoAPS") (49191 "MeshCoP") (1000 "Thread TMF (CoAP)")))

(defun decode-udp-nhc (octets position)
  "(VALUES UDP-OBJECT POSITION SOURCE-PORT DESTINATION-PORT)."
  (with-cursor (octets position)
    (let* ((b (take 1 "UDP NHC"))
           (checksum-elided (logbitp 2 b))
           (ports (ldb (byte 2 0) b))
           (big (lambda () (let ((v (take 2 "port"))) (logior (ash (ldb (byte 8 0) v) 8) (ldb (byte 8 8) v)))))
           (src 0) (dst 0))
      (ecase ports
        (0 (setf src (funcall big) dst (funcall big)))
        (1 (setf src (funcall big) dst (+ #xf000 (take 1 "port"))))
        (2 (setf src (+ #xf000 (take 1 "port")) dst (funcall big)))
        (3 (let ((p (take 1 "ports")))
             (setf src (+ #xf0b0 (ldb (byte 4 4) p)) dst (+ #xf0b0 (ldb (byte 4 0) p))))))
      (unless checksum-elided (take 2 "checksum"))
      (values (obj "layer" "udp" "source_port" src "destination_port" dst
                   "service" (or (udp-port-name dst) (udp-port-name src))
                   "compressed" :true)
              position src dst))))

;;; --- MLE ---------------------------------------------------------------

(defparameter *mle-commands*
  #("link request" "link accept" "link accept and request" "link reject" "advertisement"
    "update" "update request" "data request" "data response" "parent request"
    "parent response" "child ID request" "child ID response" "child update request"
    "child update response" "announce" "discovery request" "discovery response"
    "link metrics management request" "link metrics management response"
    "link probe"))

(defparameter *mle-tlvs*
  #("source address" "mode" "timeout" "challenge" "response" "link-layer frame counter"
    "link quality" "network parameter" "MLE frame counter" "route64" "address16"
    "leader data" "network data" "TLV request" "scan mask" "connectivity" "link margin"
    "status" "version" "address registration" "channel" "PAN ID" "active timestamp"
    "pending timestamp" "active operational dataset" "pending operational dataset"
    "thread discovery"))

(defparameter *meshcop-tlvs*
  '((0 . "channel") (1 . "PAN ID") (2 . "extended PAN ID") (3 . "network name")
    (4 . "PSKc") (5 . "network key") (7 . "mesh-local prefix") (8 . "steering data")
    (9 . "border agent locator") (10 . "commissioner ID") (11 . "commissioner session ID")
    (12 . "security policy") (18 . "joiner UDP port") (128 . "discovery request")
    (129 . "discovery response")))

(defun decode-meshcop (octets)
  (let ((tlvs '()) (position 0))
    (with-cursor (octets position)
      (loop while (>= (remaining) 2)
            do (let* ((type (take 1)) (length (take 1)) (value (take-bytes length "MeshCoP TLV")))
                 (push (apply #'obj "type" (or (cdr (assoc type *meshcop-tlvs*)) (format nil "~D" type))
                              (case type
                                (2 (list "value" (colon-hex value)))
                                (3 (list "value" (map 'string #'code-char value)))
                                (18 (list "value" (big-endian value 0 2)))
                                (128 (list "version" (ldb (byte 4 4) (aref value 0))
                                           "joiner" (bool (logbitp 3 (aref value 0)))))
                                (129 (list "version" (ldb (byte 4 4) (aref value 0))
                                           "native_commissioner" (bool (logbitp 3 (aref value 0)))))
                                (t (list "hex" (hex-string value)))))
                       tlvs))))
    (arr (nreverse tlvs))))

(defun big-endian (octets start count)
  (loop for i below count sum (ash (aref octets (+ start i)) (* 8 (- count 1 i)))))

(defun decode-mle-tlv (type value)
  (case type
    ((0 10) (list "value" (hex16 (big-endian value 0 2))))
    (1 (let ((mode (aref value 0)))
         (list "receiver_on_when_idle" (bool (logbitp 3 mode))
               "full_thread_device" (bool (logbitp 1 mode))
               "full_network_data" (bool (logbitp 0 mode)))))
    (2 (list "seconds" (big-endian value 0 4)))
    (11 (when (>= (length value) 8)
          (list "partition_id" (format nil "0x~(~8,'0x~)" (big-endian value 0 4))
                "weighting" (aref value 4) "data_version" (aref value 5)
                "stable_data_version" (aref value 6) "leader_router_id" (aref value 7))))
    (9 (when (>= (length value) 9)
         (list "id_sequence" (aref value 0)
               "router_ids" (arr (loop for id from 0 below 64
                                       when (logbitp (- 7 (mod id 8)) (aref value (+ 1 (floor id 8))))
                                         collect id)))))
    (18 (list "value" (big-endian value 0 2)))
    (26 (list "meshcop" (decode-meshcop value)))
    (t (list "hex" (hex-string value)))))

(defun decode-mle (octets position)
  (with-cursor (octets position)
    (let ((suite (take 1 "MLE security suite")))
      (case suite
        (0 (multiple-value-bind (security position level) (decode-aux-security octets position)
             (let ((mic (mic-length level)))
               (obj "layer" "mle" "secured" :true "security_suite" 0 "security" security
                    ;; Thread uses key ID mode 2 with the key sequence as the key source.
                    "key_sequence" (let ((source (field security "key_source")))
                                     (and source (= 2 (field security "key_id_mode"))
                                          (parse-integer source :start 2 :radix 16)))
                    ;; Thread derives the key index from the sequence; a frame where they
                    ;; disagree has been corrupted somewhere the CRC did not catch.
                    "key_index_consistent"
                    (let ((source (field security "key_source")) (index (field security "key_index")))
                      (and source index (= 2 (field security "key_id_mode"))
                           (bool (= index (1+ (mod (parse-integer source :start 2 :radix 16) 128))))))
                    "encrypted_length" (max 0 (- (length octets) position mic))
                    "mic_length" mic))))
        (255 (let* ((command (take 1 "MLE command"))
                    (problem nil)
                    (tlvs (loop while (>= (remaining) 2)
                                for tlv = (handler-case
                                              (let* ((type (take 1)) (length (take 1))
                                                     (value (take-bytes length "MLE TLV")))
                                                (apply #'obj "type" (if (< type (length *mle-tlvs*))
                                                                        (aref *mle-tlvs* type)
                                                                        (format nil "~D" type))
                                                       (ignore-errors (decode-mle-tlv type value))))
                                            (truncated (c) (setf problem (princ-to-string c)) nil))
                                while tlv collect tlv)))
               (obj "layer" "mle" "secured" :false "security_suite" 255
                    "command" (if (< command (length *mle-commands*)) (aref *mle-commands* command)
                                  (format nil "~D" command))
                    "tlvs" (arr tlvs)
                    "error" problem)))
        (t (obj "layer" "mle" "security_suite" suite "note" "unknown security suite"))))))

;;; --- Zigbee ------------------------------------------------------------

(defun zigbee-nwk-p (octets position)
  (and (>= (- (length octets) position) 8)
       (let ((b (aref octets position)))
         (and (member (ldb (byte 2 6) b) '(0 1))    ; discover route: suppress or enable
              (member (ldb (byte 4 2) b) '(1 2 3))  ; protocol version
              (member (ldb (byte 2 0) b) '(0 1 3)))))) ; data, command, inter-PAN

(defun decode-zigbee-nwk (octets position)
  "(VALUES NWK-OBJECT POSITION SECURED FRAME-TYPE)."
  (with-cursor (octets position)
    (let* ((fc (take 2 "NWK frame control"))
           (frame-type (ldb (byte 2 0) fc))
           (security (logbitp 9 fc))
           (dst (take 2 "NWK destination")) (src (take 2 "NWK source"))
           (radius (take 1 "radius")) (seq (take 1 "sequence"))
           (dst64 (when (logbitp 11 fc) (cons :extended (take 8 "NWK IEEE destination"))))
           (src64 (when (logbitp 12 fc) (cons :extended (take 8 "NWK IEEE source"))))
           (multicast (when (logbitp 8 fc) (take 1 "multicast control")))
           (relays (when (logbitp 10 fc)
                     (let ((count (take 1 "relay count")))
                       (take 1 "relay index")
                       (loop repeat count collect (hex16 (take 2 "relay"))))))
           (aux (when security
                  (let* ((control (take 1 "NWK security control"))
                         (counter (take 4 "NWK frame counter"))
                         (source (when (logbitp 5 control) (cons :extended (take 8 "NWK security source"))))
                         (key-seq (when (= 1 (ldb (byte 2 3) control)) (take 1 "key sequence"))))
                    (obj "key_id" (aref #("data key" "network key" "key-transport key" "key-load key")
                                        (ldb (byte 2 3) control))
                         "frame_counter" counter
                         "source" (and source (address-object source))
                         "key_sequence" key-seq)))))
      (values (obj "layer" "zigbee-nwk"
                   "frame_type" (aref #("data" "command" "reserved" "inter-PAN") frame-type)
                   "protocol_version" (ldb (byte 4 2) fc)
                   "destination" (address-object dst) "source" (address-object src)
                   "radius" radius "sequence" seq
                   "ieee_destination" (and dst64 (address-object dst64))
                   "ieee_source" (and src64 (address-object src64))
                   "multicast_control" multicast
                   "source_route" (and relays (arr relays))
                   "security" aux)
              position security frame-type))))

(defun decode-zigbee-aps (octets position)
  (with-cursor (octets position)
    (let* ((fc (take 1 "APS frame control"))
           (frame-type (ldb (byte 2 0) fc))
           (delivery (ldb (byte 2 2) fc)))
      (if (= frame-type 0)
          ;; Every delivery mode but group addresses an endpoint.
          (let* ((dst-endpoint (unless (= delivery 3) (take 1 "destination endpoint")))
                 (group (when (= delivery 3) (take 2 "group")))
                 (cluster (take 2 "cluster")) (profile (take 2 "profile"))
                 (src-endpoint (take 1 "source endpoint")) (counter (take 1 "APS counter")))
            (obj "layer" "zigbee-aps" "frame_type" "data"
                 "delivery" (aref #("unicast" "indirect" "broadcast" "group") delivery)
                 "destination_endpoint" dst-endpoint "group" (and group (hex16 group))
                 "cluster" (hex16 cluster) "profile" (hex16 profile)
                 "profile_name" (case profile (#x0104 "Home Automation") (#x0000 "Zigbee Device Object")
                                  (#xc05e "Zigbee Light Link") (#xa1e0 "Green Power"))
                 "source_endpoint" src-endpoint "counter" counter
                 "secured" (bool (logbitp 5 fc))))
          (obj "layer" "zigbee-aps" "frame_type" (aref #("data" "command" "ack" "inter-PAN") frame-type)
               "secured" (bool (logbitp 5 fc)))))))

;;; --- the whole frame ----------------------------------------------------

(defun remainder (octets position &key encrypted (mic 0))
  (let ((length (- (length octets) position)))
    (when (plusp length)
      (obj "layer" "data" "length" (max 0 (- length mic))
           "encrypted" (and encrypted :true)
           "mic_length" (and (plusp mic) mic)
           "hex" (hex-string octets :start position :end (max position (- (length octets) mic)))))))

(defun decode-6lowpan (octets position source destination)
  "Layers for a 6LoWPAN payload at POSITION."
  (let ((layers '()) (fields '()))
    (flet ((done (&rest more) (return-from decode-6lowpan
                                (append (list (apply #'obj "layer" "6lowpan" fields))
                                        (reverse layers) (remove nil more))))
           (add (key value) (setf fields (append fields (list key value)))))
      (handler-case
       (loop
        (when (>= position (length octets)) (done))
        (let ((b (aref octets position)))
          (cond
            ;; Mesh header: 10 V F hops.
            ((= (ldb (byte 2 6) b) 2)
             (with-cursor (octets position)
               (take 1 "mesh header")
               (let* ((hops (let ((h (ldb (byte 4 0) b))) (if (= h 15) (take 1 "hops") h)))
                      (originator (if (logbitp 5 b) (take 2 "originator") (cons :extended (take 8 "originator"))))
                      (final (if (logbitp 4 b) (take 2 "final") (cons :extended (take 8 "final")))))
                 (add "mesh" (obj "hops_left" hops "originator" (format-address originator)
                                  "final" (format-address final)))
                 (setf source originator destination final))))
            ;; FRAG1 11000, FRAGN 11100.
            ((= (ldb (byte 5 3) b) #b11000)
             (with-cursor (octets position)
               (let ((head (take-bytes 4 "FRAG1")))
                 (add "first_fragment" (obj "size" (logior (ash (logand (aref head 0) 7) 8) (aref head 1))
                                            "tag" (hex16 (big-endian head 2 2)))))))
            ((= (ldb (byte 5 3) b) #b11100)
             (let ((head (subseq octets position (min (length octets) (+ position 5)))))
               (when (< (length head) 5) (done))
               (add "subsequent_fragment" (obj "size" (logior (ash (logand (aref head 0) 7) 8) (aref head 1))
                                               "tag" (hex16 (big-endian head 2 2)) "offset" (* 8 (aref head 4))))
               (incf position 5)
               (done (obj "layer" "data" "length" (- (length octets) position)
                          "note" "continuation of a fragmented packet"))))
            ;; Uncompressed IPv6.
            ((= b #x41)
             (incf position)
             (when (< (- (length octets) position) 40) (done (remainder octets position)))
             (push (obj "layer" "ipv6"
                        "source" (ipv6-string (subseq octets (+ position 8) (+ position 24)))
                        "destination" (ipv6-string (subseq octets (+ position 24) (+ position 40)))
                        "next_header" (next-header-name (aref octets (+ position 6)))
                        "hop_limit" (aref octets (+ position 7)))
                   layers)
             (add "dispatch" "IPv6 (uncompressed)")
             (done (remainder octets (+ position 40))))
            ;; IPHC.
            ((= (ldb (byte 3 5) b) #b011)
             (multiple-value-bind (iphc ipv6 next-header nhc new-position)
                 (decode-iphc octets position source destination)
               (setf position new-position)
               (loop for (k . v) in (rest iphc) do (add k v))
               (push ipv6 layers)
               (cond
                 ((and nhc (< position (length octets))
                       (= (ldb (byte 5 3) (aref octets position)) #b11110))
                  (multiple-value-bind (udp p src dst) (decode-udp-nhc octets position)
                    (push udp layers)
                    (setf position p)
                    (done (if (or (= src +mle-port+) (= dst +mle-port+))
                              (decode-mle octets position)
                              (remainder octets position)))))
                 (nhc (done (obj "layer" "data" "note" "NHC other than UDP"
                                 "hex" (hex-string octets :start position))))
                 ((eql next-header 17)
                  (with-cursor (octets position)
                    (let ((src (big-endian (take-bytes 2) 0 2)) (dst (big-endian (take-bytes 2) 0 2)))
                      (take 4 "UDP length and checksum")
                      (push (obj "layer" "udp" "source_port" src "destination_port" dst
                                 "service" (or (udp-port-name dst) (udp-port-name src)))
                            layers)
                      (done (if (or (= src +mle-port+) (= dst +mle-port+))
                                (decode-mle octets position)
                                (remainder octets position))))))
                 ((eql next-header 58)
                  (with-cursor (octets position)
                    (let ((type (take 1 "ICMPv6 type")) (code (take 1 "ICMPv6 code")))
                      (take 2 "checksum")
                      (push (obj "layer" "icmpv6" "type" type "code" code
                                 "name" (cdr (assoc type *icmpv6-types*)))
                            layers)
                      (done (remainder octets position)))))
                 (t (done (remainder octets position))))))
            (t (done (obj "layer" "data" "note" (format nil "unknown 6LoWPAN dispatch ~A" (hex8 b))
                          "hex" (hex-string octets :start position)))))))
        ;; Keep the headers already decoded; report where it ran out.
        (truncated (c)
          (done (obj "layer" "error" "reason" (princ-to-string c))))))))

(defun decode-frame (mac)
  "The layers of the MAC frame MAC (an octet vector without FCS), outermost first."
  (handler-case (decode-frame-1 mac)
    (truncated (c)
      (list (obj "layer" "error" "reason" (princ-to-string c) "hex" (hex-string mac))))))

(defun decode-frame-1 (mac)
  (let ((header (decode-mac-header mac)))
    (unless header
      (error 'truncated :what "MAC header"))
    (let* ((type (mac-header-frame-type header))
           (position (or (mac-header-length header) 2))
           (security nil) (level 0) (ies nil))
      (when (and (member type '(:beacon :data :ack :command)) (mac-header-security header))
        (multiple-value-setq (security position level)
          (decode-aux-security mac position :frame-counter (< (mac-header-version header) 2))))
      (when (and (member type '(:beacon :data :ack :command))
                 (>= (mac-header-version header) 2)
                 (logbitp 1 (aref mac 1)))  ; IE present
        (setf ies (decode-header-ies mac position))
        (setf position (nth-value 1 (decode-header-ies mac position))))
      (let* ((mic (mic-length level))
             (encrypted (>= level 4))
             (mac-layer (obj "layer" "mac"
                             "frame_type" (string-downcase (frame-type-name type))
                             "version" (case (mac-header-version header) (0 "2003") (1 "2006") (2 "2015"))
                             "sequence" (mac-header-sequence header)
                             "destination_pan" (and (mac-header-destination-pan header)
                                                    (hex16 (mac-header-destination-pan header)))
                             "destination" (and (mac-header-destination header)
                                                (address-object (mac-header-destination header)))
                             "source_pan" (and (mac-header-source-pan header)
                                               (hex16 (mac-header-source-pan header)))
                             "source" (and (mac-header-source header)
                                           (address-object (mac-header-source header)))
                             "ack_request" (bool (mac-header-ack-request header))
                             "frame_pending" (bool (mac-header-frame-pending header))
                             "pan_id_compression" (bool (mac-header-pan-compression header))
                             "security" security
                             "header_ies" (and ies (arr ies))
                             "length" (length mac)))
             (payload-end (- (length mac) mic))
             (payload (subseq mac 0 (max position payload-end))))
        (cons mac-layer
              (handler-case
               (remove nil
                      (cond
                        ;; A secured command frame's identifier is in the open
                        ;; payload; only its arguments are encrypted.
                        ((and encrypted (eq type :command) (< position payload-end))
                         (list (obj "layer" "command" "id" (hex8 (aref mac position))
                                    "name" (let ((id (aref mac position)))
                                             (or (and (< id (length *mac-commands*)) (aref *mac-commands* id))
                                                 "reserved")))
                               (remainder mac (1+ position) :encrypted t :mic mic)))
                        (encrypted (list (remainder mac position :encrypted t :mic mic)))
                        ((eq type :beacon) (list (decode-beacon payload position)))
                        ((eq type :command) (list (decode-command payload position)))
                        ((eq type :ack) '())
                        ((not (eq type :data)) (list (remainder mac position)))
                        ((>= position (length payload)) '())
                        ((zigbee-nwk-p payload position)
                         (multiple-value-bind (nwk p secured frame-type) (decode-zigbee-nwk payload position)
                           (list nwk
                                 (cond (secured (remainder payload p :encrypted t :mic 4))
                                       ((= frame-type 0) (decode-zigbee-aps payload p))
                                       (t (remainder payload p))))))
                        (t (decode-6lowpan payload position
                                           (mac-header-source header)
                                           (mac-header-destination header)))))
                ;; An inner header that runs off the end keeps everything decoded
                ;; above it; only the part that could not be read is given up.
                (truncated (c)
                  (list (obj "layer" "error" "reason" (princ-to-string c)
                             "hex" (hex-string mac :start (min position (length mac))))))))))))
