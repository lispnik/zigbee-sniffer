(in-package #:zigbee-sniffer.cli)

;;; --- options shared between subcommands --------------------------------

(defun device-option ()
  (clingon:make-option :string
                       :description "the dongle to use, as BUS:ADDRESS from `zigbee-sniffer list' (default: the only one attached)"
                       :short-name #\d :long-name "device" :key :device))

(defun channel-option (&key (initial-value 25))
  (clingon:make-option :integer
                       :description "802.15.4 channel, 11-26"
                       :short-name #\c :long-name "channel"
                       :initial-value initial-value :key :channel))

(defun check-channel (channel)
  (unless (channel-p channel)
    (error "802.15.4 channels are 11 to 26, not ~A." channel))
  channel)

(defun parse-channels (string)
  "\"11-26\", \"15,20,25\" or a mix of the two, as a list of channels."
  (loop for part in (uiop:split-string string :separator ",")
        for dash = (position #\- part)
        for from = (parse-integer part :end dash)
        for to = (if dash (parse-integer part :start (1+ dash)) from)
        nconc (loop for channel from from to to
                    collect (check-channel channel))))

;;; --- time --------------------------------------------------------------

(defun format-time (microseconds &key date)
  "Local wall-clock time for MICROSECONDS since the Unix epoch:
HH:MM:SS.uuuuuu, with the date in front when DATE is true."
  (multiple-value-bind (seconds us) (floor microseconds 1000000)
    (multiple-value-bind (sec min hour day month year)
        (decode-universal-time (+ seconds +unix-epoch-universal-time+))
      (format nil "~:[~*~;~{~4,'0D-~2,'0D-~2,'0D ~}~]~2,'0D:~2,'0D:~2,'0D.~6,'0D"
              date (list year month day) hour min sec us))))

(defun monotonic-seconds ()
  (/ (get-internal-real-time) (float internal-time-units-per-second 1d0)))

;;; --- frames ------------------------------------------------------------

(defun address-text (object)
  "An address from the decoder, with who made it or that it is random."
  (cond ((null object) nil)
        ((field object "short")
         (format nil "~A~@[ (~A)~]" (field object "short") (field object "meaning")))
        (t (format nil "~A~@[ (~A)~]" (field object "extended")
                   (or (field object "vendor")
                       (and (search "local" (field object "administration")) "random"))))))

(defun upper-summary (layers)
  "What the frame carries, past the MAC header, in a few words."
  (let ((parts '()))
    (dolist (layer (rest layers))
      (let ((name (field layer "layer")))
        (push
         (cond
           ((string= name "beacon")
            (let ((payload (field layer "payload")))
              (cond ((null payload) "beacon, no payload")
                    ((equal (field payload "protocol") "thread")
                     (format nil "Thread beacon ~S xpan ~A" (field payload "network_name")
                             (field payload "extended_pan_id")))
                    ((equal (field payload "protocol") "zigbee")
                     (format nil "Zigbee beacon xpan ~A depth ~D~:[~; router-capacity~]~:[~; end-device-capacity~]"
                             (field payload "extended_pan_id") (field payload "device_depth")
                             (eq :true (field payload "router_capacity"))
                             (eq :true (field payload "end_device_capacity"))))
                    (t (format nil "beacon payload ~A" (field payload "protocol"))))))
           ((string= name "command") (format nil "cmd ~A" (field layer "name")))
           ((string= name "ipv6") (format nil "~A -> ~A" (field layer "source") (field layer "destination")))
           ((string= name "udp") (format nil "UDP ~D~@[ ~A~]" (field layer "destination_port") (field layer "service")))
           ((string= name "icmpv6") (format nil "ICMPv6 ~A" (or (field layer "name") (field layer "type"))))
           ((string= name "mle")
            (if (eq :true (field layer "secured"))
                (format nil "MLE encrypted~@[ key-seq ~D~]~@[ fc ~D~]" (field layer "key_sequence")
                        (field (field layer "security") "frame_counter"))
                (format nil "MLE ~A" (field layer "command"))))
           ((string= name "zigbee-nwk")
            (format nil "NWK ~A ~A -> ~A~:[~; encrypted~]" (field layer "frame_type")
                    (field (field layer "source") "short") (field (field layer "destination") "short")
                    (field layer "security")))
           ((string= name "zigbee-aps")
            (format nil "APS ~@[~A ~]cluster ~A" (field layer "profile_name") (field layer "cluster")))
           ((string= name "data")
            (format nil "~D B~:[~; encrypted~]~@[ (~A)~]" (field layer "length")
                    (eq :true (field layer "encrypted")) (field layer "note")))
           ((string= name "error") (format nil "!! ~A" (field layer "reason")))
           (t nil))
         parts)))
    (format nil "~{~A~^ | ~}" (remove nil (nreverse parts)))))

(defun verdict-text (verdict)
  (case verdict
    ((nil) nil)
    (:bad-crc "BAD-CRC")
    (t (format nil "IMPLAUSIBLE(~(~A~))" verdict))))

(defun frame-summary (frame &key channel microseconds verdict (layers (decode-frame (frame-mac frame))))
  "One line describing FRAME, tcpdump-style: when, how strong, what, who, and what
it carries. VERDICT, from FRAME-VERDICT, marks a frame that failed a check."
  (let ((mac (find-layer layers "mac")))
    (with-output-to-string (s)
      (format s "~A  ~@[ch~D ~]~@[~4D dBm ~]~@[lqi ~3D  ~]~@[~A ~]"
              (format-time microseconds) channel (frame-rssi frame)
              (frame-correlation frame) (verdict-text verdict))
      (if (null mac)
          (format s "~A" (upper-summary (cons nil layers)))
          (progn
            (format s "~A~@[ seq ~D~]~@[ pan ~A~]" (string-capitalize (field mac "frame_type"))
                    (field mac "sequence")
                    (or (field mac "destination_pan") (field mac "source_pan")))
            (let ((source (address-text (field mac "source")))
                  (destination (address-text (field mac "destination"))))
              (cond ((and source destination) (format s "  ~A -> ~A" source destination))
                    (source (format s "  src ~A" source))
                    (destination (format s "  dst ~A" destination))))
            (let ((upper (upper-summary layers)))
              (when (plusp (length upper)) (format s "  | ~A" upper)))))
      (format s "  ~D B" (length (frame-mac frame))))))

(defun value-text (value)
  (cond ((eq value :true) "yes")
        ((eq value :false) "no")
        ((and (consp value) (eq (first value) :object))
         (format nil "~{~A~^  ~}"
                 (loop for (k . v) in (rest value)
                       collect (if (and (consp v) (member (first v) '(:object :array)))
                                   (format nil "~A={~A}" k (value-text v))
                                   (format nil "~A=~A" k (value-text v))))))
        ((and (consp value) (eq (first value) :array))
         (format nil "~{~A~^, ~}" (mapcar #'value-text (rest value))))
        (t (princ-to-string value))))

(defun print-layers (layers stream)
  "The decoded layers as an indented tree, one field per line."
  (dolist (layer layers)
    (format stream "    ~A~%" (field layer "layer"))
    (loop for (key . value) in (rest layer)
          unless (string= key "layer")
            do (format stream "      ~A: ~A~%" key (value-text value)))))

(defun frame-json (frame &key channel microseconds verdict (layers (decode-frame (frame-mac frame))))
  "FRAME and everything decoded from it, as one JSON-ready object."
  (obj "time" (and microseconds (format-time microseconds :date t))
       "timestamp_us" microseconds
       "channel" channel
       "rssi_dbm" (frame-rssi frame)
       "lqi" (frame-correlation frame)
       "crc_ok" (bool (frame-crc-ok frame))
       "verdict" (and verdict (string-downcase verdict))
       "length" (length (frame-mac frame))
       "layers" (arr layers)
       "hex" (hex-string (frame-mac frame))))

(defun emit-frame (stream frame &key channel microseconds verdict (format :text) decode hex)
  "Write FRAME to STREAM as FORMAT: :TEXT (one line; DECODE adds the layer tree and
HEX a hexdump) or :JSONL (one JSON object per line, everything included)."
  (let ((layers (decode-frame (frame-mac frame))))
    (ecase format
      (:text
       (write-line (frame-summary frame :channel channel :microseconds microseconds
                                        :verdict verdict :layers layers)
                   stream)
       (when decode (print-layers layers stream))
       (when hex (hexdump (frame-mac frame) :stream stream)))
      (:jsonl
       (write-json (frame-json frame :channel channel :microseconds microseconds
                                     :verdict verdict :layers layers)
                   stream)
       (terpri stream)))))

(defun oui-option ()
  (clingon:make-option :string
                       :description "IEEE oui.csv or Wireshark manuf file for vendor names (default: the system's, else a built-in 802.15.4 table)"
                       :long-name "oui-file" :key :oui-file :env-vars '("ZIGBEE_SNIFFER_OUI")))

(defun output-options ()
  "Options shared by everything that prints frames."
  (list (clingon:make-option :enum
                             :description "text (a line per frame) or jsonl (a JSON object per frame, every decoded field)"
                             :long-name "format" :items '(("text" . :text) ("jsonl" . :jsonl))
                             :initial-value "text" :key :format)
        (clingon:make-option :flag
                             :description "decode every layer under each frame's line: MAC, security, beacon, 6LoWPAN, IPv6, UDP, MLE, Zigbee"
                             :short-name #\V :long-name "decode" :key :decode)
        (clingon:make-option :flag
                             :description "hex dump each frame's MAC bytes under its summary"
                             :short-name #\x :long-name "hex" :key :hex)
        (oui-option)))

(defun use-oui-option (command)
  (let ((path (clingon:getopt command :oui-file)))
    (when path
      (unless (probe-file path) (error "No OUI file at ~A." path))
      (setf *oui-file* path))))

(defun hexdump (octets &key (stream *standard-output*) (indent "    "))
  (loop for start from 0 below (length octets) by 16
        for end = (min (length octets) (+ start 16))
        do (format stream "~A~4,'0X  ~{~(~2,'0x~)~^ ~}~%" indent start
                   (coerce (subseq octets start end) 'list))))

(defun hex (octets)
  (format nil "~{~2,'0X~^ ~}" (coerce octets 'list)))

;;; --- stats -------------------------------------------------------------

(defstruct stats
  (frames 0) (bad-crc 0) (implausible 0) (written 0) (heartbeats 0) (malformed 0) (unknown 0)
  (rssi-sum 0) (rssi-max nil)
  (pans '())
  (sources (make-hash-table :test #'equal)))  ; source address -> frames

(defun frame-verdict (frame)
  "NIL for a frame that passed CRC and every plausibility check, else :BAD-CRC or
the reason FRAME-IMPLAUSIBILITY gives."
  (if (frame-crc-ok frame)
      (frame-implausibility frame)
      :bad-crc))

(defun count-frame (stats frame verdict)
  (incf (stats-frames stats))
  (case verdict
    ((nil)
     ;; RSSI, PANs and sources only from frames that passed every check: a corrupt
     ;; frame can report an RSSI the radio cannot measure, and decode as a PAN or a
     ;; device that does not exist.
     (incf (stats-rssi-sum stats) (frame-rssi frame))
     (setf (stats-rssi-max stats) (max (frame-rssi frame)
                                       (or (stats-rssi-max stats) (frame-rssi frame))))
     (let ((header (decode-mac-header (frame-mac frame))))
       (dolist (pan (list (mac-header-destination-pan header)
                          (mac-header-source-pan header)))
         (when (and pan (/= pan #xffff))
           (pushnew pan (stats-pans stats))))
       (let ((source (mac-header-source header)))
         (when source
           (incf (gethash source (stats-sources stats) 0))))))
    (:bad-crc (incf (stats-bad-crc stats)))
    (t (incf (stats-implausible stats)))))

(defun stats-source-count (stats &key (minimum 2))
  "Sources heard in at least MINIMUM good frames.

Two, not one, because a frame can pass CRC and every plausibility check and still
be corrupt: over an hour on channel 25, twenty-odd addresses appeared exactly once,
each a real device's address with a bit or a byte wrong. A real device is heard
again."
  (loop for frames being the hash-values of (stats-sources stats)
        count (>= frames minimum)))

(defun stats-good (stats)
  (- (stats-frames stats) (stats-bad-crc stats) (stats-implausible stats)))

(defun stats-rssi-mean (stats)
  (and (plusp (stats-good stats))
       (/ (stats-rssi-sum stats) (float (stats-good stats)))))

;;; --- stopping ----------------------------------------------------------
;;;
;;; C-c and SIGTERM ask a capture to stop rather than killing it, so the transfers
;;; are cancelled, the radio is powered down and the summary is printed -- which
;;; also makes `timeout 60 zigbee-sniffer capture ...' a clean run rather than an
;;; aborted one. The handler only sets a flag, which the receive loop polls; it can
;;; run on any thread, including libusb's, so it must not do more than that. A
;;; second signal while the first is being honoured exits at once.

(sb-ext:defglobal **stop-requested** nil)

(defun request-stop (signal info context)
  (declare (ignore signal info context))
  (if **stop-requested**
      (sb-ext:exit :code 130 :abort t)
      (setf **stop-requested** t)))

(defun call-with-stop-signals (function)
  (setf **stop-requested** nil)
  (sb-sys:enable-interrupt sb-unix:sigint #'request-stop)
  (sb-sys:enable-interrupt sb-unix:sigterm #'request-stop)
  (funcall function))

(defmacro with-stop-signals (() &body body)
  `(call-with-stop-signals (lambda () ,@body)))

(defun stop-requested-p () **stop-requested**)
