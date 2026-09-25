(in-package #:zigbee-sniffer.cli)

;;; `zigbee-sniffer capture' -- stream one channel to the terminal, a pcap file, or
;;; a pipe.
;;;
;;; Without --write, one line per frame goes to stdout. With --write FILE, the
;;; frames go to FILE in the IEEE 802.15.4 TAP encapsulation and only the summary
;;; is printed (--verbose adds the lines, on stderr). --write - puts the pcap on
;;; stdout, flushed per frame, so Wireshark can watch live:
;;;
;;;   zigbee-sniffer capture -c 25 -w - | wireshark -k -i -
;;;
;;; Frames that failed CRC are counted but not shown or written unless --bad-crc:
;;; a frame whose bytes are known to be wrong can decode as a device that does not
;;; exist -- in the capture this tool was written against, one corrupt beacon
;;; decoded as a different device, its extended address off by a single byte.
;;; TAP has no CRC-validity field, so once written, nothing marks them.
;;;
;;; Frames that passed CRC but cannot be real -- an RSSI the radio cannot measure, a
;;; frame type nothing on 2.4 GHz sends -- are treated the same way, under
;;; --implausible. See FRAME-IMPLAUSIBILITY.

(defun open-pcap-output (path)
  (if (string= path "-")
      (sb-sys:make-fd-stream 1 :output t :element-type '(unsigned-byte 8)
                               :buffering :full :name "standard output")
      (open path :direction :output :element-type '(unsigned-byte 8)
                 :if-exists :supersede)))

(defun capture/handler (command)
  (let* ((channel (check-channel (clingon:getopt command :channel)))
         (seconds (clingon:getopt command :seconds))
         (count (clingon:getopt command :count))
         (path (clingon:getopt command :write))
         (bad-crc (clingon:getopt command :bad-crc))
         (implausible (clingon:getopt command :implausible))
         (hex-p (clingon:getopt command :hex))
         (format (clingon:getopt command :format))
         (decode (clingon:getopt command :decode))
         (inventory (and (clingon:getopt command :inventory) (make-inventory)))
         (lines (cond ((null path) *standard-output*)
                      ((clingon:getopt command :verbose) *error-output*)))
         (stats (make-stats))
         (clock (make-dongle-clock))
         (pcap nil)
         (skipped 0)
         (ended :interrupted))
    (use-oui-option command)
    (unwind-protect
         (progn
           (when path
             (setf pcap (open-pcap-output path))
             (write-pcap-header pcap)
             (finish-output pcap))
           (with-sniffer (handle :location (clingon:getopt command :device))
             (format *error-output* "~&Capturing on channel ~D (~D MHz)~@[ for ~Ds~]~
                                     ~@[, stopping after ~D frame~:P~]. C-c to stop.~%"
                     channel (channel-frequency-mhz channel) seconds count)
             (finish-output *error-output*)
             (flet ((handle-message (message)
                      (multiple-value-bind (kind detail) (parse-message message)
                        (ecase kind
                          (:heartbeat (incf (stats-heartbeats stats)))
                          ((:malformed :unknown)
                           (if (eq kind :malformed)
                               (incf (stats-malformed stats))
                               (incf (stats-unknown stats)))
                           (when lines
                             (format lines "~&!! ~:[unknown message type ~D~;malformed message: ~A~]: ~A~%"
                                     (eq kind :malformed) detail (hex message))))
                          (:frame
                           ;; The clock sees every frame, kept or not, so that one
                           ;; dropped frame cannot hide a counter wrap.
                           (let ((microseconds (dongle-clock-microseconds
                                                clock (frame-ticks detail)))
                                 (verdict (frame-verdict detail)))
                             (count-frame stats detail verdict)
                             (when (case verdict
                                     ((nil) t)
                                     (:bad-crc bad-crc)
                                     (t implausible))
                               (incf (stats-written stats))
                               (when pcap
                                 (write-pcap-frame pcap detail :channel channel
                                                               :microseconds microseconds)
                                 ;; Per frame, so a live reader sees it now and a
                                 ;; killed run leaves a readable file.
                                 (finish-output pcap))
                               (when lines
                                 (emit-frame lines detail :channel channel
                                                          :microseconds microseconds
                                                          :verdict verdict :format format
                                                          :decode decode :hex hex-p)
                                 (force-output lines)))
                             (when (and inventory (null verdict))
                               (inventory-add inventory detail :microseconds microseconds
                                                               :channel channel))))))))
               (with-stop-signals ()
                 (with-capture (capture handle :channel channel)
                   (let ((deadline (and seconds (+ (monotonic-seconds) seconds))))
                     (setf ended
                           (loop
                             (cond ((stop-requested-p) (return :interrupted))
                                   ((and deadline (>= (monotonic-seconds) deadline))
                                    (return :time))
                                   ((and count (>= (stats-written stats) count))
                                    (return :count)))
                             (let ((message (receive-message capture)))
                               (when message
                                 (handler-case (handle-message message)
                                   ;; The reader went away: `| head', or Wireshark
                                   ;; closed. That is how a pipe ends, not an error.
                                   (stream-error () (return :output-closed)))))))
                     (setf skipped (capture-skipped-octets capture))))))))
      (when (and pcap (not (string= path "-")))
        (close pcap)))
    (unless (and (eq ended :output-closed) (null path))
      (let ((out *error-output*))
        (format out "~&~%Channel ~D: ~D frame~:P received, ~D ~:[shown~;written~]~%"
                channel (stats-frames stats) (stats-written stats) pcap)
        (format out "  ~D failed CRC~:[ (excluded; --bad-crc keeps them)~;~]~%"
                (stats-bad-crc stats) (or bad-crc (zerop (stats-bad-crc stats))))
        (format out "  ~D passed CRC but are implausible~:[ (excluded; --implausible keeps them)~;~]~%"
                (stats-implausible stats) (or implausible (zerop (stats-implausible stats))))
        (when (or (plusp (stats-malformed stats)) (plusp (stats-unknown stats)) (plusp skipped))
          (format out "  ~D malformed message~:P, ~D of unknown type, ~D octet~:P skipped to realign~%"
                  (stats-malformed stats) (stats-unknown stats) skipped))
        (format out "  ~D heartbeat~:P, RSSI ~:[n/a~*~;~:*mean ~,1F dBm, peak ~D dBm~] (good frames)~%"
                (stats-heartbeats stats) (stats-rssi-mean stats) (stats-rssi-max stats))
        (when (and path (not (string= path "-")))
          (format out "  wrote ~A~%" path))
        (when (eq ended :output-closed)
          (format out "  stopped: the output was closed~%"))))
    (when inventory
      (print-inventory (inventory-report inventory) *error-output*))))

(register-subcommand
 (clingon:make-command
  :name "capture"
  :description "capture 802.15.4 frames on one channel, to the terminal or a pcap file"
  :usage "[-c CHANNEL] [-w FILE|-] [-t SECONDS] [-n COUNT] [-V] [--format text|jsonl] [-i] ..."
  :options
  (append
   (list (channel-option)
        (clingon:make-option :string
                             :description "write a pcap file (IEEE 802.15.4 TAP); - for stdout"
                             :short-name #\w :long-name "write" :key :write)
        (clingon:make-option :integer
                             :description "stop after this many seconds (default: run until C-c)"
                             :short-name #\t :long-name "seconds" :key :seconds)
        (clingon:make-option :integer
                             :description "stop after this many frames"
                             :short-name #\n :long-name "count" :key :count)
        (clingon:make-option :flag
                             :description "keep frames that failed CRC (marked BAD-CRC in text; unmarked in pcap)"
                             :long-name "bad-crc" :key :bad-crc)
        (clingon:make-option :flag
                             :description "keep frames that passed CRC but cannot be real: impossible RSSI, frame type or length (marked IMPLAUSIBLE in text; unmarked in pcap)"
                             :long-name "implausible" :key :implausible)
        (clingon:make-option :flag
                             :description "with --write, also print each frame on stderr"
                             :short-name #\v :long-name "verbose" :key :verbose)
        (clingon:make-option :flag
                             :description "when the capture ends, report every network and device seen (see `inventory')"
                             :short-name #\i :long-name "inventory" :key :inventory)
        (device-option))
   (output-options))
  :handler (reporting-errors #'capture/handler)))
