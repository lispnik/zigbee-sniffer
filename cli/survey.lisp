(in-package #:zigbee-sniffer.cli)

;;; `zigbee-sniffer survey' -- listen on each channel in turn and say what is there.
;;;
;;; For finding a network before capturing it: a coordinator beacons, and Thread and
;;; Zigbee routers talk often enough, that a couple of seconds a channel shows which
;;; channels are in use. PANs and sources are counted only from frames that passed
;;; CRC, so interference cannot invent a network.

(defun survey/handler (command)
  (let* ((channels (parse-channels (clingon:getopt command :channels)))
         (dwell (clingon:getopt command :dwell))
         (rounds (clingon:getopt command :rounds))
         (table (make-hash-table)))
    (dolist (channel channels)
      (setf (gethash channel table) (make-stats)))
    (with-sniffer (handle :location (clingon:getopt command :device))
      (format *error-output* "~&Surveying ~D channel~:P, ~Ds each~[~;~:;, ~:*~D rounds~]. C-c to stop early.~%"
              (length channels) dwell rounds)
      (with-stop-signals ()
        (with-capture (capture handle :channel (first channels))
          (block survey
            (dotimes (round rounds)
              (dolist (channel channels)
                (when (stop-requested-p) (return-from survey))
                (unless (= channel (capture-channel capture))
                  (change-channel capture channel))
                (let ((stats (gethash channel table))
                      (deadline (+ (monotonic-seconds) dwell)))
                  (loop until (or (stop-requested-p) (>= (monotonic-seconds) deadline))
                        do (let ((message (receive-message capture)))
                             (when message
                               (multiple-value-bind (kind detail) (parse-message message)
                                 (when (eq kind :frame)
                                   (count-frame stats detail))))))
                  (format *error-output* "~&  ch ~2D  ~4D frame~:P~%"
                          channel (stats-frames stats))
                  (finish-output *error-output*))))))))
    (format t "~&~%CH   MHz  FRAMES   BAD   MEAN dBm  PEAK dBm  SOURCES  PANS~%")
    (dolist (channel channels)
      (let ((stats (gethash channel table)))
        (format t "~2D  ~4D  ~6D  ~4D  ~9@A  ~8@A  ~7D  ~{0x~(~4,'0x~)~^ ~}~%"
                channel (channel-frequency-mhz channel)
                (stats-frames stats) (stats-bad-crc stats)
                (let ((mean (stats-rssi-mean stats)))
                  (if mean (format nil "~,1F" mean) "-"))
                (or (stats-rssi-max stats) "-")
                (length (stats-sources stats))
                (sort (copy-list (stats-pans stats)) #'<))))))

(register-subcommand
 (clingon:make-command
  :name "survey"
  :description "visit each channel in turn and report the traffic on it"
  :usage "[--channels 11-26] [--dwell SECONDS] [--rounds N]"
  :options
  (list (clingon:make-option :string
                             :description "channels to visit: 11-26, 15,20,25, or a mix"
                             :long-name "channels" :initial-value "11-26" :key :channels)
        (clingon:make-option :integer
                             :description "seconds to listen on each channel per round"
                             :short-name #\s :long-name "dwell" :initial-value 2 :key :dwell)
        (clingon:make-option :integer
                             :description "times to visit every channel"
                             :short-name #\r :long-name "rounds" :initial-value 1 :key :rounds)
        (device-option))
  :handler (reporting-errors #'survey/handler)))
