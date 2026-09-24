;;; One package for the library. The core's exports are declared here; the
;;; dongle layer, which is a separate system, exports its own names from
;;; dongle.lisp, so loading only zigbee-sniffer/core advertises only what it
;;; provides.

(defpackage #:zigbee-sniffer
  (:use #:cl)
  (:export
   ;; the dongle's stream
   #:+rssi-offset+
   #:frame #:frame-p #:make-frame
   #:frame-ticks #:frame-mac #:frame-rssi #:frame-correlation #:frame-crc-ok
   #:parse-message
   #:make-dongle-clock #:dongle-clock-microseconds
   #:+unix-epoch-universal-time+ #:unix-microseconds-now
   #:channel-p #:channel-frequency-mhz
   ;; 802.15.4 MAC headers
   #:mac-header #:mac-header-p
   #:mac-header-frame-type #:mac-header-version #:mac-header-security
   #:mac-header-frame-pending #:mac-header-ack-request #:mac-header-pan-compression
   #:mac-header-sequence
   #:mac-header-destination-pan #:mac-header-destination
   #:mac-header-source-pan #:mac-header-source
   #:mac-header-length
   #:decode-mac-header #:frame-type-name #:format-address
   ;; pcap
   #:write-pcap-header #:write-pcap-frame #:tap-header #:encode-single-float
   #:+linktype-ieee802-15-4-tap+))
