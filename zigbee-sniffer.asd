;;; zigbee-sniffer -- IEEE 802.15.4 / Zigbee capture on a TI CC2531 running TI's
;;; packet-sniffer firmware.
;;;
;;; Split along the USB seam, which is what keeps the parsing code -- and its
;;; tests -- runnable on a machine with no dongle and no libusb:
;;;
;;;   zigbee-sniffer/core -- the dongle's stream format, the 802.15.4 MAC header,
;;;                          the pcap/TAP writer and the dongle's clock. Pure Lisp,
;;;                          no dependencies. The test suite depends only on this.
;;;   zigbee-sniffer      -- the dongle itself: finding it, its vendor requests,
;;;                          and a streaming capture over libusb's asynchronous
;;;                          transfers.
;;;   zigbee-sniffer/cli  -- the bin/zigbee-sniffer binary; adds clingon.
;;;
;;; `libusb' comes from github.com/lispnik/libusb, checked out as a sibling of
;;; this tree. LIBUSB_DIR in the Makefile points at it (../libusb by default) and
;;; puts that one directory on the source registry. Only #:libusb is needed, not
;;; libusb/closures, so neither libffi nor cffi-callback-closures is involved.

(asdf:defsystem #:zigbee-sniffer/core
  :description "CC2531 sniffer stream format, 802.15.4 MAC headers, pcap/TAP output (portable)."
  :license     "MIT"
  :version     "0.1.0"
  :components ((:module "src"
                :components ((:file "package")
                             (:file "stream"    :depends-on ("package"))
                             ;; "stream" for LITTLE-ENDIAN.
                             (:file "ieee802154" :depends-on ("stream"))
                             (:file "pcap"      :depends-on ("stream")))))
  :in-order-to ((asdf:test-op (asdf:test-op #:zigbee-sniffer/tests))))

(asdf:defsystem #:zigbee-sniffer
  :description "Capture IEEE 802.15.4 / Zigbee traffic with a TI CC2531 sniffer dongle."
  :license     "MIT"
  :version     "0.1.0"
  ;; sb-concurrency for the mailbox between libusb's event thread, where the
  ;; transfers complete, and the thread that parses and writes.
  :depends-on  (#:zigbee-sniffer/core #:libusb #:sb-concurrency)
  :components ((:module "src"
                :components ((:file "dongle"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:zigbee-sniffer/tests))))

(asdf:defsystem #:zigbee-sniffer/tests
  :description "Test suite for the portable core; needs no dongle and no libusb."
  :license     "MIT"
  :depends-on  (#:zigbee-sniffer/core #:fiveam)
  :components ((:module "tests"
                :serial t
                :components ((:file "package")
                             (:file "core-tests"))))
  :perform (asdf:test-op (op c)
             (declare (ignore op c))
             ;; ASDF ignores what PERFORM returns; signal, or CI stays green on a
             ;; failing suite.
             (unless (uiop:symbol-call :zigbee-sniffer/tests :run-tests)
               (error "zigbee-sniffer test suite failed"))))

(asdf:defsystem #:zigbee-sniffer/cli
  :description "Command-line tool for the CC2531 sniffer."
  :license     "MIT"
  :version     "0.1.0"
  :depends-on  (#:zigbee-sniffer #:clingon)
  :components ((:module "cli"
                :components ((:file "package")
                             (:file "util"    :depends-on ("package"))
                             (:file "main"    :depends-on ("util"))
                             ;; One file per subcommand; each registers itself.
                             (:file "list"    :depends-on ("main"))
                             (:file "info"    :depends-on ("main"))
                             (:file "capture" :depends-on ("main"))
                             (:file "survey"  :depends-on ("main")))))
  :build-operation "program-op"
  :build-pathname  "bin/zigbee-sniffer"
  :entry-point     "zigbee-sniffer.cli:main")
