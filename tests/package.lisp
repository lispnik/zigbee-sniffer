(defpackage #:zigbee-sniffer/tests
  (:use #:cl #:zigbee-sniffer #:fiveam)
  (:export #:run-tests))

(in-package #:zigbee-sniffer/tests)

(def-suite zigbee-sniffer :description "The portable core: no dongle, no libusb.")

(defun run-tests ()
  "Run the suite; true if everything passed."
  (run! 'zigbee-sniffer))
