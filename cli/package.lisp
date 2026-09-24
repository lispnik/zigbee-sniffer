;;; The command-line tool: argument parsing, output formatting, and one file per
;;; subcommand. zigbee-sniffer/cli compiles it into a single binary at
;;; bin/zigbee-sniffer, dispatched on argv[1] -- `zigbee-sniffer capture -c 25'.
;;;
;;; Each subcommand file defines its handler and calls REGISTER-SUBCOMMAND at load
;;; time, so adding one means adding a file and an .asd entry, with no central list
;;; to keep in sync.

(defpackage #:zigbee-sniffer.cli
  (:use #:cl #:zigbee-sniffer)
  (:export #:main #:register-subcommand))
