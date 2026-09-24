(in-package #:zigbee-sniffer.cli)

;;; Subcommand dispatch. The top-level command is built fresh in MAIN, so the
;;; registry is read at startup rather than at load time and the subcommand files
;;; can load in any order.

(defvar *subcommands* '())

(defun register-subcommand (command)
  (setf *subcommands*
        (append (remove (clingon:command-name command) *subcommands*
                        :key #'clingon:command-name :test #'equal)
                (list command))))

(defun top-level-command ()
  (clingon:make-command
   :name "zigbee-sniffer"
   :description "capture IEEE 802.15.4 / Zigbee traffic with a TI CC2531 sniffer dongle"
   :long-description
   "Drives a TI CC2531 USB dongle running TI's packet-sniffer
firmware (0451:16AE).

  zigbee-sniffer list                  dongles attached
  zigbee-sniffer info                  descriptors, identity, radio
  zigbee-sniffer survey                traffic on channels 11-26
  zigbee-sniffer capture -c 25         frames as they arrive
  zigbee-sniffer capture -c 25 -w out.pcap
  zigbee-sniffer capture -c 25 -w - | wireshark -k -i -

Opening the dongle needs write access to its /dev/bus/usb node:
root, or the udev rule in contrib/."
   :version "0.1.0"
   :authors '("Matthew Kennedy")
   :license "MIT"
   :sub-commands *subcommands*
   :handler (lambda (command) (clingon:print-usage-and-exit command t))))

(defun fail (control &rest arguments)
  (format *error-output* "~&error: ~?~%" control arguments)
  (finish-output *error-output*)
  (sb-ext:exit :code 1 :abort t))

(defun reporting-errors (handler)
  "HANDLER, with the errors it can raise turned into a message and an exit code.

Here rather than around CLINGON:RUN because clingon catches every error inside
RUN itself and prints it bare -- so a hint for the permission error, the one
everybody meets first, has to be given before the error reaches it."
  (lambda (command)
    (handler-case (funcall handler command)
      (libusb:libusb-access-error ()
        (fail "no permission to open the dongle.~%~
               hint: run as root, or install contrib/99-cc2531-sniffer.rules:~%~
               ~6@Tsudo cp contrib/99-cc2531-sniffer.rules /etc/udev/rules.d/~%~
               ~6@Tsudo udevadm control --reload && sudo udevadm trigger"))
      (libusb:libusb-busy ()
        (fail "the dongle is in use by another process."))
      (error (condition)
        (fail "~A" condition)))))

(defun main ()
  (clingon:run (top-level-command)))
