(in-package #:zigbee-sniffer.cli)

;;; `zigbee-sniffer info' -- one dongle's descriptors, firmware identity and radio.
;;;
;;; Reads only. The identity is shown as hex because what its fields mean is not
;;; documented; the endpoint layout is shown because it is how to tell the sniffer
;;; firmware apart from anything else wearing the same IDs: exactly one
;;; vendor-specific interface, one bulk IN endpoint at 0x83.

(defun info/handler (command)
  (with-sniffer (handle :location (clingon:getopt command :device))
    (let* ((device (libusb:handle-device handle))
           (descriptor (libusb:device-descriptor device))
           (config (libusb:active-config-descriptor device)))
      (format t "~&Device        ~A  (port ~{~D~^.~}, ~(~A~) speed)~%"
              (device-location device) (libusb:device-port-numbers device)
              (libusb:device-speed device))
      (format t "ID            ~(~4,'0x:~4,'0x~)  USB ~A, device release ~A~%"
              (libusb:device-descriptor-vendor-id descriptor)
              (libusb:device-descriptor-product-id descriptor)
              (libusb:bcd-version-string (libusb:device-descriptor-usb-version descriptor))
              (libusb:bcd-version-string (libusb:device-descriptor-device-version descriptor)))
      (format t "Manufacturer  ~A~%Product       ~A~%Serial        ~A~%"
              (or (libusb:manufacturer handle) "-")
              (or (libusb:product handle) "-")
              (or (libusb:serial-number handle) "-"))
      (when config
        (loop for interface across (libusb:config-descriptor-interfaces config)
              do (loop for alt across (libusb:usb-interface-alt-settings interface)
                       do (format t "Interface     ~D alt ~D, class ~(~A~):~{ ~A~}~%"
                                  (libusb:interface-descriptor-number alt)
                                  (libusb:interface-descriptor-alt-setting alt)
                                  (libusb:interface-descriptor-interface-class alt)
                                  (loop for endpoint across (libusb:interface-descriptor-endpoints alt)
                                        collect (format nil "~2,'0X/~(~A/~A~)/~D"
                                                        (libusb:endpoint-descriptor-address endpoint)
                                                        (libusb:endpoint-descriptor-direction endpoint)
                                                        (libusb:endpoint-descriptor-transfer-type endpoint)
                                                        (libusb:endpoint-descriptor-max-packet-size endpoint)))))))
      (format t "Identity      ~A  (GET_IDENT)~%" (hex (get-ident handle)))
      (let ((power (get-power handle)))
        ;; Off is the normal state here: capture and survey power the radio up
        ;; for their duration and down again after, and info only reads.
        (format t "Radio         ~:[off (idle: capture and survey power it on while they run)~;on~] ~
                   (power register ~D)~%" (= power 4) power)))))

(register-subcommand
 (clingon:make-command
  :name "info"
  :description "show a sniffer dongle's descriptors, firmware identity and radio state"
  :options (list (device-option))
  :handler (reporting-errors #'info/handler)))
