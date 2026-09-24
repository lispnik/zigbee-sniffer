(in-package #:zigbee-sniffer.cli)

;;; `zigbee-sniffer list' -- every CC2531 attached, and whether it can sniff.
;;;
;;; Enumeration needs no permissions; the product and serial strings need the
;;; device opened, so without access they are reported as unreadable rather than
;;; failing the listing.

(defun firmware-label (firmware)
  (ecase firmware
    (:sniffer "TI packet sniffer")
    (:z-stack "Z-Stack coordinator (cannot sniff; reflash with TI's sniffer firmware)")))

(defun device-strings (device)
  "(VALUES PRODUCT SERIAL) read from DEVICE, or :NO-PERMISSION."
  (handler-case
      (libusb:with-device-handle (handle device)
        (values (libusb:product handle) (libusb:serial-number handle)))
    (libusb:libusb-access-error () :no-permission)
    (libusb:libusb-error () nil)))

(defun list/handler (command)
  (declare (ignore command))
  (libusb:with-context (context)
    (let ((dongles (find-dongles :context context)))
      (unwind-protect
           (if (null dongles)
               (format t "No CC2531 attached (looked for ~(~4,'0x:~4,'0x and ~4,'0x:~4,'0x~)).~%"
                       +vendor-id+ +sniffer-product-id+ +vendor-id+ +z-stack-product-id+)
               (dolist (device dongles)
                 (multiple-value-bind (product serial) (device-strings device)
                   (format t "~A  ~(~4,'0x:~4,'0x~)  ~A~%    ~A~@[  serial ~A~]~%"
                           (device-location device)
                           (libusb:device-vendor-id device)
                           (libusb:device-product-id device)
                           (firmware-label (dongle-firmware device))
                           (case product
                             (:no-permission "(strings unreadable: no permission to open)")
                             ((nil) "(no product string)")
                             (t product))
                           serial))))
        (mapc #'libusb:unref-device dongles)))))

(register-subcommand
 (clingon:make-command
  :name "list"
  :description "list attached CC2531 dongles and the firmware each is running"
  :handler (reporting-errors #'list/handler)))
