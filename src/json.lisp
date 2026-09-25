;;; JSON for the objects DECODE-FRAME builds: (:OBJECT (KEY . VALUE)...),
;;; (:ARRAY ITEM...), strings, integers, floats, :TRUE, :FALSE and :NULL. Just enough
;;; to write one object per line; nothing here reads JSON.

(in-package #:zigbee-sniffer)

(defun write-json-string (string stream)
  (write-char #\" stream)
  (loop for c across string
        do (case c
             (#\" (write-string "\\\"" stream))
             (#\\ (write-string "\\\\" stream))
             (#\Newline (write-string "\\n" stream))
             (#\Return (write-string "\\r" stream))
             (#\Tab (write-string "\\t" stream))
             (t (if (< (char-code c) 32)
                    (format stream "\\u~4,'0x" (char-code c))
                    (write-char c stream)))))
  (write-char #\" stream))

(defun write-json (value &optional (stream *standard-output*))
  (cond ((eq value :true) (write-string "true" stream))
        ((eq value :false) (write-string "false" stream))
        ((or (null value) (eq value :null)) (write-string "null" stream))
        ((stringp value) (write-json-string value stream))
        ((integerp value) (format stream "~D" value))
        ((realp value) (format stream "~,3F" value))
        ((and (consp value) (eq (first value) :object))
         (write-char #\{ stream)
         (loop for ((key . v) . more) on (rest value)
               do (write-json-string key stream) (write-char #\: stream) (write-json v stream)
                  (when more (write-char #\, stream)))
         (write-char #\} stream))
        ((and (consp value) (eq (first value) :array))
         (write-char #\[ stream)
         (loop for (v . more) on (rest value)
               do (write-json v stream) (when more (write-char #\, stream)))
         (write-char #\] stream))
        (t (write-json-string (princ-to-string value) stream))))
