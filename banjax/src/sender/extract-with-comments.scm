#!/usr/bin/guile -s
!#

(use-modules (ice-9 format)
             (ice-9 rdelim)
             (ice-9 regex))


;;; apply fn to lines from port
;;; preserves comments/blank lines from original file

(define (filter-port in out fn)
  (let ((s (read-line in)))
    (cond ((eof-object? s)
           s)
          ((= 0 (string-length s))
           (format out "~%")
           (filter-port in out fn))
          ((eqv? #\# (string-ref s 0))
           (format out "~a" s)
           (filter-port in out fn))
          (else
           (fn s)
           (filter-port in out fn)))))


;;; write named fields from specified file

(define (filter-named-fields in out fields)

  (define (make-field-regexp f)
    (make-regexp (string-append f ":[ \t\n]*([^, \t\n]*)") regexp/icase))
  
  (let ((regexps (map make-field-regexp fields)))
    (filter-port in out (lambda (s)
                          (map (lambda (regexp) 
                                 (let ((match (regexp-exec regexp s)))
                                   (if (regexp-match? match)
                                       (format out "~a\t" (substring s (match:start match 1) (match:end match 1)))
                                       (format out "-\t")))) regexps)
                          (format out "~&")))))


;;; extract named fields from file

(let ((fields (cdr (command-line))))
  (format (current-output-port) "# Generator: ~a~&" (command-line))
  (filter-named-fields (current-input-port) (current-output-port) fields))
