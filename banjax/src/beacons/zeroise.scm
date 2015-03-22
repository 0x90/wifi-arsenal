#!/usr/bin/guile
!#

(use-modules (ice-9 format))

(let ((first (read)))
  (let filter ((l first) (n (cadr first)))
    (cond ((eof-object? l)
           #t)
          ((and (list? l) (= (length l) 3))
           (format #t "(~s ~s ~s)~&" (car l) (- (cadr l) n) (caddr l))
           (filter (read) n))
          (else
           #f))))
