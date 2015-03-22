#!/usr/bin/guile
!#

(use-modules (ice-9 format))

(let ((first (read)))
  (let filter ((l first) (n (cadr first)))
    (cond ((and (list? l) (= (length l) 5))
           (format #t "(~s ~s ~s ~s ~s)~&" (car l) (- (cadr l) n) (caddr l) (list-ref l 3) (list-ref l 4))
           (filter (read) n))
          (else
           l))))
