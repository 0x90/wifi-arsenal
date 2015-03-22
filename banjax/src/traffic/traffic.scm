
(define (sum-times)
  (+ t-ctrl t-ctrl-ifs t-ctrl-delta
     t-data t-data-ifs t-data-cw t-data-delta
     t-mgmt t-mgmt-ifs t-mgmt-cw t-mgmt-delta))

(define (percent x y)
  (* (exact->inexact (/ x y)) 100))
