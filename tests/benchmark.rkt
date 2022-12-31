#lang racket
(require benchmark plot/pict "../main.rkt" crypto crypto/libcrypto racket/file)

(crypto-factories (list libcrypto-factory))


(define results
  (run-benchmarks
   ; whats
   '(original)
   ; hows
   '()
   ; run
   (lambda (impl)
     (let [(encrypted-file (build-path (current-directory) "test-data" "csenc" "5000words-3.1.txt"))
           (actual-decrypted-file (make-temporary-file* #"synology-decrypt-test" #".txt"))]
       (parameterize ([current-input-port (open-input-bytes #"buJx9/y9fV")])
         (decrypt-file encrypted-file actual-decrypted-file #:implementation impl))
       (delete-file actual-decrypted-file))
     )
   #:extract-time 'delta-time))

(parameterize ([plot-x-ticks no-ticks])
  (plot-pict
   #:title "decrypt implementations"
   #:x-label #f
   #:y-label "time"
   (render-benchmark-alts
    ; default options
    '()
    results
    ; format options so we can omit the index in the size list
    #:normalize? #f)))