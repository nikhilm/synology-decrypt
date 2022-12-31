#lang racket
(require benchmark plot/pict "../main.rkt" crypto crypto/libcrypto racket/file)

(crypto-factories (list libcrypto-factory))


(define results
  (run-benchmarks
   ; whats
   '(decrypt)
   ; hows
   (list (list #f #t))
   ; run
   (lambda (_ use-external-lz4)
     (let [(encrypted-file (build-path (current-directory) "test-data" "csenc" "5000words-3.1.txt"))
           (actual-decrypted-file (make-temporary-file* #"synology-decrypt-test" #".txt"))]
       (parameterize ([current-input-port (open-input-bytes #"buJx9/y9fV")])
         (decrypt-file encrypted-file actual-decrypted-file #:external-lz4 use-external-lz4))
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
    (list #f)
    results
    #:format-opts (lambda (args) (if (first args) "external lz4" "racket lz4"))
    #:normalize? #f)))