#lang racket/base
(require "../main.rkt")
(require crypto)
(require racket/system)
(require crypto/libcrypto)

(module+ test
  (require rackunit)
  (require racket/file)
  (crypto-factories (list libcrypto-factory))
  (let [(encrypted-file (build-path (current-directory) "test-data" "csenc" "5000words-3.1.txt"))
        (expected-decrypted-file (build-path (current-directory) "test-data" "plain" "5000words-3.1.txt"))
        (actual-decrypted-file (make-temporary-file* #"synology-decrypt-test" #".txt"))]
    (parameterize ([current-input-port (open-input-bytes #"buJx9/y9fV")])
      (decrypt-file encrypted-file actual-decrypted-file #:implementation 'recursive-descent))
    ; todo attach exn handler so we always remove
    (check-true (system* "/usr/bin/diff" "-q" expected-decrypted-file actual-decrypted-file))
    (delete-file actual-decrypted-file)))
