#lang racket/base
(require file/md5)
(require racket/port)
(require racket/list)
(require racket/match)
(require base64)
(require crypto)
(require racket/system)
(require crypto/libcrypto)
(require (only-in file/sha1 hex-string->bytes))
(require file/lz4)

(require "parser.rkt")

(provide decrypt-ports decrypt-file)

(define my-kdf (get-kdf (list 'pbkdf2 'hmac 'md5)))

(define (repeated-hash start count)
  (for/fold ([output start])
            ([i (in-range count)])
    (md5 output #f)))

; this is convoluted, can we do better?
(define (openssl-kdf-iter pwd salt key-size iv-size key-iv-buffer temp)
  (let ([repeat-count (if (eq? 0 (bytes-length salt)) 1 1000)])
    (if (< (bytes-length key-iv-buffer) (+ key-size iv-size))
        (let ([temp (repeated-hash (bytes-append temp pwd salt) repeat-count)])
          (openssl-kdf-iter pwd salt key-size iv-size (bytes-append key-iv-buffer temp) temp))
        key-iv-buffer)))

(define (openssl-kdf pwd salt key-size iv-size)
  (let* ([count 1000]
         [key-iv-output (openssl-kdf-iter pwd salt key-size iv-size (bytes) (bytes))])
    (list (subbytes key-iv-output 0 key-size) (subbytes key-iv-output key-size))
    ))


(define (decrypted-enc1-key password encryption-struct)
  (match (openssl-kdf password (encryption-information-salt encryption-struct) 32 16)
    [(list key iv) (decrypt '(aes cbc)
                            key iv (encryption-information-enc_key1 encryption-struct) #:pad #t)]))

(define (decrypt-impl-original password input-port output-port)
  (define parsed-parts (parse-synology-port input-port))
  (define encryption-struct (first parsed-parts))
  #;(printf "E-struct ~v~n" encryption-struct)
  (define key-iv (let ([enc1-key (decrypted-enc1-key password encryption-struct)])
                   #;(printf "enc1 key ~v~n" enc1-key)
                   (openssl-kdf (hex-string->bytes (bytes->string/latin-1 enc1-key)) (bytes) 32 16)))
  (define data-dicts (second parsed-parts))
  (define aes-ctx (make-decrypt-ctx '(aes cbc) (first key-iv) (second key-iv)))
  ; TODO(nikhilm): If there was a way to have a lazy port, then we could have an list of closures referring to the encrypted chunks (already in memory) instead of
  ; a list of decrypted data (another set of data in memory).
  (define decrypted-ports
    (let ([num-of-chunks (length data-dicts)])
      (for/list ([data-dict (in-list data-dicts)]
                 [i (in-naturals)])
        (let ([decrypted-port (open-input-bytes (cipher-update aes-ctx (hash-ref data-dict "data")))])
          (if (eq? i (sub1 num-of-chunks))
              ; cipher-final is wrinkly since it produces additional output that we must put somewhere
              (input-port-append #f decrypted-port (open-input-bytes (cipher-final aes-ctx)))
              decrypted-port)))))

  (lz4-decompress-through-ports (apply input-port-append #f decrypted-ports) output-port)

  ; TODO: md5 validation
 
  )


(define (decrypt-ports password input-port output-port #:implementation [implementation 'original])
  (case implementation
    [(original) (decrypt-impl-original password input-port output-port)]
    [else (error "Unknown implementation")]))

(define (decrypt-file input output #:implementation [implementation 'original])
  (define password (read-bytes-line))
  (call-with-input-file* input
    (lambda (input-port)
      ; TODO(nikhilm): Revert truncation to error, allow override for tests.
      (call-with-output-file* output
                              (lambda (output-port)
                                (decrypt-ports password input-port output-port #:implementation implementation)) #:exists 'truncate))))

(module+ test
  (require rackunit)
  (require racket/file)
  (crypto-factories (list libcrypto-factory))
  (let [(encrypted-file (build-path (current-directory) "tests" "test-data" "csenc" "5000words-3.1.txt"))
        (expected-decrypted-file (build-path (current-directory) "tests" "test-data" "plain" "5000words-3.1.txt"))
        (actual-decrypted-file (make-temporary-file* #"synology-decrypt-test" #".txt"))]
    (parameterize ([current-input-port (open-input-bytes #"buJx9/y9fV")])
      (decrypt-file encrypted-file actual-decrypted-file))
    ; todo attach exn handler so we always remove
    (check-true (system* "/usr/bin/diff" expected-decrypted-file actual-decrypted-file))
    (delete-file actual-decrypted-file)))

(module+ main
  (require racket/cmdline)

  (crypto-factories (list libcrypto-factory))

  ; TODO: Allow password file to be specified on the command line
  
  (command-line
   #:program "synology-decrypt"
   #:args (input output)
   (decrypt-file input output)))
