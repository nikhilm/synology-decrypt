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

(define (decrypt-ports password input-port output-port)
  (define parsed-parts (parse-synology-port input-port))
  (define encryption-struct (first parsed-parts))
  (printf "E-struct ~v~n" encryption-struct)
  (define key-iv (let ([enc1-key (decrypted-enc1-key password encryption-struct)])
                   (printf "enc1 key ~v~n" enc1-key)
                   (openssl-kdf (hex-string->bytes (bytes->string/latin-1 enc1-key)) (bytes) 32 16)))
  (define data-dicts (second parsed-parts))

  (define encrypted-ports
    (for/list ([data-dict (in-list data-dicts)])
      (open-input-bytes (hash-ref data-dict "data"))))
  ; Ok, here is the fucked up bit about the file format.
  ; It first encrypts the entire file using a stream cipher (stateful), along with inserting padding.
  ; It _then_ splits the file into 8KB chunks.
  ; This means, to reverse it, we necessarily need a state-ful decryption routine, to which we can pass encrypted chunks.
  ; Racket doesn't seem to have it right now.
  ; this is gonna be a super large buffer since I can't find a port based version
  ; so we need to use make-decrypt-ctx!
  (define decrypted-data (decrypt '(aes cbc) (first key-iv) (second key-iv) (apply input-port-append #f encrypted-ports)))
  (lz4-decompress-through-ports (open-input-bytes decrypted-data) output-port)

  ; TODO: md5 validation
 
  )

(module+ main
  (require racket/cmdline)

  (crypto-factories (list libcrypto-factory))

  ; TODO: Allow password file to be specified on the command line
  (define (decrypt-file input output)
    (define password (read-bytes-line))
    (call-with-input-file* input
      (lambda (input-port)
        ; TODO(nikhilm): Revert truncation to error
        (call-with-output-file* output
                                (lambda (output-port)
                                  (decrypt-ports password input-port output-port)) #:exists 'truncate))))

  (command-line
   #:program "synology-decrypt"
   #:args (input output)
   (decrypt-file input output)))
