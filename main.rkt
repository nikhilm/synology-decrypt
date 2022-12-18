#lang racket/base
(require file/md5)
(require racket/port)
(require racket/list)
(require racket/match)
(require base64)
(require crypto)
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

(define (decrypt-data password encryption-struct data-bytes)
  (let ([enc1-key (decrypted-enc1-key password encryption-struct)])
    (match (openssl-kdf (hex-string->bytes (bytes->string/latin-1 enc1-key)) (bytes) 32 16)
      [(list key iv)
       (decrypt '(aes cbc) key iv data-bytes #:pad #t)])))

(define (decrypt-ports password input-port output-port)
  (define parsed-parts (parse-synology-port input-port))
  (define encryption-struct (first parsed-parts))
  (define file-bytes (second parsed-parts))
  (define metadata (third parsed-parts))
  (define plaintext (decrypt-data password encryption-struct file-bytes))
  (lz4-decompress-through-ports (open-input-bytes plaintext) output-port))


(module+ main
  (require racket/cmdline)

  (crypto-factories (list libcrypto-factory))

  ; TODO: Allow password file to be specified on the command line
  (define (decrypt-file input output)
    (define password (read-bytes-line))
    (call-with-input-file* input
      (lambda (input-port)
        (call-with-output-file* output
                                (lambda (output-port)
                                  (decrypt-ports password input-port output-port))))))

  (command-line
   #:program "synology-decrypt"
   #:args (input output)
   (decrypt-file input output)))
