#lang racket/base
(require file/md5)
(require racket/match)
(require crypto)
(provide (struct-out encryption-information) decrypted-enc1-key openssl-kdf)

(struct encryption-information
  (compressed
   digest-type
   enc_key1
   enc_key2
   encrypted
   file_name
   key1_hash
   key2_hash
   salt
   session_key_hash
   version)
  #:transparent)

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
