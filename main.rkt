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

(module+ test
  (require rackunit))

; TODO: Actually do this side-effecting state either in main or see the parameterize stuff
(crypto-factories (list libcrypto-factory))
(define my-kdf (get-kdf (list 'pbkdf2 'hmac 'md5)))

(define (repeated-hash start count)
  (for/fold ([output start])
            ([i (in-range count)])
    (md5 output #f)))

; this is convoluted, can we do better?
(define (openssl-kdf-iter pwd salt key-size iv-size key-iv-buffer temp)
  (if (< (bytes-length key-iv-buffer) (+ key-size iv-size))
      (let ([temp (repeated-hash (bytes-append temp pwd salt) (if (eq? 0 (bytes-length salt)) 1 1000))])
        (openssl-kdf-iter pwd salt key-size iv-size (bytes-append key-iv-buffer temp) temp))
      key-iv-buffer))

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

(define (salted-hash salt input)
  (md5 (bytes-append salt input)))
;; Notice
;; To install (from within the package directory):
;;   $ raco pkg install
;; To install (once uploaded to pkgs.racket-lang.org):
;;   $ raco pkg install <<name>>
;; To uninstall:
;;   $ raco pkg remove <<name>>
;; To view documentation:
;;   $ raco docs <<name>>
;;
;; For your convenience, we have included LICENSE-MIT and LICENSE-APACHE files.
;; If you would prefer to use a different license, replace those files with the
;; desired license.
;;
;; Some users like to add a `private/` directory, place auxiliary files there,
;; and require them in `main.rkt`.
;;
;; See the current version of the racket style guide here:
;; http://docs.racket-lang.org/style/index.html

(define (decrypt-ports password input-port output-port)
  (define parsed-parts (parse-synology-port input-port))
  (define encryption-struct (first parsed-parts))
  (define file-bytes (second parsed-parts))
  (define metadata (third parsed-parts))
  (define plaintext (decrypt-data password encryption-struct file-bytes))
  (lz4-decompress-through-ports (open-input-bytes plaintext) output-port))


(module+ main
  ;; (Optional) main submodule. Put code here if you need it to be executed when
  ;; this file is run using DrRacket or the `racket` executable.  The code here
  ;; does not run when this file is required by another module. Documentation:
  ;; http://docs.racket-lang.org/guide/Module_Syntax.html#%28part._main-and-test%29

  (require racket/cmdline)

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
