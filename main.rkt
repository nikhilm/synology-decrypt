#lang racket/base
(require file/md5)
(require racket/port)
(require racket/list)
(require racket/match)
(require racket/generator)
(require base64)
(require crypto)
(require crypto/libcrypto)
(require racket/system)
(require (only-in file/sha1 hex-string->bytes))
(require file/lz4)

(require "crypto-related.rkt")

(provide decrypt-ports decrypt-file)
  
(define (expect-byte expected)
  (let ([actual (read-byte)])
    (unless (equal? actual expected)
      (raise-argument-error 'expect-byte (format "~v" expected) actual))))

(define (expect-bytes expected)
  (unless (equal? (read-bytes (bytes-length expected)) expected)
    (error "Did not match")))

(define (read-bytes-with-len)
  (let ([len (integer-bytes->integer (read-bytes 2) #f #t)])
    (read-bytes len)
    ))

(define (read-string)
  (expect-byte #x10)
  (bytes->string/utf-8 (read-bytes-with-len)))

(define (read-my-bytes)
  (expect-byte #x11)
  (read-bytes-with-len))

(define (read-my-int)
  (expect-byte #x01)
  (let ([len (read-byte)])
    (integer-bytes->integer (read-bytes len) #f #t)))

(define (read-key)
  (read-string))

(define (read-value)
  (case (peek-byte)
    [(#x10) (read-string)]
    [(#x11) (read-my-bytes)]
    [(#x01) (read-my-int)]
    [(#x42) (read-dict)]))

(define (read-dict-entry)
  (list (read-key) (read-value)))

(define (read-dict)
  (expect-byte #x42)
  (begin0
    (let ([dict (make-hash)])
      (let loop ()
        (unless (equal? (peek-byte) #x40)
          (let ([entry (read-dict-entry)])
            (hash-set! dict (first entry) (second entry)))
          (loop)))
      dict)
    ; discard
    (expect-byte #x40)))

(define (read-encryption-info)
  (let ([d (read-dict)])
    (encryption-information
     (equal? 1 (hash-ref d "compress"))
     (hash-ref d "digest")
     (base64-decode (hash-ref d "enc_key1"))
     (base64-decode (hash-ref d "enc_key2"))
     (equal? 1 (hash-ref d "encrypt"))
     (hash-ref d "file_name")
     (hash-ref d "key1_hash")
     (hash-ref d "key2_hash")
     (string->bytes/latin-1 (hash-ref d "salt"))
     (hash-ref d "session_key_hash")
     (hash-ref d "version"))))

(define (recursive-parser-gen input-port)
  (generator ()
             (parameterize ([current-input-port input-port])
               ; first read and discard the magic bytes
               (expect-bytes #"__CLOUDSYNC_ENC__")
               (expect-bytes  #"d8d6ba7b9df02ef39a33ef912a91dc56")

               (yield (read-encryption-info))
               (let loop ()
                 (unless (eof-object? (peek-byte))
                   (yield (read-dict))
                   (loop)))
               eof)))

(define (decrypt-recursive password input-port decrypted-output-port)
  (define generator (recursive-parser-gen input-port))
  (define encryption-struct (generator))
  (define key-iv (let ([enc1-key (decrypted-enc1-key password encryption-struct)])
                   (openssl-kdf (hex-string->bytes (bytes->string/latin-1 enc1-key)) (bytes) 32 16)))
  (define aes-ctx (make-decrypt-ctx '(aes cbc) (first key-iv) (second key-iv)))
    
  (for ([dict (in-producer generator eof)]
        [i (in-naturals)]
        #:when (equal? (hash-ref dict "type" #f) "data"))
    (write-bytes (cipher-update aes-ctx (hash-ref dict "data")) decrypted-output-port))
  (write-bytes (cipher-final aes-ctx) decrypted-output-port))

(define (decrypt-racket-lz4 password input-port output-port)
  (match-define-values (decrypted-read-port decrypted-write-port) (make-pipe 8192))
  (define lz4-thread
    (thread
     (lambda () (lz4-decompress-through-ports decrypted-read-port output-port))))
  (decrypt-recursive password input-port decrypted-write-port)
  (close-output-port decrypted-write-port)
  (thread-wait lz4-thread))
  
(define (decrypt-external-lz4 password input-port output-port)
  (define lz4-path (find-executable-path "lz4"))
  (unless lz4-path
    (error "lz4 command not found. Please make sure it is installed and in the path."))
  (match-define-values (lz4-proc lz4-stdout lz4-stdin lz4-stderr)
    (subprocess output-port #f #f
                lz4-path
                "-d"))
  (decrypt-recursive password input-port lz4-stdin)
  (close-output-port lz4-stdin)
  (close-input-port lz4-stderr)
  (subprocess-wait lz4-proc))

(define (decrypt-impl-recursive password input-port output-port #:external-lz4 [use-external-lz4? #f])
  (if use-external-lz4?
      (decrypt-external-lz4 password input-port output-port)
      (decrypt-racket-lz4 password input-port output-port)))

(define (decrypt-ports password input-port output-port #:external-lz4 [use-external-lz4? #f])
  (decrypt-impl-recursive password input-port output-port #:external-lz4 use-external-lz4?))

(define (decrypt-file input output #:external-lz4 [use-external-lz4? 'decide])
  (define password (read-bytes-line))
  ; right now the 100mb number is pulled out of thin air. needs benchmarking.
  (define external-lz4 (if (eq? use-external-lz4? 'decide)
                           (and (> (file-size input) (* 100 1024 1024)) (find-executable-path "lz4"))
                           use-external-lz4?))
  (call-with-input-file* input
    (lambda (input-port)
      ; TODO(nikhilm): Revert truncation to error, allow override for tests.
      (call-with-output-file* output
                              (lambda (output-port)
                                (decrypt-ports password
                                               input-port
                                               output-port
                                               #:external-lz4 external-lz4)) #:exists 'truncate))))

(module+ main
  (require racket/cmdline)
  (require setup/getinfo)
  (require pkg/lib)

  (define package-info (get-info/full (pkg-directory "synology-decrypt")))
  (define use-external-lz4 'decide)

  (define (additional-help exn)
    (eprintf
     "Please pass an input file path and output file path to run this program.
In addition pass the encryption password to stdin. It will then decrypt
the input file path using the password and write the decrypted file to
the output file path.~n")
    (raise exn))
  
  ; TODO: Allow password file to be specified on the command line
  (with-handlers ([exn:fail:user? additional-help])
    (command-line
     #:program "synology-decrypt"
     #:once-each [("-V" "--version") "Print the version"
                                     (printf "synology-decrypt ~a~n" (package-info 'version)) (exit)]
     ["--external-lz4"
      "Use the external lz4 program, which is faster for large files. By default, a heuristic is used to decide whether to use this based on the file size. lz4 should exist in the path."
      (set! use-external-lz4 #t)]
     ["--no-external-lz4"
      "Do not use the external lz4 program. See --external-lz4."
      (set! use-external-lz4 #f)]
     #:usage-help
     "\nsynology-decrypt decrypts files encrypted by Synology Cloudsync."
     "<input> is the path to the encrypted file."
     "<output> is the path where decrypted output should be written."
     "The password to use for decryption must be provided on stdin."
     #:args (input output)
   
     (crypto-factories (list libcrypto-factory))
     (decrypt-file input output #:external-lz4 use-external-lz4))))
