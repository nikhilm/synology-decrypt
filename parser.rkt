#lang racket/base

(require racket/contract)
(require racket/match)
(require racket/dict)
(require racket/list)
(require base64)
(require (prefix-in synology: "format.b"))

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

; Thanks to binfmt author Bogdan Popa for this helper function.
(define ref
  (case-lambda
    [(id v)
     (define p (assq id v))
     (unless p
       (error 'ref "key not found: ~s~n  have: ~e" id (map car v)))
     (cdr p)]
    [(id . args)
     (ref id (apply ref args))]))

(define (u8-list? l)
  (equal? (car l) 'u8_1))

(define/contract (u8-list-to-string u8-list)
  (u8-list? . -> . string?)
  (bytes->string/utf-8 (u8-list-to-bytes u8-list)))

(define/contract (u8-list-to-bytes u8-list)
  (u8-list? . -> . bytes?)
  (apply bytes (cdr u8-list)))

(define (kv-pair? l)
  (and (equal? (length l) 2)
       (equal? (car (car l)) 'key_1)
       (equal? (car (cadr l)) 'value_1)))

(define (parse-primitive prim)
  (case (car prim)
    [(string-rest_1) (u8-list-to-string (list-ref prim 2))]
    [(bytes-rest_1) (u8-list-to-bytes (list-ref prim 2))]
    [(int-rest_1) (cadr (list-ref prim 2))]
    [(dict-entry_1) (parse-dict-entry prim)]
    [else (error "no primitive match ~a" (car prim))]))

(define/contract (parse-kv kv)
  (kv-pair? . -> . any)
  ; index 1 is always '(num_1 . <n>) and index 2 is the primitive
  `(,(parse-primitive (list-ref (car kv) 2)) . ,(parse-primitive (list-ref (cadr kv) 2))))

(define (parse-dict-entry de)
  (case (car de)
    [(dict-entry_1)
     (for/list [(kv (in-list (cdr de)))]
       (parse-kv kv))]
    [else "parse-dict-entry fail"]))

(define (parse-dict d)
  ; prefix-byte (dict-entry_1 with actual dictionary entries) end-byte
  (make-hash (parse-dict-entry (list-ref d 1))))

(define (parse-dicts ds)
  ; (dict_1 dict dict dict)
  (for/list [(d (in-list (cdr ds)))]
    (parse-dict d)))

(define (parse-string string-rest)
  (caddr string-rest))

(define (parse-whole whole)
  (car
   (for/list ([elem (in-list whole)]
              #:when (equal? (car elem) 'dict_1))
     (parse-dicts elem))))

; The problem with data being a dictionary is we have to parse the whole file into memory before we can process it.
; We would much rather assume that the metadata dictionary comes first, and then the data dictionary is streamed somehow, and then the md5 metadata dict can be read later (or can be read from the end)

(define (all-dicts? ds)
  (for/and ([d (in-list ds)])
    (dict? d)))

(define (data-dict? d)
  #;(printf "~v ~v~n" (hash-ref d "type" #f) (equal? (hash-ref d "type" #f) "data"))
  (equal? (hash-ref d "type" #f) "data"))

(define (make-encryption-information d)
  (encryption-information
   (equal? 1 (dict-ref d "compress"))
   (dict-ref d "digest")
   (base64-decode (dict-ref d "enc_key1"))
   (base64-decode (dict-ref d "enc_key2"))
   (equal? 1 (dict-ref d "encrypt"))
   (dict-ref d "file_name")
   (dict-ref d "key1_hash")
   (dict-ref d "key2_hash")
   (string->bytes/latin-1 (dict-ref d "salt"))
   (dict-ref d "session_key_hash")
   (dict-ref d "version")))

(define/contract (three-dicts-to-synology-file dicts)
  (all-dicts? . -> . any)
  (match/values (partition data-dict? dicts)
    ([datas metadatas]
     (printf "chunks: ~v metadata: ~v~n" (length datas) metadatas)
     (list (make-encryption-information (car metadatas)) datas (second metadatas)))))

(define (parse-synology-port input-port)
  (let ([dicts (parse-whole (synology:format input-port))])
    (three-dicts-to-synology-file dicts)))

(provide
 parse-synology-port
 (struct-out encryption-information))