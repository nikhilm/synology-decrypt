#lang info
(define collection "synology-decrypt")
(define deps '("base64-lib"
               "binfmt"
               "crypto-lib"
               "lz4-lib"
               "base"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib" "benchmark"))
(define scribblings '(("scribblings/synology-decrypt.scrbl" ())))
(define pkg-desc "Description Here")
(define version "0.0")
(define pkg-authors '(me@nikhilism.com))
(define license '(Apache-2.0))
