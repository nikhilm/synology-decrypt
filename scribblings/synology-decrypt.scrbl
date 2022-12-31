#lang scribble/manual
@require[scribble/bnf
         @for-label[synology-decrypt
                    racket/base]]

@title{synology-decrypt}
@author[(author+email "Nikhil Marathe" "me@nikhilism.com")]

@defmodule[synology-decrypt]

This package implements a library and command-line client to decrypt files encrypted by the @link["https://www.synology.com/en-us/dsm/feature/cloud_sync"]{Synology Cloudsync} program.

Files may be encrypted with either a password or a private key. This module has the following limitations:
@itemlist[@item{It only supports password based decryption.}
          @item{It only supports version 3.1 of the @seclink["file-format"]{encryption format}.}]

@section{Running the program}
@codeblock|{
racket main.rkt <encrypted file path> <decrypted output path>
}|

When run like this, the program will read standard input to obtain the decryption password. Standard input is read to avoid leaking the password in shell history or in-memory process information. Type the password and press Ctrl+D to close standard input.

@section{Reference}

This package can also be used as a library.

@defproc[(decrypt-ports [password string?] [input-port input-port?] [output path-string?]) void?]{
 Decrypts data from @racket[input-port], using @racket[password] as the password. Decrypted and decompressed data is written to @racket[output-port].
}

@defproc[(decrypt-file [password string?] [input path-string?] [output-port output-port?]) void?]{
 Decrypts data from the file with path @racket[input] which must be readable, using @racket[password] as the password. Decrypted and decompressed data is written to the path @racket[output].
}

@section[#:tag "file-format"]{Encrypted File Format}

The Synology Cloudsync encrypted file is a binary file describing structured data.
The structured data begins with some magic bytes identifying the file, then a series of @deftech[#:normalize? #t]{dictionaries}.
Dictionary keys are strings, while values can be integers, byte strings, strings or nested @tech{dictionaries}.

@subsection{Syntax}
The syntax can be described with this BNF grammar.


@BNF[(list @nonterm{file}

           @BNF-seq[@nonterm{magic}

                    @nonterm{magic-hash}

                    @kleeneplus[@nonterm{dictionary}]])

     (list @nonterm{magic}

           @litchar{__CLOUDSYNC_ENC__})

     (list @nonterm{magic-hash}
           @litchar{d8d6ba7b9df02ef39a33ef912a91dc56})

     (list @nonterm{dictionary}

           @BNF-seq[@litchar{0x42} @kleenestar[@nonterm{dictionary-entry}] @litchar{0x40}])

     (list @nonterm{dictionary-entry}
           @BNF-seq[@nonterm{key} @nonterm{value}])

     (list @nonterm{key} @nonterm{string})

     (list @nonterm{value}
           @BNF-alt[@nonterm{string} @nonterm{bytes} @nonterm{int} @nonterm{dictionary}])

     (list @nonterm{string} @BNF-seq[@litchar{0x10} @nonterm{bytes-with-len}])

     (list @nonterm{bytes} @BNF-seq[@litchar{0x11} @nonterm{bytes-with-len}])

     (list @nonterm{int} @BNF-seq[@litchar{0x01} @nonterm{int-with-len}])

     (list @nonterm{bytes-with-len} @BNF-seq[@nonterm{length} @kleeneplus[@racket[byte?]]])

     (list @nonterm{length} @elem{unsigned short, big endian encoded (2 bytes)})

     (list @nonterm{int-with-len}
           @BNF-seq[@elem{1 byte length followed by length bytes (in practice always 1)}])]

@subsection{Semantics}

The encryption scheme uses the password to derive a 32-byte key and 16-byte initialization vector (IV). The @secref["kdf"] is the one used by OpenSSL. The key+IV is used to decrypt @litchar{enc_key1} using AES in Cipher Block Chaining (AES-CBC) mode.

The decrypted @litchar{enc_key1} will be a hex string. It should be converted to bytes and fed back into the @secref["kdf"]. This will result in the final key+IV used to decrypt the actual file contents.

The first dictionary in the file describes the @deftech{encryption information}. It consists of the following key-value pairs:

@itemlist[
 @item{@litchar{"compress"} - always @litchar{1}, indicating the file has been compressed before encryption.}
 @item{@litchar{"digest"} - TODO}
 @item{@litchar{"enc_key1"} - base64 encoded, encrypted key. The user's password can be used to decrypt this to derive the decryption key.}
 @item{@litchar{"enc_key2"} - TODO}
 @item{@litchar{"encrypt"} - always @litchar{1}, indicating the file is encrypted.}
 @item{@litchar{"file_name"} - string representing the original file name.}
 @item{@litchar{"key1_hash"} - TODO}
 @item{@litchar{"key2_hash"} - TODO}
 @item{@litchar{"salt"} - a string containing the salt used for key derivation.}
 @item{@litchar{"session_key_hash"} - TODO. Used to validate the encryption key integrity.}
 @item{@litchar{"version"} - a (sub) dictionary:
  @itemlist[
 @item{@litchar{"major"} - @litchar{3}}
 @item{@litchar{"minor"} - @litchar{1}}]}]

Once the @tech{encryption information} is obtained, the remaining file (except for the last dictionary) consists of @deftech{data dictionaries} which have two key-value pairs:

@itemlist[
 @item{@litchar{"type"} - always @litchar{"data"}.}
 @item{@litchar{"data"} - bytes representing encrypted chunks.}]

The data values are always 8192 bytes long, except the last one. The way encryption is performed is to pass the original file through AES-CBC (which is a stream cipher) using the key+IV derived above. The data is padded with PKCS7 padding as part of the process. Then the encrypted data is split in 8192 byte chunks. If @litchar{"compress"} is true (@litchar{1}), the original file is compressed using LZ4 @italic{before} encryption.

This means, to decrypt the data, one must feed all the chunks into a stateful AES decryption routine, initialized with the key+IV above. Then the data must be run through LZ4 decompression to obtain the original file.

Finally, the last dictionary in the file is an additional @italic{meta-data dictionary} that contains the MD5 checksum of the decrypted (original) file.

@subsection[#:tag "kdf"]{Key Derivation Function}

TODO Describe in words.

@racketblock[
 (code:comment @#,elem{helper})
 (define (openssl-kdf-iter password salt key-size iv-size key-iv-buffer temp)
   (let ([repeat-count (if (eq? 0 (bytes-length salt)) 1 1000)])
     (if (< (bytes-length key-iv-buffer) (+ key-size iv-size))
         (let ([temp (repeated-hash (bytes-append temp password salt) repeat-count)])
           (openssl-kdf-iter password salt key-size iv-size (bytes-append key-iv-buffer temp) temp))
         key-iv-buffer)))

 (define (openssl-kdf password salt key-size iv-size)
   (let* ([count 1000]
          [key-iv-output (openssl-kdf-iter password salt key-size iv-size (bytes) (bytes))])
     (list (subbytes key-iv-output 0 key-size) (subbytes key-iv-output key-size))
     ))
 ]

@section{References}

TODO Acknowledgements and references.