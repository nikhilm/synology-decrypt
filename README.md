synology-decrypt
================

An open source implementation of the Synology Cloudsync Decryption tool.
This can be used to decrypt files encrypted using Synology Cloudsync when uploading from a Network Attached Storage device to a cloud provider.

For now, you will need to install [Racket](https://racket-lang.org), then run:

```
raco pkg install --auto --name synology-decrypt
racket main.rkt --help
racket main.rkt <input> <output>
```
