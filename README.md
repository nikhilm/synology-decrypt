synology-decrypt
================

An open source implementation of the Synology Cloudsync Decryption tool.
This can be used to decrypt files encrypted using Synology Cloudsync when uploading from a Network Attached Storage device to a cloud provider.

For now, you will need to install [Racket](https://racket-lang.org), then run:

```
raco pkg install --auto --name synology-decrypt
racket main.rkt --help
racket main.rkt <input> <output>
# This will block on stdin, where you must type in the decryption password, then press Enter and Ctrl+D.
```

Alternatively, you can store the password in a file, and then redirect the program's stdin to it.
See [this page](https://www.netmeister.org/blog/passing-passwords.html) for why this program prefers to read the password from stdin instead of an environment variable or command line argument.

Personally, I use [1password](https://1password.com) and using the [CLI](https://1password.com/downloads/command-line/) tool, I just pipe the password to this program like so:

```
eval $(op signin)  # Assuming bash/zsh. Skip the `$` for fish.
op read 'op://<vault name>/<item name>/password' | racket main.rkt encrypted-file output-file
```
