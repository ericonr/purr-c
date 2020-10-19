# purr-c

This repository holds some loosely related networking projects of mine. This is
mainly a learning exercise for network, crypto and SSL programming, and all of
the programs inside should be treated as such.

The [BearSSL](https://www.bearssl.org/) library was chosen as the crypto and SSL
implementation.

The code has a few instances of `// TODO: remove hack` comments and the like,
which I hope to get to someday.

## Building

The only external dependency is BearSSL - on Void Linux, this can be obtained
with the `bearssl-devel` package. GNU Make and a C99 compiler, such as
[cproc](https://git.sr.ht/~mcf/cproc), are required for building.

You can build and install the project with the commands below:

```
$ ./configure # creates config.mk
$ make
$ make install PREFIX=$HOME/.local/bin
```

## Programs

### purr

This is a pure C client for the
[PurritoBin](https://github.com/PurritoBin/PurritoBin) pastebin server, and uses
PurritoBin's author's instance in <https://bsd.ac> by default.

It supports symmetric paste encryption (as supported by PurritoBin's online
interface and its [suggested
clients](https://github.com/PurritoBin/PurritoBin/tree/master/clients)). This
makes it possible to share paste links that can only be decrypted by someone who
has the keys to them. The key and IV are stored in the url's hash property, and
are never sent to the server.

It can also work as a very limited `curl` alternative, due to its support of
both HTTP and HTTPS. It uses `HTTP/1.0` for communication, but requires the
`Content-Length` field in the response header - this is done because I have
found servers that don't send `notify_close` when their transmission is done,
instead relying on the `Content-Length` field to provide enough information for
the client to determine if the transmission was sucessful or if the connection
was terminated before it should have been.

This program can use either Linux's `getrandom(2)` system call or BSD's
`arc4random_buf(3)` function for key generation.

#### Usage

Usage information can be viewed with `purr -h`. There are two symlinks to the
`purr` executable, `meow` and `meowd`, which are used as shortcuts to send and
receive encrypted pastes, respectively.

### gemi

This is a (not so dumb anymore) [Gemini](https://gemini.circumlunar.space/)
client. It doesn't support TOFU (Trust On First Use) yet, so it isn't fully
compliant with the Gemini spec, but it can talk to any server, not being limited
to those whose certificates can be verified by the local trust anchors.

It has a built-in "navigation" mechanism via the `-b` command line flag, which
parses the received page, finds links, asks the user to select one, and execs
into itself with the new link.

It supports parsing server messages, including redirects, and can deal with
"complex" links, such as `../../docs`. It is now in the process of being
submitted to the browser torture test.

#### Usage

Usage information can be viewed with `gemi -h`.

## Acknowledgements

- Thomas Pornin for BearSSL
- Laurent Bercot for s6-networking (even though it's no longer in use here)
- epsilon-0 for PurritoBin (and the valuable help while I was testing this
   program)
- paolostivanin for libbaseencode (also no longer used here)
