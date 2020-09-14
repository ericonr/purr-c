# purr-c

This is a pure C client for the
[PurritoBin](https://github.com/PurritoBin/PurritoBin) pastebin server, and uses
PurritoBin's author's instance in <https://bsd.ac> by default.

It was written as an exercise for learning network and crypto libraries, and
uses [BearSSL](https://www.bearssl.org/) for symmetric encryption (supported by
PurritoBin's online interface as well as its [suggested
clients](https://github.com/PurritoBin/PurritoBin/tree/master/clients)) and SSL
interaction with the server.
[libbaseencode](https://github.com/paolostivanin/libbaseencode) has been
vendored in (can be found in `external/libbaseencode`), but has also gone
through some changes, namely removing null-byte checking from the base64
encoding function, adding an output length parameter to the base64 decoding
function and fixing Valgrind warnings about out-of-bounds accesses.

The code has a few instances of `// TODO: remove hack` comments and the like,
which I hope to get to someday.

## Usage

Usage information can be viewed with `purr -h`.

## Build dependencies

The only external dependency is BearSSL, and GNU Make and a C compiler are
required for building. This program currently depends on Linux's `getrandom(2)`
function, but I plan on adding at least an `arc4random_buf(3)` implementation.

## Acknowledgements

- Thomas Pornin for BearSSL
- Laurent Bercot for s6-networking (even though it's no longer in use here)
- epsilon-0 for PurritoBin (and the valuable help while I was testing this
   program)
- paolostivanin for libbaseencode
