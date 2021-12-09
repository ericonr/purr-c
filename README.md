# purr-c

![Tests](https://github.com/ericonr/purr-c/workflows/Tests/badge.svg?event=push)

This repository holds some loosely related networking projects. This is mainly a
learning exercise for network and TLS programming, with a dash of crypto, and
all of the programs contained here should be treated as such.

The [BearSSL](https://www.bearssl.org/) library was chosen as the TLS and crypto
implementation.

All pieces of code should be either self explanatory or well commented. If you
find any part of the code lacking in those, feel free to open an issue.

## Building

The only non-optional external dependency is the BearSSL library - on [Void
Linux](https://voidlinux.org/), it can be obtained via the `bearssl-devel`
package.

This project can be built with two different build systems.

### GNU Make

GNU Make and a C99 compiler, such as [cproc](https://git.sr.ht/~mcf/cproc), are
required for building.

You can build and install the project with the commands below:

```
$ ./configure # creates config.mk
$ make
$ make install PREFIX=$HOME/.local
```

### Meson

Alternatively, you can use the Meson build system, which requires the Meson tool
itself, Ninja, a C99 compiler that Meson knows about (GCC or Clang will do the
trick), and the `msgfmt` tool from GNU Gettext or a compatible implementation.
Note that **only** the Meson builds support localization, and it isn't optional.

You can build and install the project with the commands below:

```
$ meson build --prefix $HOME/.local
$ ninja -C build/
$ ninja -C build/ install
```

Instead of using Ninja, you can use
[samurai](https://github.com/michaelforney/samurai).

## Programs

### purr

This is a pure C client for the
[PurritoBin](https://github.com/PurritoBin/PurritoBin) pastebin server, and uses
PurritoBin's author's instance at <https://bsd.ac> by default. It also supports
[zdykstra's pastebin](https://github.com/zdykstra/pastebin).

It supports symmetric paste encryption (as supported by PurritoBin's online
interface and its [suggested
clients](https://github.com/PurritoBin/PurritoBin/tree/master/clients)). This
makes it possible to share paste links that can only be decrypted by someone who
has the keys to them. The key and IV are stored in the url's hash property, and
are never sent to the server.

It can also work as a very limited `curl` alternative, due to its support of
both HTTP and HTTPS. It can use `HTTP/1.0` or `HTTP/1.1` for requests, and
always requires the `Content-Length` field in the response header (no chunked
transfer here!) - this is done because I have found servers that don't send
`notify_close` when their transmission is done, instead relying on the
`Content-Length` field to provide enough information for the client to determine
if the transmission was sucessful or if the connection was terminated before it
should have been.

This program uses `getentropy(3)` for key and IV generation.

#### Usage

Usage information can be viewed with `purr -h`. There are two symlinks to the
`purr` executable, `meow` and `meowd`, which are used as shortcuts to send and
receive encrypted pastes, respectively.

### gemi

This is a (not so dumb anymore) [Gemini](https://gemini.circumlunar.space/)
client. It doesn't support TOFU (Trust On First Use) yet, so it isn't fully
compliant with the Gemini spec, but it can talk to (almost) any server, not
being limited to those whose certificates can be verified by the local trust
anchors.

It has a built-in "navigation" mechanism via the `-b` command line flag, which
parses the received page, finds links, asks the user to select one, and finally
execs into itself with the new link.

It can parse server responses with status headers, including redirects, and can
deal with "complex" links, such as `../../docs`. However, it doesn't pass the
gemini browser torture test.

#### Usage

Usage information can be viewed with `gemi -h`.

## Localization

The Meson build system has been added mainly due to its capabilities for dealing
with translation via [GNU gettext](https://www.gnu.org/software/gettext/).
Documentation for these features can be found in their [official
docs](https://mesonbuild.com/Localisation.html) and [module
manual](https://mesonbuild.com/i18n-module.html).

For reference, some useful commands:

```
$ ninja -C build/ purr-c-pot # generate pot file
$ ninja -C build/ purr-c-update-po # update po files
$ ninja -C build/ purr-c-gmo # builds translations without installing
```

### Contributing translations

Simply add the locale name (usually in the form `ll` or `ll_CC`, where `ll`
refers to the language and `CC` to the country - see the [GNU Gettext manual
section on Locale
Names](https://www.gnu.org/software/gettext/manual/html_node/Locale-Names.html))
to the `po/LINGUAS` file and run the command for updating po files, shown above.
After that, you will be ready to start working on the new `po/ll[_CC].po` file!

## Acknowledgements

- Thomas Pornin for [BearSSL](https://www.bearssl.org/)
- Laurent Bercot for [s6-networking](http://skarnet.org/software/s6-networking/)
   (even though it's no longer in use here)
- epsilon-0 for [PurritoBin](https://github.com/PurritoBin/PurritoBin) (and the
   valuable help while I was testing this program)
- paolostivanin for
   [libbaseencode](https://github.com/paolostivanin/libbaseencode) (also no
   longer used here)
