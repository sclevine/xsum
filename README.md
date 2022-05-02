# xsum

[![GoDoc](https://pkg.go.dev/badge/github.com/sclevine/ztgrep?status.svg)](https://pkg.go.dev/github.com/sclevine/xsum)
[![Tests](https://github.com/sclevine/xsum/actions/workflows/go.yml/badge.svg)](https://github.com/sclevine/xsum/actions/workflows/go.yml)

**xsum** is a utility for calculating checksums that supports:
- [18 cryptographic hash functions](#cryptographic)
- [12 non-cryptographic hash functions](#non-cryptographic)

The `xsum` CLI can be used in place of `shasum`, `md5sum`, or similar utilities.

**xsum** differs from existing tools that calculate checksums in that it can:
- **Calculate a single checksum for an entire directory structure** using [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree).
  - Merkle trees allow for concurrency when calculating checksums of directories. (See [Performance](#performance).)
  - Merkle trees are the same data structure used to reference layers in Docker images.
- **Calculate checksums that include file attributes** such as type, UID, GID, permissions, etc.
  - Attributes are serialized deterministically using [DER-encoded ASN.1](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der). (See [Format](#format).)
  - Attributes include: file mode, UID, GID, mtime, ctime, xattrs, device ID
- Execute plugins, including:
  - [**xsum-pcm**](./cmd/xsum-pcm): calculate checksums of raw PCM inside audio files (e.g., AAC, MP3, FLAC, ALAC)
    - Checksums remain constant when audio file metadata/tags change, but still protect audio stream.
    - Install `xsum-pcm` to `$PATH` and use `xsum -a pcm` to invoke.
    - Requires `ffmpeg`.

## Performance

xsum aims to:
- Minimize execution time using concurrency
- Avoid opening more files than available CPUs
- Provide entirely deterministic output
- Avoid buffering or delaying output

This makes xsum ideal for calculating checksums of large directory structures (e.g., for archival purposes).

With `shasum -a 256`, ~21 seconds:
```
laptop:Library stephen$ time find "The Beatles/" -type f -print0|xargs -0 shasum -a 256
...

real    0m24.775s
user    0m21.250s
sys     0m2.209s
```

With `xsum`, defaulting to sha256, ~3 seconds:
```
laptop:Library stephen$ time find "The Beatles/" -type f -print0|xargs -0 xsum
...

real    0m2.882s
user    0m19.297s
sys     0m0.971s
```

Checksum of entire directory structure (including UID/GID/perms), using ASN.1 Merkle tree, ~3 seconds:
```
laptop:Library stephen$ time xsum -f "The Beatles/"
sha256:c1ee0a0a43b56ad834d12aa7187fdb367c9efd5b45dbd96163a9ce27830b5651:7777+ug  The Beatles

real    0m2.832s
user    0m19.328s
sys     0m0.937s
```
(671 files, 4.2 GB total, tested on 2.3 GHz Quad-Core Intel Core i7)

## Usage

```
$ xsum -h
Usage:
  xsum [OPTIONS] [paths...]

General Options:
  -a, --algorithm=  Use specified hash function (default: sha256)
  -w, --write=      Write a separate, adjacent file for each checksum
                    By default, filename will be [orig-name].[alg]
                    Use -w=ext or -wext to override extension (no space!)
  -c, --check       Validate checksums
  -s, --status      With --check, suppress all output
  -q, --quiet       With --check, suppress passing checksums
  -v, --version     Show version

Mask Options:
  -m, --mask=       Apply attribute mask as [777]7[+ugx...]:
                    +u	Include UID
                    +g	Include GID
                    +s	Include special file modes
                    +t	Include modified time
                    +c	Include created time
                    +x	Include extended attrs
                    +i	Include top-level metadata
                    +n	Exclude file names
                    +e	Exclude data
                    +l	Always follow symlinks
  -d, --dirs        Directory mode (implies: -m 0000)
  -p, --portable    Portable mode, exclude names (implies: -m 0000+p)
  -g, --git         Git mode (implies: -m 0100)
  -f, --full        Full mode (implies: -m 7777+ug)
  -x, --extended    Extended mode (implies: -m 7777+ugxs)
  -e, --everything  Everything mode (implies: -m 7777+ugxsct)
  -i, --inclusive   Include top-level metadata (enables mask, adds +i)
  -l, --follow      Follow symlinks (enables mask, adds +l)
  -o, --opaque      Encode attribute mask to opaque, fixed-length hex (enables mask)

Help Options:
  -h, --help        Show this help message
```

## Format

When extended flags are used (e.g., `xsum -d [paths...]`), xsum checksums follow a three-part format:
```
[checksum type]:[checksum](:[attribute mask])  [file name]
```
For example:
```
sha256:c1ee0a0a43b56ad834d12aa7187fdb367c9efd5b45dbd96163a9ce27830b5651:7777+ug  The Beatles
sha256:d0ed3ba499d2f79b4b4af9b5a9301918515c35fc99b0e57d88974f1ee74f7820  The Beatles.tar
```
This allows xsum to:
1. Encode which attributes (e.g., UNIX permission bits) are included in the hash (if applicable).
2. Specify which hashing algorithm should be used to validate each hash.

The data format used for extended checksums is specified in [FORMAT.md](FORMAT.md) and may be considered stable.

Extended checksums are portable across operating systems, as long as all requested attributes are supported.

### Top-level Attributes

By default, xsum only calculates checksums for file/directory **contents**, including when extended mode flags are used. 
This means that by default, extended checksums only include attributes (e.g., UNIX permissions) for files/directories that are **inside a specified directory**.

Use `-i` to include top-level attributes:
```
$ xsum -fi "The Beatles.tar" "The Beatles/"
sha256:60f6435e916aae9c4b1a7d4d66011963d80c29744a42c2f0b2171e4c50e90113:7777+ugi  The Beatles.tar
sha256:7a90cbb0973419f0d3b10a82e53281aa3f0f317ab4ecce10570f26a7404975a1:7777+ugi  The Beatles
```

Without `-i`, `xsum` will not append an attribute mask for non-directories, for example:
```
$ xsum -f "The Beatles.tar" "The Beatles/"
sha256:d0ed3ba499d2f79b4b4af9b5a9301918515c35fc99b0e57d88974f1ee74f7820  The Beatles.tar  # contents only!
sha256:c1ee0a0a43b56ad834d12aa7187fdb367c9efd5b45dbd96163a9ce27830b5651:7777+ug  The Beatles
```

Additionally, without any extended flags, xsum checksums and errors follow the standard output format used by other checksum tools:
```
$ xsum "The Beatles.tar" "The Beatles/"
d0ed3ba499d2f79b4b4af9b5a9301918515c35fc99b0e57d88974f1ee74f7820  The Beatles.tar
xsum: The Beatles: is a directory
```

## Installation

### Homebrew

The `xsum` CLI and plugins are available via [Homebrew](https://brew.sh):

```
brew install sclevine/tap/xsum
brew install sclevine/tap/xsum-pcm # optional PCM plugin
```

Invoke `xsum-pcm` with `xsum -a pcm`.

### Manual

Binaries for macOS, Linux, and Windows are [attached to each release](https://github.com/sclevine/xsum/releases).

To install `xsum-pcm`, copy the binary to `$PATH`. Invoke it with `xsum -a pcm`.

### Docker

`xsum` is also available as a [Docker image](https://hub.docker.com/r/sclevine/xsum) (includes `xsum-pcm` in `:full`).

## Go Package

xsum may be imported as a Go package.
See [godoc](https://pkg.go.dev/github.com/sclevine/xsum) for details.

NOTE: The current Go API should not be considered stable.

## Security Considerations

- xsum only uses hashing algorithms present in Go's standard library and `golang.org/x/crypto` packages.
- xsum uses a [subset](https://luca.ntop.org/Teaching/Appunti/asn1.html) of [DER-encoded ASN.1](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der) for deterministic and canonical encoding of all metadata and Merkle Trees.
- Extended checksums (which include a checksum type and attribute mask) should only be validated with xsum to avoid collision with files that contain xsum's data format directly.
- Certain (generally non-cryptographic) hash functions supported by xsum may have high collision rates with specific patterns of data.
  These hash functions may not be appropriate when used to generate checksums of directories.
  Unless you know what you are doing, choose a strong cryptographic hashing function (like sha256) when calculating checksums of directories.

## Built-in Hash Functions

### Cryptographic

- `md4`
- `md5`
- `sha1`
- `sha256`
- `sha224`
- `sha512`
- `sha384`
- `sha512-224`
- `sha512-256`
- `sha3-224`
- `sha3-256`
- `sha3-384`
- `sha3-512`
- `blake2s256`
- `blake2b256`
- `blake2b384`
- `blake2b512`
- `rmd160`

### Non-cryptographic

- `crc32`
- `crc32c`
- `crc32k`
- `crc64iso`
- `crc64ecma`
- `adler32`
- `fnv32`
- `fnv32a`
- `fnv64`
- `fnv64a`
- `fnv128`
- `fnv128a`
