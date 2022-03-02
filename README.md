# xsum

**xsum** is a utility for calculating checksums that supports:
- 18 cryptographic hashing algorithms
- 12 non-cryptographic hashing algorithms

The `xsum` CLI can be used in place of `shasum`, `md5sum`, or similar utilities.

xsum differs from existing tools that calculate checksums in that it supports:
1. Calculating checksums of **directories** using [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree).
   Merkle trees are the data structure used by Docker images. They allow for concurrency when generating/validating checksums.
2. Calculating checksums that include file attributes such as type, UID/GID, permissions, xattr, etc.
3. Plugins, including:
   1. **xsum-pcm** (in repo): checksums of raw PCM in audio files (e.g., AAC, MP3, FLAC, ALAC) that remain constant when metadata tags change.

With extended mode flags (e.g., `xsum -d [paths...]`), xsum checksums follow a three-part format:
```
[checksum type]:[checksum]:[attribute mask]  [file name]
```
For example:
```
sha256:c1ee0a0a43b56ad834d12aa7187fdb367c9efd5b45dbd96163a9ce27830b5651:7777+ug  The Beatles
```
This allows checksums to:
1. Encode which file/directory attributes (e.g., UNIX permissions) are included in the hash.
2. Specify which hashing algorithm should be used to validate hashes.

The data format used for extended checksums is specified in [FORMAT.md](FORMAT.md) and may be considered stable.

Extended checksums are portable across operating systems, as long as all requested attributes are supported.

**NOTE:** By default, xsum only calculates checksums for **file/directory contents**, even in extended mode. 
This means that by default, extended mode only includes attributes (e.g., permissions) for files/directories that are **inside a specified path**.
Use `-i` to include top-level attributes. Without `-i`, `xsum` will not append an attribute mask for non-directories, for example:
```
$ xsum -d "The Beatles.tar"
sha256:d0ed3ba499d2f79b4b4af9b5a9301918515c35fc99b0e57d88974f1ee74f7820  The Beatles.tar
```

Additionally, without any extended mode flags, xsum checksums follow the standard format used by other checksum tools:
```
$ xsum "The Beatles.tar"
d0ed3ba499d2f79b4b4af9b5a9301918515c35fc99b0e57d88974f1ee74f7820  The Beatles.tar
```

### Installation

Binaries for macOS, Linux, and Windows are [attached to each release](https://github.com/sclevine/xsum/releases). (WIP)

`xsum` is also available as a [Docker image](https://hub.docker.com/r/sclevine/xsum). (WIP)

### Go Package

xsum may be imported as a Go package.
See [godoc](https://pkg.go.dev/github.com/sclevine/xsum) for details.
NOTE: the current Go API should not be considered stable.

## Performance

xsum aims to:
- Minimize execution time using concurrency
- Avoid opening more files than available CPUs
- Provide entirely deterministic output
- Avoid buffering or delaying output

This makes xsum ideal for calculating checksums of large directory structures (e.g., for archival purposes):
```
laptop:Library stephen$ time find "The Beatles/" -type f -print0|xargs -0 shasum -a 256
...

real    0m24.775s
user    0m21.250s
sys     0m2.209s
```
```
laptop:Library stephen$ time xsum -f "The Beatles/"
sha256:c1ee0a0a43b56ad834d12aa7187fdb367c9efd5b45dbd96163a9ce27830b5651:7777+ug  The Beatles

real    0m2.832s
user    0m19.328s
sys     0m0.937s
```

## Security Considerations

- xsum only uses hashing algorithms present in Go's standard library and `golang.org/x/crypto` packages.
- xsum uses a [subset](https://luca.ntop.org/Teaching/Appunti/asn1.html) of [DER-encoded ASN.1](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der) for deterministic and canonical encoding of all metadata and Merkle Trees.
- Extended checksums (which include a checksum type and attribute mask) should only be validated with xsum to avoid collision with files that contain xsum's data format directly.
- Certain (generally non-cryptographic) hash functions supported by xsum may have high collision rates with specific patterns of data.
  These hash functions may not be appropriate when used to generate checksums of directories.
  Unless you know what you are doing, choose a strong cryptographic hashing function (like sha256) when calculating checksums of directories.
