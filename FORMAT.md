# xsum Data Format v1.0

## Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in [RFC 2119](http://tools.ietf.org/html/rfc2119).

The key words "unspecified", "undefined", and "implementation-defined" are to be interpreted as described in the [rationale for the C99 standard](http://www.open-std.org/jtc1/sc22/wg14/www/C99RationaleV5.10.pdf#page=18).

An implementation is not compliant if it fails to satisfy one or more of the MUST, MUST NOT, REQUIRED, SHALL, or SHALL NOT requirements for the protocols it implements.
An implementation is compliant if it satisfies all the MUST, MUST NOT, REQUIRED, SHALL, and SHALL NOT requirements for the protocols it implements.

## Checksum Format

xsum v1 MUST output checksums in one of the following formats: 
```
# extended with attributes (e.g., directory, file with +i)
[checksum type]:[checksum]:[attribute mask]  [file name]

# simple with type (e.g., file without +i but with extended mode flags)
[checksum type]:[checksum]  [file name]

# simple
[checksum]  [file name]
```

Examples:
```
$ xsum -fi .gitconfig # extended, human-readable
sha256:01fa7ebf8c4b55cb4dce50725ca2978242086bb81758d5a1a23ba1d5802af5fd:7777+ugi  .gitconfig
$ xsum -fio .gitconfig # extended, fixed-length
sha256:01fa7ebf8c4b55cb4dce50725ca2978242086bb81758d5a1a23ba1d5802af5fd:afff0103  .gitconfig
$ xsum -f .gitconfig # simple (only directories have mask)
sha256:05a024e3204055272b58624880f81389eccfe4808ceba8770ca26efcea100f37  .gitconfig
# xsum .gitconfig # simple (directory input results in error)
05a024e3204055272b58624880f81389eccfe4808ceba8770ca26efcea100f37  .gitconfig
```

### Attribute Mask

xsum v1 MUST support two attribute mask formats:
1. Human-readable with variable length
2. Opaque with fixed length

The human-readable attribute mask MUST begin with an *attribute mode mask* which MAY be followed by an *attribute options mask*.
- The attribute mode mask MUST contain four octal digits, each between `0` and `7`.
- If present, the attribute options mask MUST consist of a single `+` followed by at least one option.
- Example: `7755+ugis`

The opaque attribute mask MUST begin with an *attribute mode mask* that MUST be followed by an *attribute options mask*.
- The attribute mask MUST begin with the case-insensitive hexadecimal digit `a`, denoting the format version.
- The attribute mode mask MUST contain three case-insensitive hexadecimal digits, each between `0` and `f`.
- The attribute options mask MUST contain four case-insensitive hexadecimal digits, each between `0` and `f`.
- Future versions of xsum v1 MAY allow for attribute options masks longer than four digits to encode additional options.
- Example: `afed0143`

If an attribute mask is not present, xsum v1 MUST reject directories, follow symlinks, and read from special files.

#### Attribute Mode Mask

The human-readable attribute mode mask SHALL encode UNIX permissions specified by a four digit octal [umask](https://en.wikipedia.org/wiki/Umask). 
Future versions of xsum v1 MAY allow human-readable attribute mode masks without leading zeros.

The opaque attribute mode mask SHALL encode the human-readable attribute mode mask as a case-insensitive hexadecimal number in big endian format.

#### Attribute Options Mask

For a given checksum output, the attribute options mask MAY include any of the follow options:

0.  `u` = Include UID (user ID)
1.  `g` = Include GID (group ID)
2.  NI  = *Include atime (file access time, reserved but not implemented)*
3.  `t` = Include mtime (file modification time)
4.  `c` = Include ctime (file creation time)
5.  NI  = *Include btime (file birth time, reserved but not implemented)*
6.  `s` = Include file content equivalents for special files (e.g., device IDs for character devices)
7.  `x` = Include xattr (extended file system attributes)
8.  `i` = Apply other attributes to the named file/directory itself
9.  `n` = Exclude file names when summing directories (files are sorted by data checksum)
10. `e` = Exclude file contents
11. `l` = Follow symlinks (without `l`, extended checksums only validate path)

Notes:
- Without `i`, attribute options SHALL only apply to files and directories inside an explicitly specified directory.
- With `i`, attribute options SHALL result in the inclusion of metadata of explicitly specified files and directories.
- Future versions of xsum v1 MAY introduce additional flags, but they SHALL NOT remove existing flags.

The human-readable attribute options mask MUST consist of a single `+` followed by any order of at least one attribute option.

The opaque attribute options mask SHALL encode the human-readable attribute options mask as a case-insensitive hexadecimal number in big endian format.
The number MUST be the sum of all options included in the mask, where the value of each option is two to the power of the ordinal number in the list above.

## Tree Format

The xsum v1 tree format makes use of [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree) to calculate metadata-inclusive checksums of files and directories.

The xsum v1 tree format uses DER-encoded ASN.1 to achieve canonical and deterministic output, such that:
- For two files with identical file contents, xsum MUST always provide the same file content as input to the chosen hash function.
- For two files with identical file attributes, xsum MUST always provide the same file attributes as input to the chosen hash function.
- For two files with different file contents, xsum MUST NOT provide the same file content as input to the chosen hash function.
- For two files with different file attributes, xsum MUST NOT provide the same file attributes as input to the chosen hash function.

### ASN.1 Schema

```
--- ASN.1 Schema

XSum DEFINITIONS  ::=  BEGIN
    File  ::=  SEQUENCE  {
        hash        [0]  EXPLICIT Hash OPTIONAL,
        mode        [1]  EXPLICIT Mode,
        uid         [2]  EXPLICIT INTEGER OPTIONAL,
        gid         [3]  EXPLICIT INTEGER OPTIONAL,
        atime       [4]  EXPLICIT Timespec OPTIONAL,
        mtime       [5]  EXPLICIT Timespec OPTIONAL,
        ctime       [6]  EXPLICIT Timespec OPTIONAL,
        btime       [7]  EXPLICIT Timespec OPTIONAL,
        rdev        [8]  EXPLICIT INTEGER OPTIONAL,
        xattr       [9]  EXPLICIT HashTree OPTIONAL
    }
    Hash  ::=  SEQUENCE  {
        hashType    HashType,
        hash        OCTET STRING
    }
    Mode  ::=  SEQUENCE  {
        mask        BIT STRING,
        mode        BIT STRING
    }
    Timespec  ::=  SEQUENCE  {
        sec         INTEGER,
        nsec        INTEGER
    }
    HashTree  ::=  SEQUENCE  {
        hashType    HashType,
        tree        SET OF HashEntry
    }
    HashEntry  ::=  SEQUENCE  {
        hash        OCTET STRING,
        name        OCTET STRING OPTIONAL
    }
    HashType  ::=  ENUMERATED {
        none        (0),
        md4         (1),
        md5         (2),
        sha1        (3),
        sha256      (4),
        sha224      (5),
        sha512      (6),
        sha384      (7),
        sha512-224  (8),
        sha512-256  (9),
        sha3-224    (10),
        sha3-256    (11),
        sha3-384    (12),
        sha3-512    (13),
        blake2s256  (14),
        blake2b256  (15),
        blake2b384  (16),
        blake2b512  (17),
        rmd160      (18),
        crc32       (19),
        crc32c      (20),
        crc32k      (21),
        crc64iso    (22),
        crc64ecma   (23),
        adler32     (24),
        fnv32       (25),
        fnv32a      (26),
        fnv64       (27),
        fnv64a      (28),
        fnv128      (29),
        fnv128a     (30)
    }
END
```

Where the following definitions MUST be used as input into the chosen hash function:
- File without `i` => Raw file contents
- File with `i` => `File` (DER-encoded) such that `hash` contains hash of raw file contents
- Directory without `i` => `HashTree` (DER-encoded)
- Directory with `i` => `File` (DER-encoded) such that `hash` contains hash of `HashTree` (DER-encoded)

Notes:
- An unordered, DER-encoded ASN.1 `SET` possess a deterministic encoding defined by DER.
- Attribute options specified by the attribute options mask MUST determine whether `OPTIONAL` fields are provided.
- `name` is the basename of the file (i.e., without preceding path elements).
- `mode` and `mask` are encoded as the sum of the file mode type bits, file mode permission bits, and file mode special bits (sticky, setuid, setgid).
  Bit ordering is as defined by Go's [`fs.FileMode`](https://pkg.go.dev/io/fs#FileMode).
- `HashType` MUST always use the same value within the same ASN.1 structure.

### Unintentional Exclusions

Any unintentional exclusions necessary to achieve reproducible checksums SHALL be specified as implemented in `xsum` CLI v1.

