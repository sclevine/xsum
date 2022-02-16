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

# simple with type (e.g., file without +i but with extended mode flag)
[checksum type]:[checksum]  [file name]

# simple
[checksum]  [file name]
```

For example:
```
$ xsum -fi .gitconfig # extended, human-readable
sha256:01fa7ebf8c4b55cb4dce50725ca2978242086bb81758d5a1a23ba1d5802af5fd:7777+ugi  .gitconfig
$ xsum -fio .gitconfig # extended, fixed-length
sha256:01fa7ebf8c4b55cb4dce50725ca2978242086bb81758d5a1a23ba1d5802af5fd:fff4300  .gitconfig
```

```
# xsum -f .gitconfig
sha256:05a024e3204055272b58624880f81389eccfe4808ceba8770ca26efcea100f37  .gitconfig
```

```
# xsum .gitconfig
05a024e3204055272b58624880f81389eccfe4808ceba8770ca26efcea100f37  .gitconfig
```

### Attribute Mask

xsum v1 MUST support two attribute mask formats:
1. Human-readable with variable length
2. Opaque with fixed length

The human-readable attribute mask MUST include an attribute mode mask and MAY include an attribute options mask.
- The attribute mode mask MUST contain four octal digits, each between 0 and 7.
- If present, the attribute options mask MUST consist of a single `+` followed by at least one option.
- Example: `7755+ugis`

The opaque attribute mask MUST include both an attribute mode mask and an attribute options mask.
- The attribute mode mask MUST contain three case-insensitive hexadecimal digits, each between 0 and f.
- The attribute options mask MUST contain four case-insensitive hexadecimal digits, each between 0 and f.
- Future versions of xsum v1 MAY allow for attribute options masks longer than four digits to encode additional options.
- Example: `fed4b00`

If an attribute mask is not present, xsum v1 MUST reject directories, follow symlinks, and read from special files.

#### Attribute Mode Mask

The human-readable attribute mode mask SHALL encode UNIX permissions specified by a four digit octal [umask](https://en.wikipedia.org/wiki/Umask). 
Future versions of xsum v1 MAY allow human-readable attribute mode masks without leading zeros.

The opaque attribute mode mask SHALL encode the human-readable attribute mode mask as a case-insensitive hexadecimal number in big endian format.

#### Attribute Options Mask

For a given checksum output, the attribute options mask MAY include any of the follow options:

0. `u` = Include UID (user ID)
1. `g` = Include GID (group ID)
2. `x` = Include xattr (extended file system attributes)
3. `s` = Include file content equivalents for special files (e.g., device IDs for character devices)
4. `t` = include mtime (file modification time)
5. `c` = Include ctime (file creation time)
6. `i` = Apply other attributes to the name file/directory itself
7. `n` = Exclude file names when summing directories (files are sorted by data checksum)
8. `e` = Exclude file contents
9. `l` = Follow symlinks (without `l`, extended checksums only validate path)

Notes:
- Without `i`, other attribute options MUST only apply to files/directories inside of directories.
- Future versions of xsum v1 MAY introduce more flags, but they SHALL NOT remove existing flags.

The human-readable attribute options mask MUST consist of a single `+` followed by any order of at least one option.

The opaque attribute options mask SHALL encode the human-readable attribute options mask as a case-insensitive hexadecimal number in little endian format.
The number MUST be the sum of all options included in the mask, where the value of each option is two to the power of the ordinal number in the list above.

## Tree Format

The xsum v1 tree format makes use of [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree) to calculate checksums of metadata-inclusive files and directories.

The xsum v1 tree format MUST ensure that two files with different contents or attributes cannot result in the same input to the chosen hashing algorithm.

As such, for a given checksum generated for a file,
- All checksums are calculated using the same algorithm.
- All checksums are fixed-length.
- Only checksums are concatenated (never raw data).

Where:
- `sum(x)` is a fixed-length checksum produced by the chosen hashing algorithm applied to named value `x`.
- `filename` is the name of the file (basename, without preceding path elements).
- `contents` is the contents of the file or directory, as defined below.
- `sysattr` contains standard file system attributes, as defined below.
- `xattr` contains extended file system attributes, as defined below.

Directory `contents` is encoded as a list of files, each encoded to `4*len(sum(x))` bytes as such:
```
[sum(filename)][sum(contents)][sum(sysattr)][sum(xattr)]
```
File encoding are sorted lexicographically and appended to each other with no delimiter. 

File `contents` (for files with `+i`) is encoded as such:
```
[sum(contents)][sum(sysattr)][sum(xattr)]
```

`sysattr` is encoded as 52 bytes as such: // TODO: should we reserve more than 52 bytes?
```
[mode{4}][uid{4}][gid{4}][device-id{8}][mtime{16}][ctime{16}]
```
Attributes not reflected in the attribute mask are set to zero.

`mode{4}` is encoded as the sum of the file mode type bits, file mode permission bits, and file mode special bits (sticky, setuid, setgid).
Bit ordering is as defined by Go's [`fs.FileMode`](https://pkg.go.dev/io/fs#FileMode).
The file mode type bits are not maskable.

`xattr` is encoded as a list of lexicographically sorted keys, each followed by `:`, a vowel, and a newline:
```
[key]:[value]\n
```


### Unintentional Exclusions

Any unintentional exclusions necessary to achieve reproducible checksums SHALL be considered to be as implemented in `xsum` CLI v1. 

