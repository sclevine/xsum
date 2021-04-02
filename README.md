# xsum

xsum is a simple CLI for calculating checksums that supports 18 cryptographic and 12 non-cryptographic hashing algorithms.

It can be used in place of `shasum`, `md5sum`, or similar utilities.

However, xsum is different from existing tools because:
1. xsum allows you to take checksums of directory contents quickly using [Merkle Trees](). This is the same strategy used to verify Docker image layers.
2. xsum allows you to take checksums that include file attributes such as UID/GID, permissions, extended attributes, special file metadata, etc.

[performance comparison]

## Security Considerations

- xsum only uses hashing algorithms from Go's standard library and official golang.org/x/crypto packages.
- (note about hash appropriateness)
- (note about not using shasum CLI when annotated due to file standins for dir/sym/etc.)
