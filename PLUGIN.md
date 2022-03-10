# xsum Plugin Interface v0.1

## Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in [RFC 2119](http://tools.ietf.org/html/rfc2119).

The key words "unspecified", "undefined", and "implementation-defined" are to be interpreted as described in the [rationale for the C99 standard](http://www.open-std.org/jtc1/sc22/wg14/www/C99RationaleV5.10.pdf#page=18).

An implementation is not compliant if it fails to satisfy one or more of the MUST, MUST NOT, REQUIRED, SHALL, or SHALL NOT requirements for the protocols it implements.
An implementation is compliant if it satisfies all the MUST, MUST NOT, REQUIRED, SHALL, and SHALL NOT requirements for the protocols it implements.

## Plugin Interface

An xsum plugin is an executable file that extends the `xsum` CLI with an additional hash function.

### Discovery

In order to make itself available to xsum, a plugin file:
- MUST be named `xsum-[name]`, where `[name]` is the name of the hash function.
- MUST be executable.
- MUST be placed on `$PATH`.

Example: `/usr/local/bin/xsum-pcm` enables `xsum -a pcm`.

### Invocation

When a plugin hash function is selected, xsum MUST execute the plugin file once for each entity of data that requires a checksum.

An xsum plugin MUST accept input data by reading from a file provided as the sole argument to the plugin (i.e., `argv[1]`).
Example: `xsum-pcm /some/file`.

If no arguments are provided, an xsum plugin SHOULD accept input data by reading standard input (i.e., `/dev/stdin`).
Example: `xsum-pcm < /some/file`

If a plugin is unable to receive data via standard input, it MUST fail with a clear error message and non-zero exit code.

xsum MUST execute the plugin with the environment variable `XSUM_PLUGIN_TYPE` set to one of the following categories:
- `data`, for file contents
- `metadata`, for all other types of data (e.g., ASN.1 DER, xattr values, symlink paths)

An xsum plugin MAY use `XSUM_PLUGIN_TYPE` to augment its hash function based on the category of data.
