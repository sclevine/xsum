package xsum

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"

	"github.com/sclevine/xsum/encoding"
)


const (
	HashNone       = ""
	HashMD4        = "md4"
	HashMD5        = "md5"
	HashSHA1       = "sha1"
	HashSHA256     = "sha256"
	HashSHA224     = "sha224"
	HashSHA512     = "sha512"
	HashSHA384     = "sha384"
	HashSHA512_224 = "sha512-224"
	HashSHA512_256 = "sha512-256"
	HashSHA3_224   = "sha3-224"
	HashSHA3_256   = "sha3-256"
	HashSHA3_384   = "sha3-384"
	HashSHA3_512   = "sha3-512"
	HashBlake2s256 = "blake2s256"
	HashBlake2b256 = "blake2b256"
	HashBlake2b384 = "blake2b384"
	HashBlake2b512 = "blake2b512"
	HashRMD160     = "rmd160"
	HashCRC32      = "crc32"
	HashCRC32c     = "crc32c"
	HashCRC32k     = "crc32k"
	HashCRC64ISO   = "crc64iso"
	HashCRC64ECMA  = "crc64ecma"
	HashAdler32    = "adler32"
	HashFNV32      = "fnv32"
	HashFNV32a     = "fnv32a"
	HashFNV64      = "fnv64"
	HashFNV64a     = "fnv64a"
	HashFNV128     = "fnv128"
	HashFNV128a    = "fnv128a"
)


func hashToEncoding(h string) encoding.HashType {
	switch h {
	case HashMD4:
		return encoding.HashMD4
	case HashMD5:
		return encoding.HashMD5
	case HashSHA1:
		return encoding.HashSHA1
	case HashSHA256:
		return encoding.HashSHA256
	case HashSHA224:
		return encoding.HashSHA224
	case HashSHA512:
		return encoding.HashSHA512
	case HashSHA384:
		return encoding.HashSHA384
	case HashSHA512_224:
		return encoding.HashSHA512_224
	case HashSHA512_256:
		return encoding.HashSHA512_256
	case HashSHA3_224:
		return encoding.HashSHA3_224
	case HashSHA3_256:
		return encoding.HashSHA3_256
	case HashSHA3_384:
		return encoding.HashSHA3_384
	case HashSHA3_512:
		return encoding.HashSHA3_512
	case HashBlake2s256:
		return encoding.HashBlake2s256
	case HashBlake2b256:
		return encoding.HashBlake2b256
	case HashBlake2b384:
		return encoding.HashBlake2b384
	case HashBlake2b512:
		return encoding.HashBlake2b512
	case HashRMD160:
		return encoding.HashRMD160
	case HashCRC32:
		return encoding.HashCRC32
	case HashCRC32c:
		return encoding.HashCRC32c
	case HashCRC32k:
		return encoding.HashCRC32k
	case HashCRC64ISO:
		return encoding.HashCRC64ISO
	case HashCRC64ECMA:
		return encoding.HashCRC64ECMA
	case HashAdler32:
		return encoding.HashAdler32
	case HashFNV32:
		return encoding.HashFNV32
	case HashFNV32a:
		return encoding.HashFNV32a
	case HashFNV64:
		return encoding.HashFNV64
	case HashFNV64a:
		return encoding.HashFNV64a
	case HashFNV128:
		return encoding.HashFNV128
	case HashFNV128a:
		return encoding.HashFNV128a
	default:
		return encoding.HashNone
	}
}

type Hash interface {
	String() string
	Metadata(b []byte) ([]byte, error)
	Data(r io.Reader) ([]byte, error)
	File(path string) ([]byte, error)
}

func NewHashAlg(name string, fn func() hash.Hash) Hash {
	return &hashAlg{
		name: name,
		fn:   fn,
	}
}

func NewHashPlugin(name, path string) Hash {
	return &hashPlugin{
		name: name,
		path: path,
	}
}

type hashAlg struct {
	name string
	fn   func() hash.Hash
}

func (h *hashAlg) String() string {
	return h.name
}

func (h *hashAlg) Metadata(b []byte) ([]byte, error) {
	hf := h.fn()
	if _, err := hf.Write(b); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *hashAlg) Data(r io.Reader) ([]byte, error) {
	hf := h.fn()
	if _, err := io.Copy(hf, r); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *hashAlg) File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return h.Data(f)
}

type hashPlugin struct {
	name, path string
}

func (h *hashPlugin) String() string {
	return h.name
}

func (h *hashPlugin) Metadata(b []byte) ([]byte, error) {
	return h.readCmd(bytes.NewReader(b), "metadata")
}

func (h *hashPlugin) Data(r io.Reader) ([]byte, error) {
	return h.readCmd(r, "data")
}

func (h *hashPlugin) File(path string) ([]byte, error) {
	return h.argCmd(path, "data")
}

func (h *hashPlugin) readCmd(r io.Reader, ptype string) ([]byte, error) {
	cmd := exec.Command(h.path)
	cmd.Env = append(os.Environ(), "XSUM_PLUGIN_TYPE="+ptype)
	cmd.Stdin = r
	sum, err := cmd.Output()
	if eErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("plugin error:\n\t%s", string(eErr.Stderr))
	} else if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(sum))
}

func (h *hashPlugin) argCmd(path, ptype string) ([]byte, error) {
	cmd := exec.Command(h.path, path)
	cmd.Env = append(os.Environ(), "XSUM_PLUGIN_TYPE="+ptype)
	sum, err := cmd.Output()
	if eErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("plugin error:\n\t%s", string(eErr.Stderr))
	} else if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(sum))
}