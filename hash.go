package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/sclevine/xsum/sum"
)

// note: algorithm names may not contain :
func parseHash(h string) (*sum.HashAlg, error) {
	h = toSingle(h, "-", "_", ".", "/")

	// order:
	// - least info to most info
	// - shorter abbreviation before longer
	// - no dash before dash

	var (
		name string
		fn   func() hash.Hash
	)
	switch h {

	// Cryptographic hashes

	case "md4":
		name, fn = "md4", md4.New
	case "md5":
		name, fn = "md5", md5.New

	case "sha1":
		name, fn = "sha1", sha1.New
	case "sha256", "sha2256", "sha2-256":
		name, fn = "sha256", sha256.New
	case "sha224", "sha2224", "sha2-224":
		name, fn = "sha224", sha256.New224
	case "sha512", "sha2512", "sha2-512":
		name, fn = "sha512", sha512.New
	case "sha384", "sha2384", "sha2-384":
		name, fn = "sha384", sha512.New384
	case "sha512224", "sha512-224", "sha2512224", "sha2-512224", "sha2-512-224":
		name, fn = "sha512-224", sha512.New512_224
	case "sha512256", "sha512-256", "sha2512256", "sha2-512256", "sha2-512-256":
		name, fn = "sha512-256", sha512.New512_256
	case "sha3224", "sha3-224":
		name, fn = "sha3-224", sha3.New224
	case "sha3256", "sha3-256":
		name, fn = "sha3-256", sha3.New256
	case "sha3384", "sha3-384":
		name, fn = "sha3-384", sha3.New384
	case "sha3512", "sha3-512":
		name, fn = "sha3-512", sha3.New512

	case "b2s256", "b2s-256", "blake2s256", "blake2s-256":
		name, fn = "blake2s256", mustHash(blake2s.New256)
	case "b2b256", "b2b-256", "blake2b256", "blake2b-256":
		name, fn = "blake2b256", mustHash(blake2b.New256)
	case "b2b384", "b2b-384", "blake2b384", "blake2b-384":
		name, fn = "blake2b384", mustHash(blake2b.New384)
	case "b2b512", "b2b-512", "blake2b512", "blake2b-512":
		name, fn = "blake2b384", mustHash(blake2b.New512)

	case "rmd160", "rmd-160", "ripemd160", "ripemd-160":
		name, fn = "rmd160", ripemd160.New

	// Non-cryptographic hashes

	case "crc32", "crc32ieee", "crc32-ieee":
		name, fn = "crc32", hashTab32(crc32.New, crc32.IEEETable)
	case "crc32c", "crc32-c", "crc32castagnoli", "crc32-castagnoli":
		name, fn = "crc32c", hashTab32(crc32.New, crc32.MakeTable(crc32.Castagnoli))
	case "crc32k", "crc32-k", "crc32koopman", "crc32-koopman":
		name, fn = "crc32k", hashTab32(crc32.New, crc32.MakeTable(crc32.Koopman))
	case "crc64iso", "crc64-iso":
		name, fn = "crc64iso", hashTab64(crc64.New, crc64.MakeTable(crc64.ISO))
	case "crc64ecma", "crc64-ecma":
		name, fn = "crc64ecma", hashTab64(crc64.New, crc64.MakeTable(crc64.ECMA))

	case "adler32":
		name, fn = "adler32", hash32(adler32.New)

	case "fnv32":
		name, fn = "fnv32", hash32(fnv.New32)
	case "fnv32a":
		name, fn = "fnv32a", hash32(fnv.New32a)
	case "fnv64":
		name, fn = "fnv64", hash64(fnv.New64)
	case "fnv64a":
		name, fn = "fnv64a", hash64(fnv.New64a)
	case "fnv128":
		name, fn = "fnv128", fnv.New128
	case "fnv128a":
		name, fn = "fnv128a", fnv.New128a
	default:
		return nil, fmt.Errorf("unknown algorithm `%s'", h)
	}
	return &sum.HashAlg{Name: name, New: fn}, nil
}

func mustHash(hkf func([]byte) (hash.Hash, error)) func() hash.Hash {
	if _, err := hkf(nil); err != nil {
		panic(err)
	}
	return func() hash.Hash {
		h, err := hkf(nil)
		if err != nil {
			panic(err)
		}
		return h
	}
}

func hash32(hf func() hash.Hash32) func() hash.Hash {
	return func() hash.Hash {
		return hf()
	}
}

func hash64(hf func() hash.Hash64) func() hash.Hash {
	return func() hash.Hash {
		return hf()
	}
}

func hashTab32(hf func(*crc32.Table) hash.Hash32, tab *crc32.Table) func() hash.Hash {
	return func() hash.Hash {
		return hf(tab)
	}
}

func hashTab64(hf func(*crc64.Table) hash.Hash64, tab *crc64.Table) func() hash.Hash {
	return func() hash.Hash {
		return hf(tab)
	}
}

func toSingle(s, to string, from ...string) string {
	for _, f := range from {
		s = strings.ReplaceAll(s, f, to)
	}
	return s
}
