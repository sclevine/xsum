package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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
)

type HashFunc func() hash.Hash

func ParseHash(h string) HashFunc {
	h = toSingle(h, "-", "_", ".", "/")

	// order:
	// - least info to most info
	// - shorter abbreviation before longer
	// - no dash before dash

	switch h {

	// Cryptographic hashes

	case "m4", "md4":
		return md4.New
	case "m5", "md5":
		return md5.New

	case "s1", "sha1":
		return sha1.New
	case "s2", "sha2", "s256", "sha256", "s2256", "s2-256", "sha2256", "sha2-256":
		return sha256.New
	case "s224", "sha224", "s2224", "s2-224", "sha2224", "sha2-224":
		return sha256.New224
	case "s512", "sha512", "s2512", "s2-512", "sha2512", "sha2-512":
		return sha512.New
	case "s384", "sha384", "s2384", "s2-384", "sha2384", "sha2-384":
		return sha512.New384
	case "s512224", "s512-224", "sha512224", "sha512-224", "s2512224", "s2-512-224", "sha2512224", "sha2-512-224":
		return sha512.New512_224
	case "s512256", "s512-256", "sha512256", "sha512-256", "s2512256", "s2-512-256", "sha2512256", "sha2-512-256":
		return sha512.New512_256
	case "s3224", "s3-224", "sha3224", "sha3-224":
		return sha3.New224
	case "s3", "sha3", "s3256", "s3-256", "sha3256", "sha3-256":
		return sha3.New256
	case "s3384", "s3-384", "sha3384", "sha3-384":
		return sha3.New384
	case "s3512", "s3-512", "sha3512", "sha3-512":
		return sha3.New512

	case "b2s", "blake2s", "b2s256", "b2s-256", "blake2s256", "blake2s-256":
		return mustHash(blake2s.New256)
	case "b2b", "blake2b", "b2b256", "b2b-256", "blake2b256", "blake2b-256":
		return mustHash(blake2b.New256)
	case "b2b384", "b2b-384", "blake2b384", "blake2b-384":
		return mustHash(blake2b.New384)
	case "b2b512", "b2b-512", "blake2b512", "blake2b-512":
		return mustHash(blake2b.New512)

	case "r160", "ripemd160":
		return ripemd160.New

	// Non-cryptographic hashes

	case "c32", "crc32", "c32-ieee", "crc32-ieee":
		return hashTab32(crc32.New, crc32.IEEETable)
	case "c32-castagnoli", "crc32-castagnoli":
		return hashTab32(crc32.New, crc32.MakeTable(crc32.Castagnoli))
	case "c32-koopman", "crc32-koopman":
		return hashTab32(crc32.New, crc32.MakeTable(crc32.Koopman))
	case "c64", "crc64", "c64-iso", "crc64-iso":
		return hashTab64(crc64.New, crc64.MakeTable(crc64.ISO))
	case "c64-ecma", "crc64-ecma":
		return hashTab64(crc64.New, crc64.MakeTable(crc64.ECMA))

	case "a32", "adler32":
		return hash32(adler32.New)

	case "f32", "fnv32":
		return hash32(fnv.New32)
	case "f32a", "fnv32a":
		return hash32(fnv.New32a)
	case "f64", "fnv64":
		return hash64(fnv.New64)
	case "f64a", "fnv64a":
		return hash64(fnv.New64a)
	case "f128", "fnv128":
		return fnv.New128
	case "f128a", "fnv128a":
		return fnv.New128a
	}
	return nil
}

func mustHash(hkf func([]byte) (hash.Hash, error)) HashFunc {
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

func hash32(hf func() hash.Hash32) HashFunc {
	return func() hash.Hash {
		return hf()
	}
}

func hash64(hf func() hash.Hash64) HashFunc {
	return func() hash.Hash {
		return hf()
	}
}

func hashTab32(hf func(*crc32.Table) hash.Hash32, tab *crc32.Table) HashFunc {
	return func() hash.Hash {
		return hf(tab)
	}
}

func hashTab64(hf func(*crc64.Table) hash.Hash64, tab *crc64.Table) HashFunc {
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
