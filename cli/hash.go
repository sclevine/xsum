package cli

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
	"os/exec"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	"github.com/sclevine/xsum"
)

// note: algorithm names may not contain :
func ParseHash(alg string) (xsum.Hash, error) {
	// order:
	// - least info to most info
	// - shorter abbreviation before longer
	// - no dash before dash

	switch toSingle(alg, "-", "_", ".", "/") {

	// Cryptographic hashes

	case "md4":
		return xsum.NewHashFunc(xsum.HashMD4, md4.New), nil
	case "md5":
		return xsum.NewHashFunc(xsum.HashMD5, md5.New), nil

	case "sha1":
		return xsum.NewHashFunc(xsum.HashSHA1, sha1.New), nil
	case "sha256", "sha2256", "sha2-256":
		return xsum.NewHashFunc(xsum.HashSHA256, sha256.New), nil
	case "sha224", "sha2224", "sha2-224":
		return xsum.NewHashFunc(xsum.HashSHA224, sha256.New224), nil
	case "sha512", "sha2512", "sha2-512":
		return xsum.NewHashFunc(xsum.HashSHA512, sha512.New), nil
	case "sha384", "sha2384", "sha2-384":
		return xsum.NewHashFunc(xsum.HashSHA384, sha512.New384), nil
	case "sha512224", "sha512-224", "sha2512224", "sha2-512224", "sha2-512-224":
		return xsum.NewHashFunc(xsum.HashSHA512_224, sha512.New512_224), nil
	case "sha512256", "sha512-256", "sha2512256", "sha2-512256", "sha2-512-256":
		return xsum.NewHashFunc(xsum.HashSHA512_256, sha512.New512_256), nil
	case "sha3224", "sha3-224":
		return xsum.NewHashFunc(xsum.HashSHA3_224, sha3.New224), nil
	case "sha3256", "sha3-256":
		return xsum.NewHashFunc(xsum.HashSHA3_256, sha3.New256), nil
	case "sha3384", "sha3-384":
		return xsum.NewHashFunc(xsum.HashSHA3_384, sha3.New384), nil
	case "sha3512", "sha3-512":
		return xsum.NewHashFunc(xsum.HashSHA3_512, sha3.New512), nil

	case "b2s256", "b2s-256", "blake2s256", "blake2s-256":
		return xsum.NewHashFunc(xsum.HashBlake2s256, mustHash(blake2s.New256)), nil
	case "b2b256", "b2b-256", "blake2b256", "blake2b-256":
		return xsum.NewHashFunc(xsum.HashBlake2b256, mustHash(blake2b.New256)), nil
	case "b2b384", "b2b-384", "blake2b384", "blake2b-384":
		return xsum.NewHashFunc(xsum.HashBlake2b384, mustHash(blake2b.New384)), nil
	case "b2b512", "b2b-512", "blake2b512", "blake2b-512":
		return xsum.NewHashFunc(xsum.HashBlake2b512, mustHash(blake2b.New512)), nil

	case "rmd160", "rmd-160", "ripemd160", "ripemd-160":
		return xsum.NewHashFunc(xsum.HashRMD160, ripemd160.New), nil

	// Non-cryptographic hashes

	case "crc32", "crc32ieee", "crc32-ieee":
		return xsum.NewHashFunc(xsum.HashCRC32, hashTab32(crc32.New, crc32.IEEETable)), nil
	case "crc32c", "crc32-c", "crc32castagnoli", "crc32-castagnoli":
		return xsum.NewHashFunc(xsum.HashCRC32c, hashTab32(crc32.New, crc32.MakeTable(crc32.Castagnoli))), nil
	case "crc32k", "crc32-k", "crc32koopman", "crc32-koopman":
		return xsum.NewHashFunc(xsum.HashCRC32k, hashTab32(crc32.New, crc32.MakeTable(crc32.Koopman))), nil
	case "crc64iso", "crc64-iso":
		return xsum.NewHashFunc(xsum.HashCRC64ISO, hashTab64(crc64.New, crc64.MakeTable(crc64.ISO))), nil
	case "crc64ecma", "crc64-ecma":
		return xsum.NewHashFunc(xsum.HashCRC64ECMA, hashTab64(crc64.New, crc64.MakeTable(crc64.ECMA))), nil

	case "adler32":
		return xsum.NewHashFunc(xsum.HashAdler32, hash32(adler32.New)), nil

	case "fnv32":
		return xsum.NewHashFunc(xsum.HashFNV32, hash32(fnv.New32)), nil
	case "fnv32a":
		return xsum.NewHashFunc(xsum.HashFNV32a, hash32(fnv.New32a)), nil
	case "fnv64":
		return xsum.NewHashFunc(xsum.HashFNV64, hash64(fnv.New64)), nil
	case "fnv64a":
		return xsum.NewHashFunc(xsum.HashFNV64a, hash64(fnv.New64a)), nil
	case "fnv128":
		return xsum.NewHashFunc(xsum.HashFNV128, fnv.New128), nil
	case "fnv128a":
		return xsum.NewHashFunc(xsum.HashFNV128a, fnv.New128a), nil

	default:
		// xsum plugin
		p, err := exec.LookPath("xsum-" + alg)
		if err != nil {
			return nil, fmt.Errorf("unknown algorithm `%s'", alg)
		}
		return xsum.NewHashPlugin(alg, p), nil
	}
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
