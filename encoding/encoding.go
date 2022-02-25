package encoding

import (
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
)

/*
--- ASN.1 Schema

XSum DEFINITIONS  ::=  BEGIN
    File  ::=  SEQUENCE  {
        hash        [0]  EXPLICIT Hash OPTIONAL,
        mode        [1]  EXPLICIT Mode OPTIONAL,
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
*/

type Sys struct {
	UID, GID      *uint32
	Mtime, Ctime  *Timespec
	Rdev          *uint64
	XattrHashes   []NamedHash
	XattrHashType HashType
}

type Timespec struct {
	Sec  int64
	Nsec int64
}

type NamedHash struct {
	Hash []byte
	Name []byte `asn1:"omitempty"`
}

// fileASN1 uses interface{} types to work around limitations of encoding/asn1:
// - encoding/asn1 wrongly assumes that optional without default should use zero-valued default
// - encoding/asn1 will not accept nil types and only respects omitempty for empty slices
type fileASN1 struct {
	Hash interface{} `asn1:"omitempty,explicit,tag:0"` // hashASN1 | emptyASN1
	Mode interface{} `asn1:"omitempty,explicit,tag:1"` // modeASN1 | emptyASN1

	// high values may be encoded as negative ASN.1 INTEGERS
	UID interface{} `asn1:"omitempty,explicit,tag:2"` // int64 | emptyASN1
	GID interface{} `asn1:"omitempty,explicit,tag:3"` // int64 | emptyASN1

	Atime interface{} `asn1:"omitempty,explicit,tag:4"` // timespecASN1 | emptyASN1
	Mtime interface{} `asn1:"omitempty,explicit,tag:5"` // timespecASN1 | emptyASN1
	Ctime interface{} `asn1:"omitempty,explicit,tag:6"` // timespecASN1 | emptyASN1
	Btime interface{} `asn1:"omitempty,explicit,tag:7"` // timespecASN1 | emptyASN1

	// high values may be encoded as negative ASN.1 INTEGERS
	Rdev interface{} `asn1:"omitempty,explicit,tag:8"` // *big.Int | emptyASN

	Xattr interface{} `asn1:"omitempty,explicit,tag:9"` // hashTreeASN1 | emptyASN1
}

type hashASN1 struct {
	HashType asn1.Enumerated
	Hash     []byte
}

type modeASN1 struct {
	Mask asn1.BitString
	Mode asn1.BitString
}

type hashTreeASN1 struct {
	HashType asn1.Enumerated
	Tree     []hashEntryASN1 `asn1:"set"`
}

type hashEntryASN1 NamedHash
type timespecASN1 Timespec

var emptyASN1 = []interface{}(nil)

type HashType asn1.Enumerated

const (
	HashNone HashType = iota

	// crypto
	HashMD4
	HashMD5
	HashSHA1
	HashSHA256
	HashSHA224
	HashSHA512
	HashSHA384
	HashSHA512_224
	HashSHA512_256
	HashSHA3_224
	HashSHA3_256
	HashSHA3_384
	HashSHA3_512
	HashBlake2s256
	HashBlake2b256
	HashBlake2b384
	HashBlake2b512
	HashRMD160

	// non-crypto
	HashCRC32
	HashCRC32c
	HashCRC32k
	HashCRC64ISO
	HashCRC64ECMA
	HashAdler32
	HashFNV32
	HashFNV32a
	HashFNV64
	HashFNV64a
	HashFNV128
	HashFNV128a
)

func FileASN1DER(hashType HashType, hash []byte, mode, mask os.FileMode, sys *Sys) ([]byte, error) {
	// filetype should never be masked:
	// - +s non-device file results in same hash as -s
	// - symbolic links result in same hash as regular files containing paths
	var maskBytes, modeBytes [4]byte
	binary.BigEndian.PutUint32(maskBytes[:], uint32(mask))
	binary.BigEndian.PutUint32(modeBytes[:], uint32(mode&mask))


	file := fileASN1{
		Hash: emptyASN1,
		Mode: modeASN1{
			Mask: asn1.BitString{Bytes: maskBytes[:], BitLength: 32},
			Mode: asn1.BitString{Bytes: modeBytes[:], BitLength: 32},
		},
		UID: emptyASN1,
		GID: emptyASN1,
		Atime: emptyASN1,
		Mtime: emptyASN1,
		Ctime: emptyASN1,
		Btime: emptyASN1,
		Rdev: emptyASN1,
		Xattr: emptyASN1,
	}

	if hashType != HashNone {
		file.Hash = hashASN1{
			HashType: asn1.Enumerated(hashType),
			Hash:     hash,
		}
	}

	// use int64 for uint32 to permit larger integer UID/GID in future
	if sys.UID != nil {
		file.UID = new(big.Int).SetInt64(int64(*sys.UID))
	}
	if sys.GID != nil {
		file.GID = new(big.Int).SetInt64(int64(*sys.GID))
	}

	// atime eventually

	if sys.Mtime != nil {
		file.Mtime = timespecASN1(*sys.Mtime)
	}
	if sys.Ctime != nil {
		file.Ctime = timespecASN1(*sys.Ctime)
	}

	// btime eventually

	if sys.Rdev != nil &&
		// safe because ModeType is never masked
		mode&(os.ModeDevice|os.ModeCharDevice) != 0 {
		// use BigInt for uint64 to permit larger device IDs in future
		file.Rdev = new(big.Int).SetUint64(*sys.Rdev)
	}

	if sys.XattrHashes != nil {
		// tree order guaranteed by DER-encoded ASN1 SET
		var tree []hashEntryASN1
		for _, h := range sys.XattrHashes {
			tree = append(tree, hashEntryASN1(h))
		}
		file.Xattr = hashTreeASN1{
			HashType: asn1.Enumerated(sys.XattrHashType),
			Tree:     tree,
		}
	}

	return asn1.Marshal(file)
}

func TreeASN1DER(hashType HashType, hashes []NamedHash) ([]byte, error) {
	var t hashTreeASN1
	t.HashType = asn1.Enumerated(hashType)
	// tree order guaranteed by DER-encoded ASN1 SET
	for _, h := range hashes {
		t.Tree = append(t.Tree, hashEntryASN1(h))
	}
	return asn1.Marshal(t)
}
