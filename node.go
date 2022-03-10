package xsum

import (
	"encoding/hex"
	"io"
	"os"

	"github.com/sclevine/xsum/encoding"
)

type File struct {
	Hash  Hash
	Path  string
	Mask  Mask
	Stdin bool
}

func (f *File) sum() ([]byte, error) {
	if f.Stdin {
		return f.Hash.Data(io.NopCloser(os.Stdin))
	}
	return f.Hash.File(f.Path)
}

func (f *File) stat(subdir bool) (os.FileInfo, error) {
	if f.Stdin {
		return os.Stdin.Stat()
	}
	if !f.follow(subdir) {
		return os.Lstat(f.Path)
	}
	return os.Stat(f.Path)
}

func (f *File) xattr(subdir bool) (*Xattr, error) {
	hashes, err := getXattr(f.Path, f.Hash, f.follow(subdir))
	if err != nil {
		return nil, err
	}
	return &Xattr{
		HashType: hashToEncoding(f.Hash.String()),
		Hashes:   hashes,
	}, nil
}

func (f *File) follow(subdir bool) bool {
	inclusive := f.Mask.Attr&AttrInclusive != 0
	return f.Mask.Attr&AttrFollow != 0 || (!inclusive && !subdir)
}

type Node struct {
	File
	Sum   []byte
	Mode  os.FileMode
	Sys   *Sys
	Xattr *Xattr
	Err   error
}

type Sys struct {
	UID, GID     *uint32
	Mtime, Ctime *encoding.Timespec
	Rdev         *uint64
}

type Xattr struct {
	HashType encoding.HashType
	Hashes   []encoding.NamedHash
}

func (n *Node) String() string {
	if n.Mode&os.ModeDir != 0 || n.Mask.Attr&AttrInclusive != 0 {
		return n.Hash.String() + ":" + n.SumString() + ":" + n.Mask.String()
	}
	return n.Hash.String() + ":" + n.SumString()
}

func (n *Node) Hex() string {
	if n.Mode&os.ModeDir != 0 || n.Mask.Attr&AttrInclusive != 0 {
		return n.Hash.String() + ":" + n.SumString() + ":" + n.Mask.Hex()
	}
	return n.Hash.String() + ":" + n.SumString()
}

func (n *Node) SumString() string {
	return hex.EncodeToString(n.Sum)
}

const (
	sModeSetuid = 04000
	sModeSetgid = 02000
	sModeSticky = 01000
)

func hashFileAttr(n *Node) ([]byte, error) {
	if n.Sys == nil && n.Mask.Attr&(AttrUID|AttrGID|AttrSpecial|AttrMtime|AttrCtime) != 0 {
		return nil, ErrNoStat
	}
	if n.Xattr == nil && n.Mask.Attr&AttrX != 0 {
		return nil, ErrNoXattr
	}

	var specialMask os.FileMode
	if n.Mask.Mode&sModeSetuid != 0 {
		specialMask |= os.ModeSetuid
	}
	if n.Mask.Mode&sModeSetgid != 0 {
		specialMask |= os.ModeSetgid
	}
	if n.Mask.Mode&sModeSticky != 0 {
		specialMask |= os.ModeSticky
	}
	permMask := os.FileMode(n.Mask.Mode) & os.ModePerm
	modeMask := os.ModeType | permMask | specialMask

	sys := &encoding.Sys{}
	if n.Mask.Attr&AttrUID != 0 {
		sys.UID = n.Sys.UID
	}
	if n.Mask.Attr&AttrGID != 0 {
		sys.GID = n.Sys.GID
	}
	if n.Mask.Attr&AttrMtime != 0 {
		sys.Mtime = n.Sys.Mtime
	}
	if n.Mask.Attr&AttrCtime != 0 {
		sys.Ctime = n.Sys.Ctime
	}
	if n.Mask.Attr&AttrSpecial != 0 {
		sys.Rdev = n.Sys.Rdev
	}
	if n.Mask.Attr&AttrX != 0 {
		sys.XattrHashType = n.Xattr.HashType
		sys.XattrHashes = n.Xattr.Hashes
	}

	hashType := encoding.HashNone
	if len(n.Sum) != 0 { // check no-data attr or not?
		hashType = hashToEncoding(n.Hash.String())
	}

	der, err := encoding.FileASN1DER(hashType, n.Sum, n.Mode, modeMask, sys)
	if err != nil {
		return nil, err
	}
	return n.Hash.Metadata(der)
}
