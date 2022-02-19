package xsum

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
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

func (f *File) stat() (os.FileInfo, error) {
	if f.Stdin {
		return os.Stdin.Stat()
	}
	return os.Lstat(f.Path)
}

type Node struct {
	File
	Sum  []byte
	Mode os.FileMode
	Sys  *SysProps
	Err  error
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

func (n *Node) dirSig(filename string) ([]byte, error) {
	nameSum, err := n.Hash.Metadata([]byte(filename))
	if err != nil {
		return nil, err
	}
	permSum, err := n.hashSysattr()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*3))
	buf.Write(nameSum)
	buf.Write(n.Sum)
	buf.Write(permSum)
	return buf.Bytes(), nil
}

func (n *Node) fileSig() ([]byte, error) {
	permSum, err := n.hashSysattr()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*2))
	buf.Write(n.Sum)
	buf.Write(permSum)
	return buf.Bytes(), nil
}

func (n *Node) hashFileSig() ([]byte, error) {
	sig, err := n.fileSig()
	if err != nil {
		return nil, err
	}
	return n.Hash.Tree([][]byte{sig})
}

const (
	sModeSetuid = 04000
	sModeSetgid = 02000
	sModeSticky = 01000

	maskLen    = 8
)

func (n *Node) hashSysattr() ([]byte, error) {
	if n.Sys == nil && n.Mask.Attr&(AttrUID|AttrGID|AttrSpecial|AttrMtime|AttrCtime) != 0 {
		return nil, ErrNoStat
	}

	// [length: 4][mask: 8][mode: 4]
	out := make([]byte, 16)

	// length
	binary.LittleEndian.PutUint32(out[:4], uint32(maskLen))

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
	fixedMask := n.Mask.Attr&(AttrX-1)
	varMask := n.Mask.Attr&AttrX
	mode := n.Mode & modeMask

	// mask
	binary.LittleEndian.PutUint32(out[4:8], uint32(modeMask))
	binary.LittleEndian.PutUint16(out[8:10], uint16(fixedMask))
	binary.LittleEndian.PutUint16(out[10:12], uint16(varMask>>7))

	// mode
	binary.LittleEndian.PutUint32(out[12:16], uint32(mode))


	if fixedMask&AttrUID != 0 {
		uid := make([]byte, 4)
		binary.LittleEndian.PutUint32(uid, n.Sys.UID)
		out = append(out, uid...)
	}

	if fixedMask&AttrGID != 0 {
		gid := make([]byte, 4)
		binary.LittleEndian.PutUint32(gid, n.Sys.GID)
		out = append(out, gid...)
	}

	if fixedMask&AttrSpecial != 0 {
		// technically not necessary to append 0s, since mode is included in checksum
		dev := make([]byte, 8)
		if n.Mode&(os.ModeDevice|os.ModeCharDevice) != 0 {
			binary.LittleEndian.PutUint64(dev, n.Sys.Device)
		}
		out = append(out, dev...)
	}

	// atime eventually

	if fixedMask&AttrMtime != 0 {
		mtimeSec := make([]byte, 8)
		binary.LittleEndian.PutUint64(mtimeSec, uint64(n.Sys.Mtime.Sec))
		out = append(out, mtimeSec...)

		mtimeNsec := make([]byte, 8)
		binary.LittleEndian.PutUint64(mtimeNsec, uint64(n.Sys.Mtime.Nsec))
		out = append(out, mtimeNsec...)
	}

	if fixedMask&AttrCtime != 0 {
		ctimeSec := make([]byte, 8)
		binary.LittleEndian.PutUint64(ctimeSec, uint64(n.Sys.Ctime.Sec))
		out = append(out, ctimeSec...)

		ctimeNsec := make([]byte, 8)
		binary.LittleEndian.PutUint64(ctimeNsec, uint64(n.Sys.Ctime.Nsec))
		out = append(out, ctimeNsec...)
	}

	// btime eventually

	if varMask&AttrX != 0 {
		blocks, err := getXattr(n.Path, n.Hash)
		if err != nil {
			return nil, err
		}
		sum, err := n.Hash.Tree(blocks)
		if err != nil {
			return nil, err
		}
		sumLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(sumLen, uint32(len(sum)))
		out = append(out, sumLen...)
		out = append(out, sum...)
	}

	return n.Hash.Metadata(out)
}
