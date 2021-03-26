package sum

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
)

type File struct {
	Alg   *HashAlg
	Path  string
	Mask  Mask
	Stdin bool
}

func (f *File) Open() (io.ReadCloser, error) {
	if f.Stdin {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(f.Path)
}

func (f *File) Stat() (os.FileInfo, error) {
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
		return n.Alg.Name + ":" + n.SumHex() + ":" + n.Mask.String()
	}
	return n.Alg.Name + ":" + n.SumHex()
}

func (n *Node) Hex() string {
	if n.Mode&os.ModeDir != 0 || n.Mask.Attr&AttrInclusive != 0 {
		return n.Alg.Name + ":" + n.SumHex() + ":" + n.Mask.Hex()
	}
	return n.Alg.Name + ":" + n.SumHex()
}

func (n *Node) SumHex() string {
	return hex.EncodeToString(n.Sum)
}

func (n *Node) dirSig(filename string) ([]byte, error) {
	nameSum, err := n.Alg.Bytes([]byte(filename))
	if err != nil {
		return nil, err
	}
	permSum, err := n.hashSysattr()
	if err != nil {
		return nil, err
	}
	xattrSum, err := n.hashXattr()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*4))
	buf.Write(nameSum)
	buf.Write(n.Sum)
	buf.Write(permSum)
	buf.Write(xattrSum)
	return buf.Bytes(), nil
}

func (n *Node) fileSig() ([]byte, error) {
	permSum, err := n.hashSysattr()
	if err != nil {
		return nil, err
	}
	xattrSum, err := n.hashXattr()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*3))
	buf.Write(n.Sum)
	buf.Write(permSum)
	buf.Write(xattrSum)
	return buf.Bytes(), nil
}

func (n *Node) hashFileSig() ([]byte, error) {
	sig, err := n.fileSig()
	if err != nil {
		return nil, err
	}
	return n.Alg.Bytes(sig)
}

const (
	sModeSetuid = 04000
	sModeSetgid = 02000
	sModeSticky = 01000
)

func (n *Node) hashSysattr() ([]byte, error) {
	var out [52]byte
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
	mode := n.Mode & (os.ModeType | permMask | specialMask)
	binary.LittleEndian.PutUint32(out[:4], uint32(mode))

	if n.Sys == nil && n.Mask.Attr&(AttrUID|AttrGID|AttrSpecial|AttrMtime|AttrCtime) != 0 {
		return nil, ErrNoStat
	}

	if n.Mask.Attr&AttrUID != 0 {
		binary.LittleEndian.PutUint32(out[4:8], n.Sys.UID)
	}
	if n.Mask.Attr&AttrGID != 0 {
		binary.LittleEndian.PutUint32(out[8:12], n.Sys.GID)
	}
	if n.Mask.Attr&AttrSpecial != 0 && n.Mode&(os.ModeDevice|os.ModeCharDevice) != 0 {
		binary.LittleEndian.PutUint64(out[12:20], n.Sys.Device)
	}
	if n.Mask.Attr&AttrMtime != 0 {
		binary.LittleEndian.PutUint64(out[20:28], uint64(n.Sys.Mtime.Sec))
		binary.LittleEndian.PutUint64(out[28:36], uint64(n.Sys.Mtime.Nsec))
	}
	if n.Mask.Attr&AttrCtime != 0 {
		binary.LittleEndian.PutUint64(out[36:44], uint64(n.Sys.Ctime.Sec))
		binary.LittleEndian.PutUint64(out[44:52], uint64(n.Sys.Ctime.Nsec))
	}

	// out[52:68] - reserve for btime?

	return n.Alg.Bytes(out[:])
}

func (n *Node) hashXattr() ([]byte, error) {
	if n.Mask.Attr&AttrX != 0 {
		xattr, err := getXattr(n.Path)
		if err != nil {
			return nil, err
		}
		return n.Alg.Bytes(xattr)
	}
	return nil, nil
}
