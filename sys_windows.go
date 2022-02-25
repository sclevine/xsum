package xsum

import (
	"errors"
	"os"
	"syscall"

	"github.com/sclevine/xsum/encoding"
)


func (f *File) sys(fi os.FileInfo) (*encoding.Sys, error) {
	if stat, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok && stat != nil {
		return &encoding.Sys{
			Mtime: filetimeToTimespec(stat.LastWriteTime),
			Ctime: filetimeToTimespec(stat.CreationTime),
		}, nil
	}
	return nil, ErrNoStat
}

func filetimeToTimespec(ft syscall.Filetime) *encoding.Timespec {
	ts := encoding.Timespec(syscall.NsecToTimespec(ft.Nanoseconds()))
	return &ts
}

func validateMask(mask Mask) error {
	if mask.Mode&(sModeSetuid|sModeSetgid|sModeSticky|0111) != 0 {
		return errors.New("masks >0666 unsupported on Windows")
	}
	if mask.Attr&(AttrUID|AttrGID|AttrX|AttrSpecial) != 0 {
		return errors.New("masks with UID/GID/xattr/special unsupported on Windows")
	}
	return nil
}
