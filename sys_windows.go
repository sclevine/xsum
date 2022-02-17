package xsum

import (
	"errors"
	"os"
	"syscall"
)

func getSysProps(fi os.FileInfo) *SysProps {
	if stat, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok && stat != nil {
		var out SysProps
		out.Ctime = filetimeToTimespec(stat.CreationTime)
		out.Mtime = filetimeToTimespec(stat.LastWriteTime)
		return &out
	}
	return nil
}

func filetimeToTimespec(ft syscall.Filetime) syscall.Timespec {
	return syscall.NsecToTimespec(ft.Nanoseconds())
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

func getXattr(path string) ([]byte, error) {
	return nil, errors.New("xattr not available on Windows")
}
