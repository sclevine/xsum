package xsum

import (
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

func getXattr(path string) ([]byte, error) {
	return nil, errors.New("xattr not available on Windows")
}