package sum

import (
	"os"
	"syscall"
)

// TODO: make time cross-platform
func getSysProps(fi os.FileInfo) *SysProps {
	var out SysProps
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		out.UID = stat.Uid
		out.GID = stat.Gid
		out.Ctime = stat.Ctimespec
		out.Mtime = stat.Mtimespec
		out.Device = stat.Rdev
	}

	switch t := fi.Sys().(type) {
	case *syscall.Stat_t:
		out.UID = t.Uid
		out.GID = t.Gid
		out.Ctime = t.Ctimespec
		out.Mtime = t.Mtimespec
		out.Device = t.Rdev
	case *syscall.Win32FileAttributeData:
		out.Ctime = t.LastZZZTime.Nanoseconds()
		out.Mtime = t.LastYYYTime.Nanoseconds()

	}

	return &out
}
