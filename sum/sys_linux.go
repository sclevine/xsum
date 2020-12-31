package sum

import (
	"os"
	"syscall"
)

func getSysProps(fi os.FileInfo) *SysProps {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat != nil {
		var out SysProps
		out.UID = stat.Uid
		out.GID = stat.Gid
		out.Ctime = stat.Ctim
		out.Mtime = stat.Mtim
		out.Device = stat.Rdev
		return &out
	}
	return nil
}
