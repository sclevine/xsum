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
		out.Ctime = stat.Ctimespec
		out.Mtime = stat.Mtimespec
		out.Device = uint64(stat.Rdev)
		return &out
	}
	return nil
}