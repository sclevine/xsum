package sum

import (
	"bytes"
	"encoding/base64"
	"os"
	"sort"
	"syscall"

	"github.com/davecheney/xattr"
)

func readDirUnordered(dirname string) ([]string, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	return names, nil
}

type SysProps struct {
	UID, GID     uint32
	Mtime, Ctime syscall.Timespec
	Device       int32
}

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
	return &out
}

//func timespecToTime(ts syscall.Timespec) time.Time {
//	return time.Unix(int64(ts.Sec), int64(ts.Nsec))
//}

func getXattr(path string) ([]byte, error) {
	attrs, err := xattr.Listxattr(path)
	if err != nil {
		return nil, err
	}
	sort.Strings(attrs)
	out := &bytes.Buffer{}
	for _, attr := range attrs {
		val, err := xattr.Getxattr(path, attr)
		if err != nil {
			return nil, err
		}
		out.Write([]byte(base64.StdEncoding.EncodeToString([]byte(attr))))
		out.Write([]byte{':'})
		out.Write([]byte(base64.StdEncoding.EncodeToString(val)))
		out.Write([]byte{'\n'})
	}
	return out.Bytes(), nil
}
