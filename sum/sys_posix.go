package sum

import (
	"bytes"
	"encoding/base64"
	"os"
	"sort"
	"syscall"

	"github.com/davecheney/xattr"
)

type SysProps struct {
	UID, GID     uint32
	Mtime, Ctime syscall.Timespec
	Device       uint64
}

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
