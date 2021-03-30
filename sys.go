package xsum

import (
	"os"
	"syscall"
)

type SysProps struct {
	UID, GID     uint32
	Mtime, Ctime syscall.Timespec
	Device       uint64
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
