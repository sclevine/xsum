package xsum

import (
	"os"
	"syscall"

	"github.com/sclevine/xsum/encoding"
)

func getSys(fi os.FileInfo) (*Sys, error) {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat != nil {
		mtime := encoding.Timespec(stat.Mtimespec)
		ctime := encoding.Timespec(stat.Ctimespec)
		rdev := uint64(stat.Rdev)
		return &Sys{
			UID:   &stat.Uid,
			GID:   &stat.Gid,
			Mtime: &mtime,
			Ctime: &ctime,
			Rdev:  &rdev, // should we check mode for dev type?
		}, nil
	}
	return nil, ErrNoStat
}
