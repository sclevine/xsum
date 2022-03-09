package xsum

import (
	"os"
	"syscall"

	"github.com/sclevine/xsum/encoding"
)

func (f *File) sys(fi os.FileInfo) (*encoding.Sys, error) {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat != nil {
		mtime := encoding.Timespec(stat.Mtimespec)
		ctime := encoding.Timespec(stat.Ctimespec)
		rdev := uint64(stat.Rdev)
		// FIXME: skip if stdin
		hashes, err := getXattr(f.Path, f.Hash) // TODO: defer unless needed
		if err != nil {
			return nil, err
		}
		return &encoding.Sys{
			UID:           &stat.Uid,
			GID:           &stat.Gid,
			Mtime:         &mtime,
			Ctime:         &ctime,
			Rdev:          &rdev, // should we check mode for dev type?
			XattrHashes:   hashes,
			XattrHashType: hashToEncoding(f.Hash.String()),
		}, nil
	}
	return nil, ErrNoStat
}