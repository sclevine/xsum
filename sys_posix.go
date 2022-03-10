// +build linux darwin freebsd netbsd solaris

package xsum

import (
	"github.com/pkg/xattr"

	"github.com/sclevine/xsum/encoding"
)

func getXattr(path string, hash Hash, follow bool) ([]encoding.NamedHash, error) {
	xlist, xget := xattr.List, xattr.Get
	if !follow {
		xlist, xget = xattr.LList, xattr.LGet
	}
	attrs, err := xlist(path)
	if err != nil {
		return nil, err
	}
	var hashes []encoding.NamedHash
	for _, attr := range attrs {
		val, err := xget(path, attr)
		if err != nil {
			return nil, err
		}
		valSum, err := hash.Metadata(val)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, encoding.NamedHash{
			Hash: valSum,
			Name: []byte(attr),
		})
	}
	return hashes, nil
}

func validateMask(_ Mask) error {
	return nil
}
