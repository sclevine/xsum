// +build linux darwin freebsd netbsd solaris

package xsum

import (
	"github.com/pkg/xattr"

	"github.com/sclevine/xsum/encoding"
)

func getXattr(path string, hash Hash) ([]encoding.NamedHash, error) {
	attrs, err := xattr.LList(path)
	if err != nil {
		return nil, err
	}
	var hashes []encoding.NamedHash
	for _, attr := range attrs {
		val, err := xattr.LGet(path, attr)
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
