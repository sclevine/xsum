// +build linux darwin freebsd netbsd solaris

package xsum

import (
	"bytes"
	"sort"

	"github.com/pkg/xattr"
)

func getXattr(path string, hash Hash) ([]byte, error) {
	attrs, err := xattr.LList(path)
	if err != nil {
		return nil, err
	}
	var blocks [][]byte
	for _, attr := range attrs {
		val, err := xattr.LGet(path, attr)
		if err != nil {
			return nil, err
		}
		attrSum, err := hash.Metadata([]byte(attr))
		if err != nil {
			return nil, err
		}
		valSum, err := hash.Data(bytes.NewReader(val))
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, append(attrSum, valSum...))
	}
	sort.Slice(blocks, func(i, j int) bool {
		return bytes.Compare(blocks[i], blocks[j]) < 0
	})
	return hash.Tree(blocks)
}

func validateMask(_ Mask) error {
	return nil
}
