// +build linux darwin freebsd netbsd solaris

package xsum

import (
	"bytes"
	"encoding/hex"
	"sort"

	"github.com/pkg/xattr"
)

func getXattr(path string) ([]byte, error) {
	attrs, err := xattr.LList(path)
	if err != nil {
		return nil, err
	}
	sort.Strings(attrs)
	out := &bytes.Buffer{}
	for _, attr := range attrs {
		val, err := xattr.LGet(path, attr)
		if err != nil {
			return nil, err
		}
		out.Write([]byte(hex.EncodeToString([]byte(attr))))
		out.Write([]byte{':'})
		out.Write([]byte(hex.EncodeToString(val)))
		out.Write([]byte{'\n'})
	}
	return out.Bytes(), nil
}

func validateMask(_ Mask) error {
	return nil
}
