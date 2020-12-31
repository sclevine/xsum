// +build linux darwin

package sum

import (
	"bytes"
	"encoding/hex"
	"sort"

	"github.com/davecheney/xattr"
)

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
		out.Write([]byte(hex.EncodeToString([]byte(attr))))
		out.Write([]byte{':'})
		out.Write([]byte(hex.EncodeToString(val)))
		out.Write([]byte{'\n'})
	}
	return out.Bytes(), nil
}
