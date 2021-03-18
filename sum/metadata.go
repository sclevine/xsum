package sum

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Attr uint16

const (
	AttrUID Attr = 1 << iota
	AttrGID
	AttrX
	AttrSpecial
	AttrMtime
	AttrCtime
	AttrPortable
	AttrInclude
	AttrMetadata

	AttrEmpty Attr = 0
)

var attrRep = []struct {
	attr Attr
	rep  byte
}{
	{AttrUID, 'u'},
	{AttrGID, 'g'},
	{AttrX, 'x'},
	{AttrSpecial, 's'},
	{AttrMtime, 't'},
	{AttrCtime, 'c'},
	{AttrPortable, 'p'},
	{AttrInclude, 'i'},
	{AttrMetadata, 'm'},
}

func NewAttr(s string) Attr {
	var attr Attr
	for _, c := range []byte(s) {
		for _, p := range attrRep {
			if p.rep == c {
				attr |= p.attr
			}
		}
	}
	return attr
}

func (a Attr) String() string {
	var out strings.Builder
	for _, p := range attrRep {
		if a&p.attr != 0 {
			out.Write([]byte{p.rep})
		}
	}
	return out.String()
}

type Mask struct {
	Mode uint16
	Attr Attr
}

func NewMaskString(s string) Mask {
	parts := strings.SplitN(s, "+", 2)
	mode := parts[0]
	var attrs string
	if len(parts) > 1 {
		attrs = parts[1]
	}

	mode64, err := strconv.ParseUint(mode, 8, 12)
	if err != nil {
		mode64 = 0
	}
	return Mask{
		Mode: uint16(mode64),
		Attr: NewAttr(attrs),
	}
}

func NewMask(mode os.FileMode, attr Attr) Mask {
	return Mask{
		Mode: uint16(mode),
		Attr: attr,
	}
}

func (m Mask) String() string {
	mode := fmt.Sprintf("%04o", m.Mode)[:4]
	attrs := m.Attr.String()
	if attrs == "" {
		return mode
	}
	return fmt.Sprintf("%s+%s", mode, attrs)
}
