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
	AttrInclude
	AttrNoName
	AttrNoData
	AttrFollow

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
	{AttrInclude, 'i'},
	{AttrNoName, 'n'},
	{AttrNoData, 'e'},
	{AttrFollow, 'l'},
}

func NewAttr(s string) (Attr, error) {
	var attr Attr
L:
	for _, c := range []byte(s) {
		for _, p := range attrRep {
			if p.rep == c {
				attr |= p.attr
				continue L
			}
		}
		return 0, fmt.Errorf("invalid attribute `%s'", string(c))
	}
	return attr, nil
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

func NewMaskString(s string) (Mask, error) {
	parts := strings.SplitN(s, "+", 2)
	mode := strings.TrimSpace(parts[0])
	var attrs string
	if len(parts) > 1 {
		attrs = parts[1]
	}
	mode16 := uint16(0)
	if mode != "" {
		mode64, err := strconv.ParseUint(mode, 8, 12)
		if err != nil {
			return Mask{}, fmt.Errorf("invalid mode `%s'", mode)
		}
		mode16 = uint16(mode64)
	}

	attr, err := NewAttr(attrs)
	return Mask{
		Mode: mode16,
		Attr: attr,
	}, err
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
