package xsum

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	AttrInclusive
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
	{AttrInclusive, 'i'},
	{AttrNoName, 'n'},
	{AttrNoData, 'e'},
	{AttrFollow, 'l'},
}

func NewAttrString(s string) (Attr, error) {
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

func NewAttrHex(s string) (Attr, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("invalid hex attribute `%s'", s)
	}
	// ignore attrs beyond 2 bytes
	if len(b) > 2 {
		b = b[:2]
	}
	return Attr(binary.LittleEndian.Uint16(b)), nil
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

func (a Attr) Hex() string {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(a))
	return hex.EncodeToString(b)
}

type Mode uint16

func NewModeString(s string) (Mode, error) {
	if s == "" {
		return 0, nil
	}
	mode64, err := strconv.ParseUint(s, 8, 12)
	if err != nil {
		return 0, fmt.Errorf("invalid mode `%s'", s)
	}
	return Mode(mode64), nil
}

func NewModeHex(s string) (Mode, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 2 {
		return 0, fmt.Errorf("invalid hex mode `%s'", s)
	}
	return Mode(binary.BigEndian.Uint16(b)), nil
}

func (m Mode) String() string {
	return fmt.Sprintf("%04o", m)[:4]
}

func (m Mode) Hex() string {
	return fmt.Sprintf("%03x", m)[:3]
}

type Mask struct {
	Mode Mode
	Attr Attr
}

func NewMaskString(s string) (Mask, error) {
	parts := strings.SplitN(s, "+", 2)
	mode := strings.TrimSpace(parts[0])
	var attrs string
	if len(parts) > 1 {
		attrs = parts[1]
	}
	m, err := NewModeString(mode)
	if err != nil {
		return Mask{}, err
	}
	attr, err := NewAttrString(attrs)
	return Mask{
		Mode: m,
		Attr: attr,
	}, err
}

func NewMaskHex(s string) (Mask, error) {
	if len(s) < 3 {
		return Mask{}, errors.New("mask too short")
	}
	mode, err := NewModeHex(s[:3])
	if err != nil {
		return Mask{}, err
	}
	attr, err := NewAttrHex(s[3:])
	return Mask{
		Mode: mode,
		Attr: attr,
	}, err
}

func NewMask(mode os.FileMode, attr Attr) Mask {
	return Mask{
		Mode: Mode(mode),
		Attr: attr,
	}
}

func (m Mask) String() string {
	mode := m.Mode.String()
	attrs := m.Attr.String()
	if attrs == "" {
		return mode
	}
	return fmt.Sprintf("%s+%s", mode, attrs)
}

func (m Mask) Hex() string {
	return m.Mode.Hex() + m.Attr.Hex()
}
