package xsum_test

import (
	"testing"

	"github.com/sclevine/xsum"
)

const attrAll = (xsum.AttrFollow<<1 - 1) &^ xsum.AttrAtime &^ xsum.AttrBtime

func TestNewMaskString(t *testing.T) {
	tests := []struct {
		in   string
		want xsum.Mask
	}{
		{"0777+ugstcxinel", xsum.NewMask(0777, attrAll)},
		{"4321+ul", xsum.NewMask(04321, xsum.AttrUID|xsum.AttrFollow)},
		{"", xsum.NewMask(0, 0)},
		{"+", xsum.NewMask(0, 0)},
		{"1", xsum.NewMask(01, 0)},
		{"1+", xsum.NewMask(01, 0)},
		{"+u", xsum.NewMask(0, xsum.AttrUID)},
	}
	for _, tt := range tests {
		out, err := xsum.NewMaskString(tt.in)
		if err != nil {
			t.Errorf("xsum.NewMaskString(%s) = %v", tt.in, err)
			continue
		}
		if out != tt.want {
			t.Errorf("xsum.NewMaskString(%s) = %s, expected %s", tt.in, out, tt.want)
		}
	}
}

func TestMask_String(t *testing.T) {
	tests := []struct {
		in   xsum.Mask
		want string
	}{
		{xsum.NewMask(0777, attrAll), "0777+ugstcxinel"},
		{xsum.NewMask(04321, xsum.AttrUID|xsum.AttrFollow), "4321+ul"},
		{xsum.NewMask(0, 0), "0000"},
		{xsum.NewMask(01, 0), "0001"},
		{xsum.NewMask(0, xsum.AttrUID), "0000+u"},
	}
	for _, tt := range tests {
		if out := tt.in.String(); out != tt.want {
			t.Errorf("xsum.Mask(%s).String() = %s, expected %s", tt.in, out, tt.want)
		}
	}
}

func TestNewMaskHex(t *testing.T) {
	tests := []struct {
		in   string
		want xsum.Mask
	}{
		{"A1FF0FDB", xsum.NewMask(0777, attrAll)},
		{"a8d10801", xsum.NewMask(04321, xsum.AttrUID|xsum.AttrFollow)},
		{"a000", xsum.NewMask(0, 0)},
		{"a001", xsum.NewMask(01, 0)},
		{"a00001", xsum.NewMask(0, xsum.AttrUID)},
	}
	for _, tt := range tests {
		out, err := xsum.NewMaskHex(tt.in)
		if err != nil {
			t.Errorf("xsum.NewMaskHex(%s) = %v", tt.in, err)
			continue
		}
		if out != tt.want {
			t.Errorf("xsum.NewMaskHex(%s) = %s, expected %s", tt.in, out, tt.want)
		}
	}
}

func TestMask_Hex(t *testing.T) {
	tests := []struct {
		in   xsum.Mask
		want string
	}{
		{xsum.NewMask(0777, attrAll), "a1ff0fdb"},
		{xsum.NewMask(04321, xsum.AttrUID|xsum.AttrFollow), "a8d10801"},
		{xsum.NewMask(0, 0), "a0000000"},
		{xsum.NewMask(01, 0), "a0010000"},
		{xsum.NewMask(0, xsum.AttrUID), "a0000001"},
	}
	for _, tt := range tests {
		if out := tt.in.Hex(); out != tt.want {
			t.Errorf("xsum.Mask(%s).Hex() = %s, expected %s", tt.in, out, tt.want)
		}
	}
}
