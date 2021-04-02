package xsum_test

import (
	"testing"

	"github.com/sclevine/xsum"
)

func TestNewMaskString(t *testing.T) {
	all := xsum.AttrFollow<<1 - 1
	tests := []struct {
		in   string
		want xsum.Mask
	}{
		{"0777+ugxstcinel", xsum.NewMask(0777, all)},
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
	all := xsum.AttrFollow<<1 - 1
	tests := []struct {
		in   xsum.Mask
		want string
	}{
		{xsum.NewMask(0777, all), "0777+ugxstcinel"},
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
	all := xsum.AttrFollow<<1 - 1
	tests := []struct {
		in   string
		want xsum.Mask
	}{
		{"1FFFF03", xsum.NewMask(0777, all)},
		{"8d10102", xsum.NewMask(04321, xsum.AttrUID|xsum.AttrFollow)},
		{"000", xsum.NewMask(0, 0)},
		{"001", xsum.NewMask(01, 0)},
		{"00001", xsum.NewMask(0, xsum.AttrUID)},
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
	all := xsum.AttrFollow<<1 - 1
	tests := []struct {
		in   xsum.Mask
		want string
	}{
		{xsum.NewMask(0777, all), "1ffff03"},
		{xsum.NewMask(04321, xsum.AttrUID|xsum.AttrFollow), "8d10102"},
		{xsum.NewMask(0, 0), "0000000"},
		{xsum.NewMask(01, 0), "0010000"},
		{xsum.NewMask(0, xsum.AttrUID), "0000100"},
	}
	for _, tt := range tests {
		if out := tt.in.Hex(); out != tt.want {
			t.Errorf("xsum.Mask(%s).Hex() = %s, expected %s", tt.in, out, tt.want)
		}
	}
}
