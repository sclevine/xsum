package sum

import (
	"bytes"
	"hash"
	"io"
	"sort"
)

type HashAlg struct {
	Name string
	New  func() hash.Hash
}

func (h *HashAlg) Bytes(b []byte) ([]byte, error) {
	hf := h.New()
	if _, err := hf.Write(b); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *HashAlg) Reader(r io.Reader) ([]byte, error) {
	hf := h.New()
	if _, err := io.Copy(hf, r); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *HashAlg) Zero() []byte {
	return h.New().Sum(nil)
}

func (h *HashAlg) Blocks(blocks [][]byte) ([]byte, error) {
	sort.Slice(blocks, func(i, j int) bool {
		return bytes.Compare(blocks[i], blocks[j]) < 0
	})
	hf := h.New()
	for _, block := range blocks {
		if _, err := hf.Write(block); err != nil {
			return nil, err
		}
	}
	return hf.Sum(nil), nil
}
