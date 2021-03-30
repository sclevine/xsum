package sum

import (
	"bytes"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
)

type Hash interface {
	String() string
	Metadata(b []byte) ([]byte, error)
	Data(r io.Reader) ([]byte, error)
	File(path string) ([]byte, error)
	Tree(bs [][]byte) ([]byte, error)
}

func NewHashAlg(name string, fn func() hash.Hash) Hash {
	return &hashAlg{
		name: name,
		fn:   fn,
	}
}

func NewHashPlugin(name, path string) Hash {
	return &hashPlugin{
		name: name,
		path: path,
	}
}

type hashAlg struct {
	name string
	fn   func() hash.Hash
}

func (h *hashAlg) String() string {
	return h.name
}

func (h *hashAlg) Metadata(b []byte) ([]byte, error) {
	hf := h.fn()
	if _, err := hf.Write(b); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *hashAlg) Data(r io.Reader) ([]byte, error) {
	hf := h.fn()
	if _, err := io.Copy(hf, r); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *hashAlg) File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hf := h.fn()
	if _, err := io.Copy(hf, f); err != nil {
		return nil, err
	}
	return hf.Sum(nil), nil
}

func (h *hashAlg) Tree(bs [][]byte) ([]byte, error) {
	hf := h.fn()
	for _, b := range bs {
		if _, err := hf.Write(b); err != nil {
			return nil, err
		}
	}
	return hf.Sum(nil), nil
}

type hashPlugin struct {
	name, path string
}

func (h *hashPlugin) String() string {
	return h.name
}

func (h *hashPlugin) Metadata(b []byte) ([]byte, error) {
	return h.readCmd(bytes.NewReader(b), "metadata")
}

func (h *hashPlugin) Data(r io.Reader) ([]byte, error) {
	return h.readCmd(r, "data")
}

func (h *hashPlugin) File(path string) ([]byte, error) {
	return h.argCmd(path, "data")
}

func (h *hashPlugin) Tree(bs [][]byte) ([]byte, error) {
	var rs []io.Reader
	for _, b := range bs {
		rs = append(rs, bytes.NewReader(b))
	}
	return h.readCmd(io.MultiReader(rs...), "tree")
}

func (h *hashPlugin) readCmd(r io.Reader, ptype string) ([]byte, error) {
	cmd := exec.Command(h.path)
	cmd.Env = append(cmd.Env, "XSUM_PLUGIN_TYPE="+ptype)
	cmd.Stdin = r
	sum, err := cmd.Output()
	if eErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("plugin error: %s", string(eErr.Stderr))
	}
	return sum, err
}

func (h *hashPlugin) argCmd(path, ptype string) ([]byte, error) {
	cmd := exec.Command(h.path, path)
	cmd.Env = append(cmd.Env, "XSUM_PLUGIN_TYPE="+ptype)
	sum, err := cmd.Output()
	if eErr, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("plugin error: %s", string(eErr.Stderr))
	}
	return sum, err
}