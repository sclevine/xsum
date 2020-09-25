package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/jessevdk/go-flags"
	"golang.org/x/sync/semaphore"
)

type Options struct {
	Algorithm string `short:"a" long:"algorithm" default:"sha256" description:"Select hashing algorithm"`
	Args      struct {
		Paths []string `required:"1"`
	} `positional-args:"yes"`
}

func main() {
	log.SetFlags(0)

	var opts Options
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassAfterNonOption|flags.PassDoubleDash)
	rest, err := parser.Parse()
	if err != nil {
		log.Fatalf("Invalid arguments: %s", err)
	}
	if len(rest) != 0 {
		log.Fatalf("Unparsable arguments: %s", strings.Join(rest, ", "))
	}
	hf := parseHash(opts.Algorithm)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", opts.Algorithm)
	}
	nodes, err := hf.Sum(opts.Args.Paths)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	for _, n := range nodes {
		fmt.Printf("%x  %s\n", n.sum, n.path)
	}
}

var Lock = semaphore.NewWeighted(int64(runtime.NumCPU()))

type Node struct {
	path string
	sum  []byte
	mode os.FileMode
}

type HashFunc func() hash.Hash

func (hf HashFunc) extend(n *Node) error {
	permSum, err := hf.hashBytes(permBytes(n))
	if err != nil {
		return err
	}
	xattrSum, err := hf.hashBytes(nil)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.sum)*4))
	buf.Write(n.sum)
	buf.Write(permSum)
	buf.Write(xattrSum)
	n.sum = buf.Bytes()
	return nil
}

func (hf HashFunc) Sum(paths []string) ([]*Node, error) {
	var wg sync.WaitGroup
	wg.Add(len(paths))
	errC := make(chan error)
	go func() {
		wg.Wait()
		close(errC) // safe, no more errors sent
	}()
	nodes := make([]*Node, len(paths))
	for i, path := range paths {
		i, path := i, path
		go func() {
			var err error
			nodes[i], err = hf.walk(path)
			if err != nil {
				errC <- err
			}
			wg.Done()
		}()
	}
	for err := range errC {
		return nil, err
	}
	return nodes, nil
}

func (hf HashFunc) walk(path string) (*Node, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("path `%s' does not exist", path)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat `%s': %w", path, err)
	}
	switch {
	case fi.IsDir():
		names, err := readDirUnordered(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read dir `%s': %w", path, err)
		}
		nodes, err := hf.Sum(withBase(path, names...))
		if err != nil {
			return nil, err
		}
		sum, err := hf.merkle(nodes)
		if err != nil {
			return nil, fmt.Errorf("failed to hash `%s': %w", path, err)
		}
		return &Node{path, sum, fi.Mode()}, nil

	case fi.Mode().IsRegular():
		// refine to prevent too many stats / merkel shas
		Lock.Acquire(context.Background(), 1)
		defer Lock.Release(1)

		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open `%s': %w", path, err)
		}
		defer f.Close()
		sum, err := hf.hashReader(f)
		if err != nil {
			return nil, fmt.Errorf("failed to hash `%s': %w", path, err)
		}
		return &Node{path, sum, fi.Mode()}, nil

	case fi.Mode()&os.ModeSymlink != 0:
		link, err := os.Readlink(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read link `%s': %w", path, err)
		}
		sum, err := hf.hashBytes([]byte(link))
		if err != nil {
			return nil, fmt.Errorf("failed to hash `%s': %w", path, err)
		}
		return &Node{path, sum, fi.Mode()}, nil
	}
	return &Node{path, nil, fi.Mode()}, nil
}

func withBase(base string, paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Join(base, p))
	}
	return out
}

func (hf HashFunc) hashBytes(b []byte) ([]byte, error) {
	h := hf()
	if _, err := h.Write(b); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (hf HashFunc) hashReader(r io.Reader) ([]byte, error) {
	h := hf()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (hf HashFunc) exclude(n *Node) bool {
	return !n.mode.IsRegular() && !n.mode.IsDir()
}

func permBytes(n *Node) []byte {
	var perm [52]byte
	binary.LittleEndian.PutUint32(perm[:4], uint32(n.mode&os.ModeType))
	return perm[:]
}

func (hf HashFunc) merkle(nodes []*Node) ([]byte, error) {
	blocks := make([][]byte, 0, len(nodes))
	for _, n := range nodes {
		if hf.exclude(n) {
			log.Printf("Warning: skipping special file `%s'", n.path)
			continue
		}
		nameSum, err := hf.hashBytes([]byte(filepath.Base(n.path)))
		if err != nil {
			return nil, err
		}
		permSum, err := hf.hashBytes(permBytes(n))
		if err != nil {
			return nil, err
		}
		xattrSum, err := hf.hashBytes(nil)
		if err != nil {
			return nil, err
		}

		buf := bytes.NewBuffer(make([]byte, 0, len(n.sum)*4))
		buf.Write(nameSum)
		buf.Write(n.sum)
		buf.Write(permSum)
		buf.Write(xattrSum)
		blocks = append(blocks, buf.Bytes())
	}
	sort.Slice(blocks, func(i, j int) bool {
		return bytes.Compare(blocks[i], blocks[j]) < 0
	})
	h := hf()
	for _, block := range blocks {
		if _, err := h.Write(block); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func readDirUnordered(dirname string) ([]string, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	return names, nil
}
