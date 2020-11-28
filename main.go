package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	Algorithm string `short:"a" long:"algorithm" default:"sha256" description:"Use hashing algorithm"`
	Check     bool   `short:"c" long:"check" description:"Validate checksums"`
	Mask      string `short:"m" long:"mask" default:"0000" description:"Apply mask"`
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
	if opts.Check && opts.Mask != "" {
		log.Fatal("Mask must be read from checksum file and cannot be specified manually.")
	}
	if opts.Check {
		check(opts.Args.Paths, opts.Algorithm)
	} else {
		output(toFiles(opts.Args.Paths, opts.Mask), opts.Algorithm)
	}
}

func check(indexes []string, alg string) {
	//mask := NewMaskString(maskStr)
	//hf := ParseHash(alg)
	//sum := Sum{Func: hf, Mask: mask}
	//if hf == nil {
	//	log.Fatalf("Invalid algorithm `%s'", alg)
	//}
	//next := sum.Sum(paths)
	//for n, err := next(); err != ErrEmpty; n, err = next() {
	//	if err != nil {
	//		log.Printf("xsum: %s", err)
	//		continue
	//	}
	//	if n.Mode&os.ModeDir != 0 {
	//		fmt.Printf("%x:%s  %s\n", n.Sum, mask, filepath.ToSlash(n.Path))
	//	} else {
	//		fmt.Printf("%x  %s\n", n.Sum, filepath.ToSlash(n.Path))
	//	}
	//}
}

func output(files []File, alg string) {
	hf := ParseHash(alg)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", alg)
	}
	if err := NewSum(hf).EachList(files, func(n *Node) error {
		if n.Mode&os.ModeDir != 0 {
			fmt.Printf("%x:%s  %s\n", n.Sum, n.Mask, filepath.ToSlash(n.Path))
		} else {
			fmt.Printf("%x  %s\n", n.Sum, filepath.ToSlash(n.Path))
		}
		return nil
	}); err != nil {
		log.Printf("xsum: %s", err)
	}
}

func toFiles(paths []string, mask string) []File {
	var out []File
	for _, path := range paths {
		out = append(out, File{path, NewMaskString(mask)})
	}
	return out
}

var (
	ErrSpecialFile = errors.New("special file")

	DefaultLock = semaphore.NewWeighted(int64(runtime.NumCPU()))
)

type File struct {
	Path string
	Mask Mask
}

type Node struct {
	File
	Sum  []byte
	Mode os.FileMode
	Sys  *SysProps
}

type Sum struct {
	Func HashFunc
	Sem  *semaphore.Weighted
}

func NewSum(fn HashFunc) *Sum {
	return &Sum{
		Func: fn,
		Sem:  DefaultLock,
	}
}

func (s *Sum) Sum(files []File) ([]*Node, error) {
	var nodes []*Node
	if err := s.EachList(files, func(n *Node) error {
		nodes = append(nodes, n)
		return nil
	}); err != nil {
		return nil, err
	}
	return nodes, nil
}

func (s *Sum) EachList(files []File, f func(*Node) error) error {
	ch := make(chan File)
	ctx, done := context.WithCancel(context.Background())
	defer done()
	go func() {
		for _, f := range files {
			select {
			case ch <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	return s.Each(ch, f)
}

func (s *Sum) Each(files chan<- File, f func(*Node) error) error {
	ch := make(chan chan *Node, NumCPU)
	errs := make(chan error)
	go func() {
		var nwg sync.WaitGroup
		for file := range files {
			var swg sync.WaitGroup
			file.Path = filepath.Clean(file.Path)
			nch := make(chan *Node)
			ch <- nch
			nwg.Add(1)
			swg.Add(1)
			go func() {
				defer nwg.Done()
				n, err := s.walk(file, false, swg.Done)
				if err != nil {
					errs <- err
					return
				}
				nch <- n
			}()
			swg.Wait()
		}
		nwg.Wait()
		close(errs)
	}()

	// TODO: err does not shutdown goroutines, need to thread ctx
	for {
		select {
		case c := <-ch:
			if err := f(<-c); err != nil {
				return err
			}
		case err := <-errs:
			return err
		}
	}
}

func (s *Sum) acquire() {
	s.Sem.Acquire(context.Background(), 1)
}

func (s *Sum) release() {
	s.Sem.Release(1)
}

// If passed, sched is called exactly once when all remaining work has acquired locks on the CPU
func (s *Sum) walk(file File, subdir bool, sched func()) (*Node, error) {
	s.acquire()
	rOnce := doOnce(true)
	defer rOnce.Do(s.release)
	sOnce := doOnce(true)
	defer sOnce.Do(sched)

	fi, err := os.Lstat(file.Path)
	if os.IsNotExist(err) {
		return nil, pathNewErr("does not exist", file.Path, subdir)
	}
	if err != nil {
		return nil, pathErr("stat", file.Path, subdir, err)
	}
	switch {
	case fi.IsDir():
		names, err := readDirUnordered(file.Path)
		if err != nil {
			return nil, pathErr("read dir", file.Path, subdir, err)
		}
		rOnce.Do(s.release)
		nodes, errs := s.dir(file, names, subdir)

		sOnce.Do(sched)

		// Locking on this operation would prevent short checksum operations from bypassing the NumCPU limit.
		// However, it would also prevent earlier entries from finishing before later entries.
		sum, err := s.merkle(nodes, errs, len(names))
		if err != nil {
			return nil, pathErr("hash", file.Path, subdir, err)
		}
		return &Node{file, sum, fi.Mode(), getSysProps(fi)}, nil

	case fi.Mode().IsRegular() || (!subdir && fi.Mode()&os.ModeSymlink != 0):
		sOnce.Do(sched)
		f, err := os.Open(file.Path)
		if err != nil {
			return nil, pathErr("open", file.Path, subdir, err)
		}
		defer f.Close()
		sum, err := s.hashReader(f)
		if err != nil {
			return nil, pathErr("hash", file.Path, subdir, err)
		}
		return &Node{file, sum, fi.Mode(), getSysProps(fi)}, nil

	case fi.Mode()&os.ModeSymlink != 0:
		sOnce.Do(sched)
		link, err := os.Readlink(file.Path)
		if err != nil {
			return nil, pathErr("read link", file.Path, subdir, err)
		}
		sum, err := s.hash([]byte(link))
		if err != nil {
			return nil, pathErr("hash", file.Path, subdir, err)
		}
		return &Node{file, sum, fi.Mode(), getSysProps(fi)}, nil
	}
	return nil, pathErr("hash", file.Path, subdir, ErrSpecialFile)
}

func (s *Sum) dir(file File, names []string, subdir bool) (<-chan *Node, <-chan error) {
	nodes := make(chan *Node, len(names))
	errs := make(chan error, len(names))
	var swg, nwg sync.WaitGroup
	for _, name := range names {
		name := name
		nwg.Add(1)
		swg.Add(1)
		go func() {
			defer nwg.Done()
			node, err := s.walk(File{filepath.Join(file.Path, name), file.Mask}, true, swg.Done)
			if err != nil {
				if !subdir {
					errs <- fmt.Errorf("%s: %w", file.Path, err)
					return
				}
				errs <- err
				return
			}
			nodes <- node
		}()
	}
	go func() {
		nwg.Wait()
		close(errs)
	}()
	swg.Wait()
	// error from walk has adequate context
	return nodes, errs
}

func (s *Sum) merkle(nodes <-chan *Node, errs <-chan error, size int) ([]byte, error) {
	blocks := make([][]byte, 0, size)
FOR:
	for {
		select {
		case n := <-nodes:
			nameSum, err := s.hash([]byte(filepath.Base(n.Path)))
			if err != nil {
				return nil, err
			}
			permSum, err := s.sysattrHash(n)
			if err != nil {
				return nil, err
			}
			xattrSum, err := s.xattrHash(n)
			if err != nil {
				return nil, err
			}
			buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*4))
			buf.Write(nameSum)
			buf.Write(n.Sum)
			buf.Write(permSum)
			buf.Write(xattrSum)
			blocks = append(blocks, buf.Bytes())
		case err := <-errs:
			if err != nil {
				return nil, err
			}
			break FOR
		}
	}
	sort.Slice(blocks, func(i, j int) bool {
		return bytes.Compare(blocks[i], blocks[j]) < 0
	})
	h := s.Func()
	for _, block := range blocks {
		if _, err := h.Write(block); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func (s *Sum) hash(b []byte) ([]byte, error) {
	h := s.Func()
	if _, err := h.Write(b); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (s *Sum) hashReader(r io.Reader) ([]byte, error) {
	h := s.Func()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

const (
	sModeSetuid = 04000
	sModeSetgid = 02000
	sModeSticky = 01000
)

func (s *Sum) sysattrHash(n *Node) ([]byte, error) {
	var out [52]byte
	var specialMask os.FileMode
	if n.Mask.Mode&sModeSetuid != 0 {
		specialMask |= os.ModeSetuid
	}
	if n.Mask.Mode&sModeSetgid != 0 {
		specialMask |= os.ModeSetgid
	}
	if n.Mask.Mode&sModeSticky != 0 {
		specialMask |= os.ModeSticky
	}
	permMask := os.FileMode(n.Mask.Mode) & os.ModePerm
	mode := n.Mode & (os.ModeType | permMask | specialMask)
	binary.LittleEndian.PutUint32(out[:4], uint32(mode))

	if n.Mask.Attr&AttrUID != 0 {
		binary.LittleEndian.PutUint32(out[4:8], n.Sys.UID)
	}
	if n.Mask.Attr&AttrGID != 0 {
		binary.LittleEndian.PutUint32(out[8:12], n.Sys.GID)
	}
	if n.Mask.Attr&AttrSpecial != 0 && n.Mode&(os.ModeDevice|os.ModeCharDevice) != 0 {
		binary.LittleEndian.PutUint32(out[12:20], uint32(n.Sys.Device))
	}
	if n.Mask.Attr&AttrMtime != 0 {
		binary.LittleEndian.PutUint64(out[20:28], uint64(n.Sys.Mtime.Sec))
		binary.LittleEndian.PutUint64(out[28:36], uint64(n.Sys.Mtime.Nsec))
	}
	if n.Mask.Attr&AttrCtime != 0 {
		binary.LittleEndian.PutUint64(out[36:44], uint64(n.Sys.Ctime.Sec))
		binary.LittleEndian.PutUint64(out[44:52], uint64(n.Sys.Ctime.Nsec))
	}

	// out[52:68] - reserve for btime?

	return s.hash(out[:])
}

func (s *Sum) xattrHash(n *Node) ([]byte, error) {
	if n.Mask.Attr&AttrX != 0 {
		xattr, err := getXattr(n.Path)
		if err != nil {
			return nil, err
		}
		return s.hash(xattr)
	}
	return nil, nil
}

type doOnce bool

// sync.Once is concurrent, not needed here
func (rs *doOnce) Do(f func()) {
	if *rs {
		*rs = false
		if f != nil {
			f()
		}
	}
}

func pathErr(verb, path string, subdir bool, err error) error {
	var msg string
	pErr := &os.PathError{}
	if !subdir {
		msg = "%[2]s: failed to %[1]s: %[3]w"
	} else if errors.As(err, &pErr) {
		msg = "failed to %[1]s: %[3]w"
	} else {
		msg = "failed to %s `%s': %w"
	}
	return fmt.Errorf(msg, verb, path, err)
}

func pathNewErr(state, path string, subdir bool) error {
	var msg string
	if subdir {
		msg = "`%s' %s"
	} else {
		msg = "%s: %s"
	}
	return fmt.Errorf(msg, path, state)
}
