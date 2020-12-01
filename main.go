package main

import (
	"bufio"
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
	if opts.Check && opts.Mask != "0000" {
		log.Fatal("Mask must be read from checksum file and cannot be specified manually.")
	}
	if opts.Check {
		check(opts.Args.Paths, opts.Algorithm)
	} else {
		output(toFiles(opts.Args.Paths, opts.Mask), opts.Algorithm)
	}
}

func check(indexes []string, alg string) {
	hf := ParseHash(alg)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", alg)
	}
	files := make(chan File, 1)
	sums := make(chan string, 1)

	go func() {
		defer close(files)
		for _, path := range indexes {
			readIndex(path, func(f File, sum string) {
				files <- f
				sums <- sum
			})
		}
	}()
	failed := 0
	if err := NewSum(hf).Each(files, func(n *Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
		}
		if string(n.Sum) != <-sums {
			fmt.Printf("%s: FAILED\n", n.Path)
			failed++
		} else {
			fmt.Printf("%s: OK\n", n.Path)
		}
		return nil
	}); err != nil {
		log.Fatalf("xsum: %s", err)
	}
	if failed > 0 {
		plural := ""
		if failed > 1 {
			plural = "s"
		}
		log.Fatalf("xsum: WARNING: %d computed checksum%s did NOT match", failed, plural)
	}
}

func readIndex(path string, fn func(File, string)) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("xsum: %s", err)
		return
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		entry := scan.Text()
		lines := strings.SplitN(entry, "  ", 2)
		if len(lines) != 2 {
			log.Printf("xsum: %s: invalid entry `%s'", path, entry)
			continue
		}
		hash := lines[0]
		filepath := lines[1]

		var mask Mask
		if p := strings.SplitN(hash, ":", 2); len(p) == 2 {
			hash = p[0]
			mask = NewMaskString(p[1])
		}

		fn(File{filepath, mask}, strings.ToLower(hash))
	}
}

func output(files []File, alg string) {
	hf := ParseHash(alg)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", alg)
	}
	if err := NewSum(hf).EachList(files, func(n *Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
		}
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
	Err  error
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
		if n.Err != nil {
			return n.Err
		}
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
				close(ch) // stops Each from processing after it returns, eventually unnecessary?
				return
			}
		}
		close(ch)
	}()
	return s.Each(ch, f)
}

func (s *Sum) Each(files <-chan File, f func(*Node) error) error {
	queue := NewNodeQueue()
	go func() {
		for file := range files {
			file := file
			var wg sync.WaitGroup
			file.Path = filepath.Clean(file.Path)
			nodeRec := make(chan *Node)
			queue.Enqueue(nodeRec)
			wg.Add(1)
			go func() {
				nodeRec <- s.walkFile(file, false, wg.Done)
			}()
			wg.Wait()
		}
		queue.Close()
	}()

	// TODO: err does not shutdown goroutines, need to thread ctx, can't close files
	for node := queue.Dequeue(); node != nil; node = queue.Dequeue() {
		if err := f(node); err != nil {
			return err
		}
	}
	return nil
}

// NodeQueue is has concurrency-safe properties.
// Neither Enqueue nor Dequeue are individually reentrant.
// However, both may be called at the same time.
type NodeQueue struct {
	front, back *NodeQueueElement
}

type NodeQueueElement struct {
	node <-chan *Node
	next chan *NodeQueueElement
}

func NewNodeQueue() *NodeQueue {
	elem := &NodeQueueElement{
		next: make(chan *NodeQueueElement, 1),
	}
	return &NodeQueue{elem, elem}
}

func (q *NodeQueue) Enqueue(ch <-chan *Node) {
	elem := &NodeQueueElement{
		node: ch,
		next: make(chan *NodeQueueElement, 1),
	}
	q.front.next <- elem
	q.front = elem
}

func (q *NodeQueue) Dequeue() *Node {
	back := <-q.back.next
	if back == nil {
		return nil
	}
	q.back = back
	return <-q.back.node
}

// after Close, Enqueue will always panic, Dequeue will always return nil
func (q *NodeQueue) Close() {
	close(q.front.next)
}

func (s *Sum) acquire() {
	s.Sem.Acquire(context.Background(), 1)
}

func (s *Sum) release() {
	s.Sem.Release(1)
}

// If passed, sched is called exactly once when all remaining work has acquired locks on the CPU
func (s *Sum) walkFile(file File, subdir bool, sched func()) *Node {
	s.acquire()
	rOnce := doOnce(true)
	defer rOnce.Do(s.release)
	sOnce := doOnce(true)
	defer sOnce.Do(sched)

	fi, err := os.Lstat(file.Path)
	if os.IsNotExist(err) {
		return &Node{File: file, Err: pathNewErr("does not exist", file.Path, subdir)}
	}
	if err != nil {
		return pathErrNode("stat", file, subdir, err)
	}
	switch {
	case fi.IsDir():
		names, err := readDirUnordered(file.Path)
		if err != nil {
			return pathErrNode("read dir", file, subdir, err)
		}
		rOnce.Do(s.release)
		nodes := s.walkDir(file, names)

		sOnce.Do(sched)

		// Locking on this operation would prevent short checksum operations from bypassing the NumCPU limit.
		// However, it would also prevent earlier entries from finishing before later entries.

		blocks := make([][]byte, 0, len(names))
		for n := range nodes {
			if n.Err != nil {
				if subdir {
					// error from walkFile has adequate context
					return &Node{File: file, Err: n.Err}
				}
				return &Node{File: file, Err: fmt.Errorf("%s: %w", file.Path, n.Err)}
			}
			b, err := s.hashDirMD(n)
			if err != nil {
				return pathErrNode("hash", file, subdir, err)
			}
			blocks = append(blocks, b)
		}
		sum, err := s.hashBlocks(blocks)
		if err != nil {
			return pathErrNode("hash", file, subdir, err)
		}
		return &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}

	case fi.Mode().IsRegular() || (!subdir && fi.Mode()&os.ModeSymlink != 0):
		sOnce.Do(sched)
		f, err := os.Open(file.Path)
		if err != nil {
			return pathErrNode("open", file, subdir, err)
		}
		defer f.Close()
		sum, err := s.hashReader(f)
		if err != nil {
			return pathErrNode("hash", file, subdir, err)
		}
		return &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}

	case fi.Mode()&os.ModeSymlink != 0:
		sOnce.Do(sched)
		link, err := os.Readlink(file.Path)
		if err != nil {
			return pathErrNode("read link", file, subdir, err)
		}
		sum, err := s.hash([]byte(link))
		if err != nil {
			return pathErrNode("hash", file, subdir, err)
		}
		return &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
	}
	return pathErrNode("hash", file, subdir, ErrSpecialFile)
}

func (s *Sum) walkDir(file File, names []string) <-chan *Node {
	nodes := make(chan *Node, len(names))
	var swg, nwg sync.WaitGroup
	for _, name := range names {
		name := name
		nwg.Add(1)
		swg.Add(1)
		go func() {
			defer nwg.Done()
			nodes <- s.walkFile(File{filepath.Join(file.Path, name), file.Mask}, true, swg.Done)
		}()
	}
	go func() {
		nwg.Wait()
		close(nodes)
	}()
	swg.Wait()
	return nodes
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

func (s *Sum) hashDirMD(n *Node) ([]byte, error) {
	nameSum, err := s.hash([]byte(filepath.Base(n.Path)))
	if err != nil {
		return nil, err
	}
	permSum, err := s.hashSysattr(n)
	if err != nil {
		return nil, err
	}
	xattrSum, err := s.hashXattr(n)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*4))
	buf.Write(nameSum)
	buf.Write(n.Sum)
	buf.Write(permSum)
	buf.Write(xattrSum)
	return buf.Bytes(), nil
}

func (s *Sum) hashFileMD(n *Node) ([]byte, error) {
	permSum, err := s.hashSysattr(n)
	if err != nil {
		return nil, err
	}
	xattrSum, err := s.hashXattr(n)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(n.Sum)*3))
	buf.Write(n.Sum)
	buf.Write(permSum)
	buf.Write(xattrSum)
	return buf.Bytes(), nil
}

func (s *Sum) hashBlocks(blocks [][]byte) ([]byte, error) {
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

const (
	sModeSetuid = 04000
	sModeSetgid = 02000
	sModeSticky = 01000
)

func (s *Sum) hashSysattr(n *Node) ([]byte, error) {
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

func (s *Sum) hashXattr(n *Node) ([]byte, error) {
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

func pathErrNode(verb string, file File, subdir bool, err error) *Node {
	return &Node{File: file, Err: pathErr(verb, file.Path, subdir, err)}
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
