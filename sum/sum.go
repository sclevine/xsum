package sum

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	"golang.org/x/sync/semaphore"
)

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

func (n *Node) String() string {
	if n.Mode&os.ModeDir != 0 || n.Mask.Attr&AttrInclude != 0 {
		return hex.EncodeToString(n.Sum) + ":" + n.Mask.String()
	}
	return hex.EncodeToString(n.Sum)
}

type Sum struct {
	Func func() hash.Hash
	Sem  *semaphore.Weighted
}

func New(fn func() hash.Hash) *Sum {
	return &Sum{
		Func: fn,
		Sem:  DefaultLock,
	}
}

func (s *Sum) Find(files []File) ([]*Node, error) {
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

func (s *Sum) Each(files <-chan File, f func(*Node) error) error {
	queue := newNodeQueue()
	go func() {
		for file := range files {
			file := file
			var wg sync.WaitGroup
			file.Path = filepath.Clean(file.Path)
			nodeRec := make(chan *Node)
			queue.enqueue(nodeRec)
			wg.Add(1)
			go func() {
				nodeRec <- s.walkFile(file, false, wg.Done)
			}()
			wg.Wait()
		}
		queue.close()
	}()

	// TODO: err does not shutdown goroutines, need to thread ctx, can't close files channel
	for node := queue.dequeue(); node != nil; node = queue.dequeue() {
		if err := f(node); err != nil {
			return err
		}
	}
	return nil
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

		// Locking on the following operation would prevent short, in-memory checksum operations from bypassing the NumCPU limit.
		// However, it would also prevent some earlier entries from finishing before later entries and lead to excessive contention.
		// Instead, we rely on preemption to schedule these operations.

		blocks := make([][]byte, 0, len(names))
		for n := range nodes {
			if n.Err != nil {
				if subdir {
					// error from walkFile has adequate context
					return &Node{File: file, Err: n.Err}
				}
				return &Node{File: file, Err: fmt.Errorf("%s: %w", file.Path, n.Err)}
			}
			b, err := s.dirSig(n)
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			blocks = append(blocks, b)
		}
		sum, err := s.hashBlocks(blocks)
		if err != nil {
			return pathErrNode("hash", file, subdir, err)
		}
		if file.Mask.Attr&AttrInclude != 0 && !subdir {
			node := &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
			node.Sum, err = s.hashFileSig(node)
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			return node
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
		if file.Mask.Attr&AttrInclude != 0 && !subdir {
			node := &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
			node.Sum, err = s.hashFileSig(node)
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			return node
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
		if file.Mask.Attr&AttrInclude != 0 && !subdir {
			node := &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
			node.Sum, err = s.hashFileSig(node)
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			return node
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

func (s *Sum) dirSig(n *Node) ([]byte, error) {
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

func (s *Sum) fileSig(n *Node) ([]byte, error) {
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

func (s *Sum) hashFileSig(n *Node) ([]byte, error) {
	sig, err := s.fileSig(n)
	if err != nil {
		return nil, err
	}
	return s.hash(sig)
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
