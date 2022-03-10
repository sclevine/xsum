package xsum

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sync/semaphore"

	"github.com/sclevine/xsum/encoding"
)

var (
	ErrDirectory = errors.New("is a directory")
	ErrNoStat    = errors.New("stat data unavailable")
	ErrNoXattr   = errors.New("xattr data unavailable")

	DefaultSemaphore = semaphore.NewWeighted(int64(runtime.NumCPU()))
	DefaultSum       = &Sum{Semaphore: DefaultSemaphore}
)

// Sum may be used to calculate checksums of files and directories.
// Directory checksums use Merkle trees to hash their contents.
// If noDirs is true, Files that refer to directories will return ErrDirectory.
// If Semaphone is not provided, DefaultSemaphore is used.
type Sum struct {
	Semaphore *semaphore.Weighted
	NoDirs    bool
}

// Find takes a slice of Files and returns a slice of *Nodes.
// Each *Node contains either a checksum or an error.
// Unlike Each and EachList, Find returns immediately on the first error encountered.
// Returned *Nodes are guaranteed to have Node.Err set to nil.
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

// EachList takes a slice of Files and invokes f for each resulting *Node.
// Each *Node contains either a checksum or an error.
// EachList returns immediately if fn returns an error.
func (s *Sum) EachList(files []File, fn func(*Node) error) error {
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
	return s.Each(ch, fn)
}

// Each takes a channel of Files and invokes f for each resulting *Node.
// Each *Node contains either a checksum or an error.
// Each returns immediately if fn returns an error.
func (s *Sum) Each(files <-chan File, fn func(*Node) error) error {
	queue := newNodeQueue()
	go func() {
		for file := range files {
			file := file
			var wg sync.WaitGroup
			if file.Path != "" {
				file.Path = filepath.Clean(file.Path)
			}
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
		if err := fn(node); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sum) acquireCPU() {
	sem := DefaultSemaphore
	if s.Semaphore != nil {
		sem = s.Semaphore
	}
	sem.Acquire(context.Background(), 1)
}

func (s *Sum) releaseCPU() {
	sem := DefaultSemaphore
	if s.Semaphore != nil {
		sem = s.Semaphore
	}
	sem.Release(1)
}

// If passed, sched is called exactly once when all remaining work has acquired locks on the CPU
func (s *Sum) walkFile(file File, subdir bool, sched func()) *Node {
	s.acquireCPU()
	rOnce := newOnce()
	defer rOnce.Do(s.releaseCPU)
	sOnce := newOnce()
	defer sOnce.Do(sched)

	if err := validateMask(file.Mask); err != nil {
		return newFileErrorNode("validate mask for file", file, subdir, err)
	}
	if file.Stdin {
		file.Mask.Attr &= ^AttrX
	}

	fi, err := file.stat()
	if os.IsNotExist(err) {
		return newFileErrorNode("", file, subdir, err)
	}
	if err != nil {
		return newFileErrorNode("stat", file, subdir, err)
	}
	sys, err := getSys(fi)
	if err == ErrNoStat &&
		file.Mask.Attr&(AttrUID|AttrGID|AttrSpecial|AttrMtime|AttrCtime) == 0 {
		// sys not needed
	} else if err != nil {
		return newFileErrorNode("stat", file, subdir, err)
	}
	var xattr *Xattr
	if file.Mask.Attr&AttrX != 0 {
		xattr, err = file.xattr()
		if err != nil {
			return newFileErrorNode("get xattr", file, subdir, err)
		}
	}

	portable := file.Mask.Attr&AttrNoName != 0
	inclusive := file.Mask.Attr&AttrInclusive != 0
	follow := file.Mask.Attr&AttrFollow != 0 || (!inclusive && !subdir)
	noData := file.Mask.Attr&AttrNoData != 0 && (inclusive || subdir)

	var sum []byte
	switch {
	case fi.IsDir():
		if s.NoDirs {
			return newFileErrorNode("", file, subdir, ErrDirectory)
		}
		names, err := readDirUnordered(file.Path)
		if err != nil {
			return newFileErrorNode("read dir", file, subdir, err)
		}
		rOnce.Do(s.releaseCPU)
		nodes := s.walkDir(file, names)

		sOnce.Do(sched)

		// Locking on the following operation would prevent short, in-memory checksum operations from bypassing the NumCPU limit.
		// However, it would also prevent some earlier entries from finishing before later entries and lead to excessive contention.
		// Instead, we rely on preemption to schedule these operations.

		hashes := make([]encoding.NamedHash, 0, len(names))
		for n := range nodes {
			if n.Err != nil {
				if subdir { // preserve bottom-level and top-level FileError only
					// error from walkFile has adequate context
					return &Node{File: file, Err: n.Err}
				}
				return newFileErrorNode("", file, subdir, n.Err)
			}
			var name string
			if !portable {
				// safe because subdir nodes have generated bases
				name = filepath.Base(n.Path)
			}
			b, err := hashFileAttr(n)
			if err != nil {
				return newFileErrorNode("hash metadata for file", file, subdir, err)
			}
			hashes = append(hashes, encoding.NamedHash{
				Hash: b,
				Name: []byte(name),
			})
		}
		der, err := encoding.TreeASN1DER(hashToEncoding(file.Hash.String()), hashes)
		if err != nil {
			return newFileErrorNode("encode", file, subdir, err)
		}
		sum, err = file.Hash.Metadata(der)
		if err != nil {
			return newFileErrorNode("hash", file, subdir, err)
		}

	case fi.Mode()&os.ModeSymlink != 0 && follow:
		link, err := filepath.EvalSymlinks(file.Path)
		if err != nil {
			return newFileErrorNode("", file, subdir, err) // closer to, e.g., shasum w/o action
		}

		rOnce.Do(s.releaseCPU) // will be re-acquired at dest
		sOnce.Do(nil)          // prevent defer, will be called at dest

		path := file.Path
		file.Path = link
		n := s.walkFile(file, subdir, sched) // FIXME: pass link here instead?
		n.Path = path
		fErr := &FileError{}
		if errors.As(err, &fErr) && !subdir {
			fErr.Path = path // FIXME: account for symlink to directory, track real vs. fake path?
		}
		return n
	case fi.Mode()&os.ModeSymlink != 0:
		sOnce.Do(sched)
		file.Mask.Attr &= ^AttrNoName // not directory
		if noData {
			file.Mask.Attr |= AttrNoData
		} else {
			link, err := os.Readlink(file.Path)
			if err != nil {
				return newFileErrorNode("read link", file, subdir, err)
			}
			file.Mask.Attr &= ^AttrNoData
			sum, err = file.Hash.Metadata([]byte(link))
			if err != nil {
				return newFileErrorNode("hash link", file, subdir, err)
			}
		}

	default:
		sOnce.Do(sched)
		file.Mask.Attr &= ^AttrNoName // not directory
		if noData || (!fi.Mode().IsRegular() && (inclusive || subdir)) {
			file.Mask.Attr |= AttrNoData
		} else {
			file.Mask.Attr &= ^AttrNoData
			sum, err = file.sum()
			if err != nil {
				return newFileErrorNode("hash", file, subdir, err)
			}
		}
	}

	n := &Node{
		File:  file,
		Sum:   sum,
		Mode:  fi.Mode(),
		Sys:   sys,
		Xattr: xattr,
	}
	if inclusive && !subdir {
		n.Sum, err = hashFileAttr(n)
		if err != nil {
			return newFileErrorNode("hash metadata for file", file, subdir, err)
		}
	}
	return n
}

func (s *Sum) walkDir(file File, names []string) <-chan *Node {
	nodes := make(chan *Node, len(names))
	var swg, nwg sync.WaitGroup
	nwg.Add(len(names))
	swg.Add(len(names))
	for _, name := range names {
		name := name
		go func() {
			defer nwg.Done()
			nodes <- s.walkFile(File{
				Hash: file.Hash,
				Path: filepath.Join(file.Path, name),
				Mask: file.Mask,
			}, true, swg.Done)
		}()
	}
	go func() {
		nwg.Wait()
		close(nodes)
	}()
	swg.Wait()
	return nodes
}

func newOnce() doOnce {
	return true
}

// sync.Once is concurrent, not needed here
type doOnce bool

func (rs *doOnce) Do(f func()) {
	if *rs {
		*rs = false
		if f != nil {
			f()
		}
	}
}

func newFileErrorNode(action string, file File, subdir bool, err error) *Node {
	return &Node{File: file, Err: newFileError(action, file.Path, subdir, err)}
}

func newFileError(action, path string, subdir bool, err error) error {
	return &FileError{
		Action: action,
		Path:   path,
		Subdir: subdir,
		Err:    err,
	}
}

// FileError is similar to os.PathError, but contains extra information such as Subdir.
type FileError struct {
	Action string // failed action
	Path   string
	Subdir bool // error apply to file/dir in subdir of specified path
	Err    error
}

// Error message
func (e *FileError) Error() string {
	err := e.Err
	pErr := &os.PathError{}
	fErr := &FileError{}
	if errors.As(err, &pErr) && !errors.As(err, &fErr) {
		err = pErr.Err // remove intermediate *PathError -- will be covered by FileError
	}
	if e.Action == "" {
		return fmt.Sprintf("%s: %s", e.Path, err)
	}
	if e.Subdir {
		return fmt.Sprintf("failed to %s `%s': %s", e.Action, e.Path, err)
	}
	return fmt.Sprintf("%[2]s: failed to %[1]s: %[3]s", e.Action, e.Path, err)
}

// Unwrap returns the underlying error
func (e *FileError) Unwrap() error {
	return e.Err
}
