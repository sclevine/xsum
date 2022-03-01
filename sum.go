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

	DefaultLock = semaphore.NewWeighted(int64(runtime.NumCPU()))
)

type Sum struct {
	Sem      *semaphore.Weighted
	SkipDirs bool
}

func New(skipDirs bool) *Sum {
	return &Sum{
		Sem:      DefaultLock,
		SkipDirs: skipDirs,
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
		if err := f(node); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sum) acquireCPU() {
	s.Sem.Acquire(context.Background(), 1)
}

func (s *Sum) releaseCPU() {
	s.Sem.Release(1)
}

// If passed, sched is called exactly once when all remaining work has acquired locks on the CPU
func (s *Sum) walkFile(file File, subdir bool, sched func()) *Node {
	s.acquireCPU()
	rOnce := doOnce(true)
	defer rOnce.Do(s.releaseCPU)
	sOnce := doOnce(true)
	defer sOnce.Do(sched)

	fi, err := file.stat()
	if os.IsNotExist(err) {
		return newFileErrorNode("", file, subdir, err)
	}
	if err != nil {
		return newFileErrorNode("stat", file, subdir, err)
	}
	sys, err := file.sys(fi)
	if err == ErrNoStat &&
		file.Mask.Attr&(AttrUID|AttrGID|AttrSpecial|AttrMtime|AttrCtime) == 0 {
		// sys not needed
	} else if err != nil {
		return newFileErrorNode("stat", file, subdir, err)
	}
	if err := validateMask(file.Mask); err != nil {
		return newFileErrorNode("validate mask for file", file, subdir, err)
	}

	portable := file.Mask.Attr&AttrNoName != 0
	inclusive := file.Mask.Attr&AttrInclusive != 0
	follow := file.Mask.Attr&AttrFollow != 0 || (!inclusive && !subdir)
	noData := file.Mask.Attr&AttrNoData != 0 && (inclusive || subdir)

	var sum []byte
	switch {
	case fi.IsDir():
		if s.SkipDirs {
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
			b, err := n.hashFileAttr()
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
		sOnce.Do(nil) // prevent defer, will be called at dest

		path := file.Path
		file.Path = link
		n := s.walkFile(file, subdir, sched)
		n.Path = path
		fErr := &FileError{}
		if errors.As(err, &fErr) {
			fErr.Path = path
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
		File: file,
		Sum:  sum,
		Mode: fi.Mode(),
		Sys:  sys,
	}
	if inclusive && !subdir {
		n.Sum, err = n.hashFileAttr()
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

type FileError struct {
	Action string
	Path   string
	Subdir bool
	Err    error
}

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

func (e *FileError) Unwrap() error {
	return e.Err
}
