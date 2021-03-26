package sum

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sync/semaphore"
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

func New(basic bool) *Sum {
	return &Sum{
		Sem:      DefaultLock,
		SkipDirs: basic,
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

	fi, err := file.Stat()
	if os.IsNotExist(err) {
		return &Node{File: file, Err: pathErrSimple(file.Path, err)}
	}
	if err != nil {
		return pathErrNode("stat", file, subdir, err)
	}

	portable := file.Mask.Attr&AttrNoName != 0
	inclusive := file.Mask.Attr&AttrInclusive != 0
	follow := file.Mask.Attr&AttrFollow != 0 || (!inclusive && !subdir)
	noData := file.Mask.Attr&AttrNoData != 0 && (inclusive || subdir)

	switch {
	case fi.IsDir():
		if s.SkipDirs {
			return &Node{File: file, Err: pathErrSimple(file.Path, ErrDirectory)}
		}
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
			var name string
			if !portable {
				// safe because subdir nodes have generated bases
				name = filepath.Base(n.Path)
			}
			b, err := n.dirSig(name)
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			blocks = append(blocks, b)
		}
		sum, err := file.Alg.Blocks(blocks)
		if err != nil {
			return pathErrNode("hash", file, subdir, err)
		}
		if inclusive && !subdir {
			node := &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
			node.Sum, err = node.hashFileSig()
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			return node
		}
		return &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}

	case fi.Mode()&os.ModeSymlink != 0:
		if !follow {
			// announce schedule early if not following link
			sOnce.Do(sched)
		}
		link, err := os.Readlink(file.Path)
		if err != nil {
			return pathErrNode("read link", file, subdir, err)
		}
		if follow {
			rOnce.Do(s.release)
			sOnce.Do(nil)
			n := s.walkFile(File{Path: link, Mask: file.Mask}, subdir, sched)
			n.Path = file.Path
			return n
		}
		file.Mask.Attr &= ^AttrNoName
		var sum []byte
		if noData {
			file.Mask.Attr |= AttrNoData
			sum = file.Alg.Zero()
		} else {
			file.Mask.Attr &= ^AttrNoData
			sum, err = file.Alg.Bytes([]byte(link))
			if err != nil {
				return pathErrNode("hash", file, subdir, err)
			}
		}
		if inclusive && !subdir {
			node := &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
			node.Sum, err = node.hashFileSig()
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			return node
		}
		return &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}

	default:
		sOnce.Do(sched)
		file.Mask.Attr &= ^AttrNoName
		var sum []byte
		if noData || (!fi.Mode().IsRegular() && (inclusive || subdir)) {
			file.Mask.Attr |= AttrNoData
			sum = file.Alg.Zero()
		} else {
			file.Mask.Attr &= ^AttrNoData
			f, err := file.Open()
			if err != nil {
				return pathErrNode("open", file, subdir, err)
			}
			defer f.Close()
			sum, err = file.Alg.Reader(f)
			if err != nil {
				return pathErrNode("hash", file, subdir, err)
			}
		}
		if inclusive && !subdir {
			node := &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
			node.Sum, err = node.hashFileSig()
			if err != nil {
				return pathErrNode("hash metadata", file, subdir, err)
			}
			return node
		}
		return &Node{File: file, Sum: sum, Mode: fi.Mode(), Sys: getSysProps(fi)}
	}
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
			nodes <- s.walkFile(File{
				Alg:  file.Alg,
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
	if errors.As(err, &pErr) {
		err = pErr.Err
	}
	if !subdir {
		msg = "%[2]s: failed to %[1]s: %[3]w"
	}  else {
		msg = "failed to %s `%s': %w"
	}
	return fmt.Errorf(msg, verb, path, err)
}

func pathErrSimple(path string, err error) error {
	pErr := &os.PathError{}
	if errors.As(err, &pErr) {
		err = pErr.Err
	}
	return fmt.Errorf("%s: %w", path, err)
}