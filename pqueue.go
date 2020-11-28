package main

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"golang.org/x/sync/semaphore"
)

var ErrEmpty = errors.New("queue empty")

type pqueue struct {
	nodes []*Node
	errs  []error
	muts  []sync.Mutex
	i     int
}

func newPQ(n int) *pqueue {
	p := &pqueue{
		nodes: make([]*Node, n),
		errs:  make([]error, n),
		muts:  make([]sync.Mutex, n),
	}
	for i := range p.muts {
		p.muts[i].Lock()
	}
	return p
}

func (p *pqueue) add(i int, n *Node, err error) {
	p.nodes[i], p.errs[i] = n, err
	p.muts[i].Unlock()
}

func (p *pqueue) next() (*Node, error) {
	if p.i >= len(p.nodes) {
		return nil, ErrEmpty
	}
	p.muts[p.i].Lock()
	r, err := p.nodes[p.i], p.errs[p.i]
	p.nodes[p.i], p.errs[p.i] = nil, nil
	p.i++
	return r, err
}

// TODO: consider re-implementing add/next to extend/contract the array, allowing stream
// TODO: re-consider parallelism model to ensure earlier manually specified items complete before later ones
// TODO: idea for solution: priority lock?
// TODO: idea for solution: instead of `go`, use ordered parallel queue
// TODO:   process manual items in blocks of numcpu (improvement, but does not solve)
// TODO: idea for solution: don't start next entry until signal that all work is scheduled

var (
	NumCPU  = int64(runtime.NumCPU())
	CPULock = semaphore.NewWeighted(NumCPU)
	//WorkerLock = semaphore.NewWeighted(NumCPU)
)

func acquire() { CPULock.Acquire(context.Background(), 1) }
func release() { CPULock.Release(1) }

type wbatch struct {
	c chan func()
	n chan int64
}

type wpool struct {
	c chan *wbatch
}

func newPool() wpool {
	// buffer limits number of goroutines contending for FS walk
	return wpool{c: make(chan *wbatch, NumCPU)}
}

func (p wpool) new() *wbatch {
	b := &wbatch{
		c: make(chan func()),
		n: make(chan int64, 1),
	}
	p.c <- b
	return b
}

func (p wpool) run() {
	for b := range p.c {
		var i, n int64
		for n > 0 && i < n {
			select {
			case n = <-b.n:
			case f := <-b.c:
				i++
				acquire()
				go func() {
					defer release()
					f()
				}()
			}
		}
	}
}

func (b *wbatch) add(f func()) {
	go func() {
		b.c <- f
	}()
}

func (b *wbatch) close(n int64) {
	b.n <- n
	b.n = nil
}

//func wlock()    { WorkerLock.Acquire(context.Background(), 1) }
//func wrelease() { WorkerLock.Release(1) }
//
//type plock struct {
//	sem, nxt *semaphore.Weighted
//}
//
//func newPlock() *plock {
//	wlock()
//	sem := semaphore.NewWeighted(NumCPU)
//	nxt := semaphore.NewWeighted(NumCPU)
//	nxt.Acquire(context.Background(), NumCPU-1)
//	return &plock{sem, nxt}
//}
//
//func (l *plock) lock() {
//	l.sem.Acquire(context.Background(), 1)
//	lock()
//}
//
//func (l *plock) release() {
//	release()
//	l.sem.Release(1)
//}
//
//func (l *plock) next() *plock {
//	nxtnxt := semaphore.NewWeighted(NumCPU)
//	nxtnxt.Acquire(context.Background(), NumCPU-1)
//	return &plock{l.nxt, nxtnxt}
//}
//
//// problem: less than numcpu threads left -> wasted CPUs (e.g., [1, 5, 1, 1] w/ 8 cpus)
//// solution: add extra CPUs to all l.sem
//
//func (l *plock) close() {
//	wrelease()                                  // must be first, else earlier workers must finish
//	l.sem.Acquire(context.Background(), NumCPU) // wait until we're the head lock
//	l.nxt.Release(NumCPU - 1)
//}

// levels:
// thread slot (shared 8)
// allowed claims on cpu (8 or 1)
// cpu (shared 8)
// on close: acquire exactly 8 claims, transfer to next semaphore

// OR

// three channels per thread
// first channel: shared work pool (7)
// second channel: used to send claimed work to previous thread's close
// third channel: used to receive free work claim from previous thread
// previous thread: select on sending free work vs. receiving in-flight work from current thread (to donate back to pool)
// current thread: select on receiving from pool vs. receiving free work from previous thread
