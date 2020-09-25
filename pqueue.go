package main

import (
	"errors"
	"sync"
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