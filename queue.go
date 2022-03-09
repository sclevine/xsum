package xsum

// nodeQueue has concurrency-safe properties.
// Neither enqueue nor dequeue are individually reentrant.
// However, both may be called at the same time.
type nodeQueue struct {
	front, back *nodeElement
}

type nodeElement struct {
	node <-chan *Node
	next chan *nodeElement
}

func newNodeQueue() *nodeQueue {
	elem := &nodeElement{
		next: make(chan *nodeElement, 1),
	}
	return &nodeQueue{elem, elem}
}

func (q *nodeQueue) enqueue(ch <-chan *Node) {
	elem := &nodeElement{
		node: ch,
		next: make(chan *nodeElement, 1),
	}
	q.front.next <- elem
	q.front = elem
}

func (q *nodeQueue) dequeue() *Node {
	back := <-q.back.next
	if back == nil {
		return nil
	}
	q.back = back
	return <-q.back.node
}

// after close, enqueue will always panic, dequeue will always return nil
func (q *nodeQueue) close() {
	close(q.front.next)
}
