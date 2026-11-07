// Copyright 2026 The Ghost Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package ghostmmr is the header Merkle mountain range of decision 0005: one
// leaf per block, committing to the block's header hash and its difficulty,
// with the summed work of the blocks below every node.
//
// The package knows nothing of headers, blocks or databases: a leaf is made
// from a 32-byte header hash and a difficulty, inner nodes are handed to the
// caller to store, and a path is read through a function the caller gives.
//
// Hashing is tagged Keccak-256: one length byte, the ASCII tag and the
// inputs. Every work value is 16 bytes big-endian; a sum that reaches 2^128
// is refused with ErrWorkOverflow.
//
//	leaf = K("ghost/header-mmr-leaf/v1", header hash, difficulty)             work difficulty
//	node = K("ghost/header-mmr-node/v1", left hash, left work, right hash, right work)   work left + right
//	bag  = K("ghost/header-mmr-bag/v1", peak hash, peak work, bag hash, bag work)       work peak + bag
//	root = K("ghost/header-mmr-root/v1", n as 8 bytes, bag hash, bag work)
//
// An MMR of n leaves has one perfect subtree, a peak, per set bit of n, the
// highest first. The peaks are bagged from the right: the bag of the last
// peak is the peak itself, and each earlier peak is bagged onto the bag after
// it. The bag of no peaks is 32 zero bytes with work 0.
package ghostmmr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"golang.org/x/crypto/sha3"
)

// The tags of decision 0005.
const (
	LeafTag = "ghost/header-mmr-leaf/v1"
	NodeTag = "ghost/header-mmr-node/v1"
	BagTag  = "ghost/header-mmr-bag/v1"
	RootTag = "ghost/header-mmr-root/v1"
)

// Sizes of the encoded values.
const (
	HashSize  = 32
	WorkSize  = 16
	EntrySize = HashSize + WorkSize // one path entry: hash then work
)

var (
	// ErrWorkOverflow is a work sum that reaches 2^128. Its text is the
	// reason of the decision record.
	ErrWorkOverflow = errors.New("work-overflow")

	// ErrIndex is a leaf index that is not below the leaf count.
	ErrIndex = errors.New("header mmr: leaf index not below the leaf count")

	// ErrPathLength is a path whose length is not the one the leaf count and
	// the index give.
	ErrPathLength = errors.New("header mmr: path of the wrong length")

	// ErrRootMismatch is a path that does not fold to the root.
	ErrRootMismatch = errors.New("header mmr: path does not fold to the root")

	// ErrMissingNode is an inner node a path needs that is not stored.
	ErrMissingNode = errors.New("header mmr: inner node not stored")

	// ErrCorrupt is a stored state or node that is not well formed.
	ErrCorrupt = errors.New("header mmr: corrupt state")
)

// Work is an unsigned 128-bit amount of work.
type Work struct{ Hi, Lo uint64 }

// WorkFromUint64 returns w as Work.
func WorkFromUint64(w uint64) Work { return Work{Lo: w} }

// WorkFromBig returns b as Work, or ErrWorkOverflow for a value that is
// negative or does not fit in 128 bits.
func WorkFromBig(b *big.Int) (Work, error) {
	if b == nil || b.Sign() < 0 || b.BitLen() > 128 {
		return Work{}, fmt.Errorf("%w: work %v does not fit in 128 bits", ErrWorkOverflow, b)
	}
	var buf [WorkSize]byte
	b.FillBytes(buf[:])
	return WorkFromBytes(buf[:]), nil
}

// WorkFromBytes reads 16 big-endian bytes.
func WorkFromBytes(b []byte) Work {
	return Work{Hi: binary.BigEndian.Uint64(b[:8]), Lo: binary.BigEndian.Uint64(b[8:WorkSize])}
}

// Add returns w + v, and false if the sum reaches 2^128.
func (w Work) Add(v Work) (Work, bool) {
	lo, carry := bits.Add64(w.Lo, v.Lo, 0)
	hi, carry := bits.Add64(w.Hi, v.Hi, carry)
	return Work{Hi: hi, Lo: lo}, carry == 0
}

// Bytes returns w as 16 big-endian bytes.
func (w Work) Bytes() (b [WorkSize]byte) {
	binary.BigEndian.PutUint64(b[:8], w.Hi)
	binary.BigEndian.PutUint64(b[8:], w.Lo)
	return b
}

// Big returns w as a big integer.
func (w Work) Big() *big.Int {
	b := w.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// IsZero reports whether w is 0.
func (w Work) IsZero() bool { return w == Work{} }

func (w Work) String() string { return w.Big().String() }

// Entry is a hash with its work: a leaf, an inner node, a peak or a bag.
type Entry struct {
	Hash [HashSize]byte
	Work Work
}

// Bytes returns the 48-byte encoding of e: the hash, then the work.
func (e Entry) Bytes() (b [EntrySize]byte) {
	copy(b[:HashSize], e.Hash[:])
	w := e.Work.Bytes()
	copy(b[HashSize:], w[:])
	return b
}

// EntryFromBytes reads a 48-byte entry.
func EntryFromBytes(b []byte) (Entry, error) {
	if len(b) != EntrySize {
		return Entry{}, fmt.Errorf("%w: entry of %d bytes", ErrCorrupt, len(b))
	}
	var e Entry
	copy(e.Hash[:], b[:HashSize])
	e.Work = WorkFromBytes(b[HashSize:])
	return e, nil
}

func tagBytes(tag string) []byte { return append([]byte{byte(len(tag))}, tag...) }

var (
	leafPrefix = tagBytes(LeafTag)
	nodePrefix = tagBytes(NodeTag)
	bagPrefix  = tagBytes(BagTag)
	rootPrefix = tagBytes(RootTag)
)

// keccakState is the Keccak-256 hasher with the Read method of x/crypto.
type keccakState interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Reset()
}

var hasherPool = sync.Pool{New: func() any { return sha3.NewLegacyKeccak256().(keccakState) }}

func keccak(input []byte) (out [HashSize]byte) {
	h := hasherPool.Get().(keccakState)
	h.Reset()
	h.Write(input)
	h.Read(out[:])
	hasherPool.Put(h)
	return out
}

// pair hashes prefix, a's hash and work, then b's hash and work.
func pair(prefix []byte, a, b Entry) [HashSize]byte {
	var buf [1 + 24 + 2*EntrySize]byte
	n := copy(buf[:], prefix)
	ea, eb := a.Bytes(), b.Bytes()
	n += copy(buf[n:], ea[:])
	n += copy(buf[n:], eb[:])
	return keccak(buf[:n])
}

// Leaf returns the leaf of a block: its header hash, the Keccak-256 of the
// whole RLP header, and its difficulty.
func Leaf(headerHash [HashSize]byte, difficulty Work) Entry {
	var buf [1 + len(LeafTag) + HashSize + WorkSize]byte
	n := copy(buf[:], leafPrefix)
	n += copy(buf[n:], headerHash[:])
	w := difficulty.Bytes()
	copy(buf[n:], w[:])
	return Entry{Hash: keccak(buf[:]), Work: difficulty}
}

// Node returns the inner node over left and right.
func Node(left, right Entry) (Entry, error) {
	work, ok := left.Work.Add(right.Work)
	if !ok {
		return Entry{}, ErrWorkOverflow
	}
	return Entry{Hash: pair(nodePrefix, left, right), Work: work}, nil
}

// BagStep bags peak onto the bag of the peaks after it.
func BagStep(peak, bag Entry) (Entry, error) {
	work, ok := peak.Work.Add(bag.Work)
	if !ok {
		return Entry{}, ErrWorkOverflow
	}
	return Entry{Hash: pair(bagPrefix, peak, bag), Work: work}, nil
}

// RootOf returns the root of an MMR of n leaves with the given bag.
func RootOf(n uint64, bag Entry) [HashSize]byte {
	var buf [1 + len(RootTag) + 8 + EntrySize]byte
	c := copy(buf[:], rootPrefix)
	binary.BigEndian.PutUint64(buf[c:], n)
	e := bag.Bytes()
	copy(buf[c+8:], e[:])
	return keccak(buf[:])
}

// EmptyRoot is the root of the MMR of no leaves, the header MMR root of every
// genesis header: b1f684aabd11aa3966ac25d6ac9c50e10cc53cbfb48957f3f514fb4b08fd23ac.
var EmptyRoot = RootOf(0, Entry{})

// Inner is an inner node with its two children, as Push hands it to be
// stored: a path is read by walking down from a peak through the children.
type Inner struct {
	Node        Entry
	Left, Right Entry
}

// State is an MMR without its inner nodes: the leaf count and the peaks,
// highest first. It is all that appending a leaf and computing the root
// need. The zero State is the empty MMR.
type State struct {
	N     uint64
	Peaks []Entry
}

// Copy returns a copy of s that shares nothing with it.
func (s State) Copy() State {
	return State{N: s.N, Peaks: append([]Entry(nil), s.Peaks...)}
}

// TotalWork returns the summed work of all leaves.
func (s State) TotalWork() (Work, error) {
	var total Work
	for _, p := range s.Peaks {
		var ok bool
		if total, ok = total.Add(p.Work); !ok {
			return Work{}, ErrWorkOverflow
		}
	}
	return total, nil
}

// Push appends a leaf in place and calls store, if not nil, with every inner
// node it creates, the lowest first. On an error s is unchanged.
func (s *State) Push(leaf Entry, store func(Inner)) error {
	if len(s.Peaks) != bits.OnesCount64(s.N) {
		return fmt.Errorf("%w: %d peaks for %d leaves", ErrCorrupt, len(s.Peaks), s.N)
	}
	if s.N == ^uint64(0) {
		return fmt.Errorf("%w: leaf count at its limit", ErrCorrupt)
	}
	total, err := s.TotalWork()
	if err != nil {
		return err
	}
	if _, ok := total.Add(leaf.Work); !ok {
		return ErrWorkOverflow
	}
	var (
		merges = bits.TrailingZeros64(^s.N) // trailing ones: peaks of heights 0, 1, ...
		cur    = leaf
		inners [64]Inner
	)
	for t := 0; t < merges; t++ {
		left := s.Peaks[len(s.Peaks)-1-t]
		node, err := Node(left, cur)
		if err != nil {
			return err
		}
		inners[t] = Inner{Node: node, Left: left, Right: cur}
		cur = node
	}
	s.Peaks = append(s.Peaks[:len(s.Peaks)-merges], cur)
	s.N++
	if store != nil {
		for t := 0; t < merges; t++ {
			store(inners[t])
		}
	}
	return nil
}

// Append returns s with the leaf appended, and the inner nodes it creates.
// s itself is not changed.
func (s State) Append(leaf Entry) (State, []Inner, error) {
	next := State{N: s.N, Peaks: make([]Entry, len(s.Peaks), len(s.Peaks)+1)}
	copy(next.Peaks, s.Peaks)
	var inners []Inner
	if err := next.Push(leaf, func(in Inner) { inners = append(inners, in) }); err != nil {
		return State{}, nil, err
	}
	return next, inners, nil
}

// bagOf bags the peaks from the right; the bag of no peaks is the zero entry.
func bagOf(peaks []Entry) (Entry, error) {
	if len(peaks) == 0 {
		return Entry{}, nil
	}
	bag := peaks[len(peaks)-1]
	for i := len(peaks) - 2; i >= 0; i-- {
		var err error
		if bag, err = BagStep(peaks[i], bag); err != nil {
			return Entry{}, err
		}
	}
	return bag, nil
}

// Bag returns the bag of all peaks.
func (s State) Bag() (Entry, error) { return bagOf(s.Peaks) }

// Root returns the root of the MMR.
func (s State) Root() ([HashSize]byte, error) {
	if len(s.Peaks) != bits.OnesCount64(s.N) {
		return [HashSize]byte{}, fmt.Errorf("%w: %d peaks for %d leaves", ErrCorrupt, len(s.Peaks), s.N)
	}
	bag, err := s.Bag()
	if err != nil {
		return [HashSize]byte{}, err
	}
	return RootOf(s.N, bag), nil
}

// Encode returns the leaf count as 8 bytes big-endian followed by the peaks,
// 48 bytes each.
func (s State) Encode() []byte {
	out := make([]byte, 8, 8+EntrySize*len(s.Peaks))
	binary.BigEndian.PutUint64(out, s.N)
	for _, p := range s.Peaks {
		e := p.Bytes()
		out = append(out, e[:]...)
	}
	return out
}

// DecodeState reads what Encode wrote. A length that does not match the leaf
// count, or peaks whose work sums to 2^128, is ErrCorrupt.
func DecodeState(b []byte) (State, error) {
	if len(b) < 8 {
		return State{}, fmt.Errorf("%w: state of %d bytes", ErrCorrupt, len(b))
	}
	n := binary.BigEndian.Uint64(b)
	peaks := bits.OnesCount64(n)
	if len(b) != 8+EntrySize*peaks {
		return State{}, fmt.Errorf("%w: state of %d bytes for %d leaves", ErrCorrupt, len(b), n)
	}
	s := State{N: n, Peaks: make([]Entry, peaks)}
	for i := range s.Peaks {
		s.Peaks[i], _ = EntryFromBytes(b[8+EntrySize*i : 8+EntrySize*(i+1)])
	}
	if _, err := s.TotalWork(); err != nil {
		return State{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return s, nil
}

// EncodeChildren returns the stored form of an inner node's children: the
// left entry, then the right, 96 bytes.
func EncodeChildren(left, right Entry) []byte {
	l, r := left.Bytes(), right.Bytes()
	return append(l[:], r[:]...)
}

// DecodeChildren reads what EncodeChildren wrote.
func DecodeChildren(b []byte) (left, right Entry, err error) {
	if len(b) != 2*EntrySize {
		return Entry{}, Entry{}, fmt.Errorf("%w: children of %d bytes", ErrCorrupt, len(b))
	}
	left, _ = EntryFromBytes(b[:EntrySize])
	right, _ = EntryFromBytes(b[EntrySize:])
	return left, right, nil
}

// position is where leaf i sits in an MMR of n leaves: its peak j (0 the
// highest), the peak's height, the first leaf the peak covers and the
// number of peaks.
type position struct {
	peak, height, peaks int
	start               uint64
}

func locate(n, i uint64) (position, error) {
	if i >= n {
		return position{}, fmt.Errorf("%w: leaf %d of %d", ErrIndex, i, n)
	}
	p := position{peaks: bits.OnesCount64(n)}
	var start uint64
	for h := 63; h >= 0; h-- {
		if n>>uint(h)&1 == 0 {
			continue
		}
		size := uint64(1) << uint(h)
		if i < start+size {
			p.height, p.start = h, start
			return p, nil
		}
		start += size
		p.peak++
	}
	return position{}, fmt.Errorf("%w: leaf %d of %d", ErrIndex, i, n) // not reached
}

// PathLen returns the number of entries of the path of leaf i in an MMR of n
// leaves: the height of its peak, plus the peaks before it, plus one for the
// bag after it unless its peak is the last. It is at most floor(log2 n) + 1.
func PathLen(n, i uint64) (int, error) {
	p, err := locate(n, i)
	if err != nil {
		return 0, err
	}
	l := p.height + p.peak
	if p.peak != p.peaks-1 {
		l++
	}
	return l, nil
}

// Children returns the stored children of the inner node with the given
// hash, and false if it is not stored.
type Children func(hash [HashSize]byte) (left, right Entry, ok bool, err error)

// Path returns the path of leaf i in the MMR s, reading inner nodes through
// children, which must hold every node Push created for s. The path is the
// concatenation of 48-byte entries:
//
//  1. the siblings from the bottom, at heights 0 to h-1 of the leaf's peak;
//  2. the bag of the peaks after the leaf's peak, if it is not the last;
//  3. the peaks before the leaf's peak, nearest first.
//
// Every node read is checked against its children, so a stored node that is
// wrong is ErrCorrupt rather than a wrong path.
func Path(s State, i uint64, children Children) ([]byte, error) {
	if len(s.Peaks) != bits.OnesCount64(s.N) {
		return nil, fmt.Errorf("%w: %d peaks for %d leaves", ErrCorrupt, len(s.Peaks), s.N)
	}
	p, err := locate(s.N, i)
	if err != nil {
		return nil, err
	}
	var (
		offset   = i - p.start
		cur      = s.Peaks[p.peak]
		siblings = make([]Entry, p.height)
	)
	for level := p.height - 1; level >= 0; level-- {
		left, right, ok, err := children(cur.Hash)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: %x", ErrMissingNode, cur.Hash)
		}
		if node, err := Node(left, right); err != nil || node != cur {
			return nil, fmt.Errorf("%w: children of %x do not hash to it", ErrCorrupt, cur.Hash)
		}
		if offset>>uint(level)&1 == 1 {
			siblings[level], cur = left, right
		} else {
			siblings[level], cur = right, left
		}
	}
	out := make([]byte, 0, EntrySize*(p.height+p.peak+1))
	for _, e := range siblings {
		b := e.Bytes()
		out = append(out, b[:]...)
	}
	if p.peak != p.peaks-1 {
		bag, err := bagOf(s.Peaks[p.peak+1:])
		if err != nil {
			return nil, err
		}
		b := bag.Bytes()
		out = append(out, b[:]...)
	}
	for j := p.peak - 1; j >= 0; j-- {
		b := s.Peaks[j].Bytes()
		out = append(out, b[:]...)
	}
	return out, nil
}

// VerifyPath checks the path of leaf i, the block with the given header hash
// and difficulty, against the root of an MMR of n leaves. It returns the work
// of the leaves before i and the total work of the n leaves.
//
// It refuses an index not below n, a path of another length than PathLen
// gives, a fold that reaches 2^128 in work, and a fold that does not give
// the root.
func VerifyPath(root [HashSize]byte, n, i uint64, headerHash [HashSize]byte, difficulty Work, path []byte) (before, total Work, err error) {
	p, err := locate(n, i)
	if err != nil {
		return Work{}, Work{}, err
	}
	want, _ := PathLen(n, i)
	if len(path) != EntrySize*want {
		return Work{}, Work{}, fmt.Errorf("%w: %d bytes, want %d entries", ErrPathLength, len(path), want)
	}
	entry := func(k int) Entry {
		e, _ := EntryFromBytes(path[EntrySize*k : EntrySize*(k+1)])
		return e
	}
	var (
		offset = i - p.start
		cur    = Leaf(headerHash, difficulty)
		ok     bool
	)
	for level := 0; level < p.height; level++ {
		sibling := entry(level)
		if offset>>uint(level)&1 == 1 {
			cur, err = Node(sibling, cur)
			if before, ok = before.Add(sibling.Work); !ok {
				err = ErrWorkOverflow
			}
		} else {
			cur, err = Node(cur, sibling)
		}
		if err != nil {
			return Work{}, Work{}, err
		}
	}
	k := p.height
	if p.peak != p.peaks-1 {
		if cur, err = BagStep(cur, entry(k)); err != nil {
			return Work{}, Work{}, err
		}
		k++
	}
	for j := 0; j < p.peak; j++ {
		peak := entry(k + j)
		if cur, err = BagStep(peak, cur); err != nil {
			return Work{}, Work{}, err
		}
		if before, ok = before.Add(peak.Work); !ok {
			return Work{}, Work{}, ErrWorkOverflow
		}
	}
	if RootOf(n, cur) != root {
		return Work{}, Work{}, ErrRootMismatch
	}
	return before, cur.Work, nil
}
