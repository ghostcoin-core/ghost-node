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

// Package ghosttree holds the coin tree and the data tree, the two commitment
// trees of the chain, and the spent-marker sets, all in the storage of
// reserved system accounts so that they are journaled state covered by the
// state root (docs/trees-and-headers.md).
package ghosttree

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
)

var (
	// ErrFillingBlock is returned for an append to a full tree in the block
	// that filled it: the transaction cannot be included in that block.
	ErrFillingBlock = errors.New("tree filled in this block; the next tree starts in a later block")

	// ErrIndexExhausted is returned for an append to a full tree whose index
	// is the largest there is.
	ErrIndexExhausted = errors.New("tree index exhausted")

	// ErrCorruptTreeState is returned when the stored tree state breaks a
	// rule of the layout; no root is guessed from it.
	ErrCorruptTreeState = errors.New("corrupt tree state")

	// ErrMarkerSpent is returned for a marker already in its spent set.
	ErrMarkerSpent = errors.New("marker already spent")

	// ErrUnknownKind is returned for a kind that is neither Coin nor Data.
	ErrUnknownKind = errors.New("unknown tree kind")

	// ErrZeroLeaf is returned for an append of the all-zero leaf, which the
	// stored frontier could not tell from an empty slot.
	ErrZeroLeaf = errors.New("zero leaf")

	// ErrDepth is returned by Params.Check for a depth other than 32.
	ErrDepth = errors.New("tree depth is not 32")
)

// Kind is the type of a tree or of a marker set.
type Kind uint8

const (
	Coin Kind = iota // the coin tree and the coin spent-marker set
	Data             // the data tree and the data spent-marker set

	// CoinMarkers and DataMarkers are the lists of spent markers of each
	// kind in the order they were spent, which only the tree history keeps.
	// They are no tree: no state, root or header field belongs to them.
	CoinMarkers
	DataMarkers
)

func (k Kind) String() string {
	switch k {
	case Coin:
		return "coin"
	case Data:
		return "data"
	case CoinMarkers:
		return "coin-markers"
	case DataMarkers:
		return "data-markers"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

func (k Kind) valid() bool { return k == Coin || k == Data }

// IsMarkers reports whether k is a marker list of the tree history.
func (k Kind) IsMarkers() bool { return k == CoinMarkers || k == DataMarkers }

// stored reports whether the tree history keeps records of kind k.
func (k Kind) stored() bool { return k.valid() || k.IsMarkers() }

// The hash tags of spec 01, section 4.
const (
	TagEmptyLeaf = "ghost/empty-leaf/v1"
	TagCoinNode  = "ghost/coin-tree-node/v1"
	TagDataNode  = "ghost/data-tree-node/v1"
)

// K is the tagged hash: Keccak-256 with the original padding over the tag's
// length as one byte, the tag's ASCII bytes and the inputs in order.
func K(tag string, inputs ...[]byte) common.Hash {
	data := make([][]byte, 0, len(inputs)+1)
	data = append(data, append([]byte{byte(len(tag))}, tag...))
	data = append(data, inputs...)
	return common.BytesToHash(crypto.Keccak256(data...))
}

// EmptyLeaf is the value of an unused leaf position.
var EmptyLeaf = K(TagEmptyLeaf)

func nodeTag(kind Kind) string {
	if kind == Data {
		return TagDataNode
	}
	return TagCoinNode
}

// node is the inner node at level (0 just above the leaves) over left and
// right in a tree of the given kind.
func node(kind Kind, level int, left, right common.Hash) common.Hash {
	return K(nodeTag(kind), []byte{byte(level)}, left[:], right[:])
}

// MaxDepth is the number of frontier slots of the storage layout.
const MaxDepth = 32

// Params are the tree parameters. Only Release is valid on a chain; the
// functions of this package take Params internally so that tests can fill
// and roll over a small tree.
type Params struct {
	Depth int // levels of inner nodes above the leaves
}

// Release is the parameter set every chain uses.
var Release = Params{Depth: 32}

// Check returns an error unless the depth is 32, so 2^32 leaves per tree.
func (p Params) Check() error {
	if p.Depth != 32 {
		return fmt.Errorf("%w: depth %d", ErrDepth, p.Depth)
	}
	return nil
}

func (p Params) usable() error {
	if p.Depth < 1 || p.Depth > MaxDepth {
		return fmt.Errorf("%w: depth %d", ErrDepth, p.Depth)
	}
	return nil
}

// capacity is the leaf count of a full tree, 2^Depth.
func (p Params) capacity() uint64 { return uint64(1) << p.Depth }

var releaseZeros = [2][]common.Hash{zeros(Coin, Release.Depth), zeros(Data, Release.Depth)}

// zeros returns Z_0 to Z_depth for a kind: Z_0 = E, Z_(l+1) = node(l, Z_l, Z_l).
func zeros(kind Kind, depth int) []common.Hash {
	z := make([]common.Hash, depth+1)
	z[0] = EmptyLeaf
	for l := 0; l < depth; l++ {
		z[l+1] = node(kind, l, z[l], z[l])
	}
	return z
}

func (p Params) zeros(kind Kind) []common.Hash {
	if p.Depth == Release.Depth {
		return releaseZeros[kind]
	}
	return zeros(kind, p.Depth)
}

// EmptyRoot returns the root of an empty tree of the kind, Z_32.
func EmptyRoot(kind Kind) common.Hash {
	return Release.zeros(kind)[Release.Depth]
}

// StateDB is the part of the state the trees and marker sets use; it is
// satisfied by *state.StateDB.
type StateDB interface {
	Exist(addr common.Address) bool
	CreateAccount(addr common.Address)
	GetNonce(addr common.Address) uint64
	SetNonce(addr common.Address, nonce uint64)
	GetState(addr common.Address, hash common.Hash) common.Hash
	SetState(addr common.Address, key, value common.Hash)
}

// TreeAccount returns the reserved account holding the tree state of a kind.
func TreeAccount(kind Kind) common.Address {
	if kind == Data {
		return ghost.DataTreeAccount
	}
	return ghost.CoinTreeAccount
}

// MarkerAccount returns the reserved account holding the spent markers of a
// kind.
func MarkerAccount(kind Kind) common.Address {
	if kind == Data {
		return ghost.DataMarkerAccount
	}
	return ghost.CoinMarkerAccount
}

// Storage slots of a tree-state account.
const (
	SlotTreeIndex  = 0 // index k of the current tree
	SlotLeafCount  = 1 // leaves n in tree k, 0 to 2^32
	SlotLastFilled = 2 // height of the block in which tree k last became full
	SlotFinalRoot  = 3 // root of tree k once full, zero otherwise
	SlotFrontier   = 4 // f_0, up to f_31 in slot 35
)

// Slot returns the storage key of slot i: i as a 32-byte big-endian integer.
func Slot(i uint64) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], i)
	return h
}

func word(v uint64) common.Hash { return Slot(v) }

// readUint reads a 32-byte big-endian integer below 2^64.
func readUint(h common.Hash) (uint64, bool) {
	for _, b := range h[:24] {
		if b != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint64(h[24:]), true
}

// ensureAccount makes a reserved account exist with nonce 1, so the
// empty-account cleanup never deletes it with its storage.
func ensureAccount(st StateDB, addr common.Address) {
	if !st.Exist(addr) {
		st.CreateAccount(addr)
	}
	if st.GetNonce(addr) == 0 {
		st.SetNonce(addr, 1)
	}
}

// treeState is the stored state of one tree kind.
type treeState struct {
	index, count, lastFilled uint64
	finalRoot                common.Hash
	frontier                 [MaxDepth]common.Hash
}

// load reads and checks the tree state of a kind. An absent account reads as
// the empty tree.
func load(p Params, st StateDB, kind Kind) (*treeState, error) {
	addr := TreeAccount(kind)
	var (
		s  treeState
		ok bool
	)
	if s.index, ok = readUint(st.GetState(addr, Slot(SlotTreeIndex))); !ok {
		return nil, fmt.Errorf("%w: %v tree index out of range", ErrCorruptTreeState, kind)
	}
	if s.count, ok = readUint(st.GetState(addr, Slot(SlotLeafCount))); !ok || s.count > p.capacity() {
		return nil, fmt.Errorf("%w: %v leaf count above %d", ErrCorruptTreeState, kind, p.capacity())
	}
	if s.lastFilled, ok = readUint(st.GetState(addr, Slot(SlotLastFilled))); !ok {
		return nil, fmt.Errorf("%w: %v last filled height out of range", ErrCorruptTreeState, kind)
	}
	s.finalRoot = st.GetState(addr, Slot(SlotFinalRoot))
	for l := 0; l < p.Depth; l++ {
		s.frontier[l] = st.GetState(addr, Slot(uint64(SlotFrontier+l)))
	}
	if s.count == p.capacity() {
		if s.finalRoot == (common.Hash{}) {
			return nil, fmt.Errorf("%w: %v tree full without a final root", ErrCorruptTreeState, kind)
		}
		return &s, nil
	}
	if s.finalRoot != (common.Hash{}) {
		return nil, fmt.Errorf("%w: %v tree not full but has a final root", ErrCorruptTreeState, kind)
	}
	for l := 0; l < p.Depth; l++ {
		if s.count>>l&1 == 1 && s.frontier[l] == (common.Hash{}) {
			return nil, fmt.Errorf("%w: %v frontier slot %d empty under a set bit", ErrCorruptTreeState, kind, l)
		}
	}
	return &s, nil
}

// store writes the slots of s that differ from old.
func store(p Params, st StateDB, kind Kind, old, s *treeState) {
	addr := TreeAccount(kind)
	ensureAccount(st, addr)
	set := func(slot uint64, before, after common.Hash) {
		if before != after {
			st.SetState(addr, Slot(slot), after)
		}
	}
	set(SlotTreeIndex, word(old.index), word(s.index))
	set(SlotLeafCount, word(old.count), word(s.count))
	set(SlotLastFilled, word(old.lastFilled), word(s.lastFilled))
	set(SlotFinalRoot, old.finalRoot, s.finalRoot)
	for l := 0; l < p.Depth; l++ {
		set(uint64(SlotFrontier+l), old.frontier[l], s.frontier[l])
	}
}

// AppendResult is where an appended leaf went.
type AppendResult struct {
	Kind      Kind
	TreeIndex uint64
	Position  uint32
	Leaf      common.Hash
}

// Append appends leaf to the current tree of a kind in the block at height,
// as spec 05, section 3 fixes. When the tree is full, the leaf starts the
// next tree, unless the tree filled in this block (ErrFillingBlock) or its
// index is the last (ErrIndexExhausted). On an error nothing is written.
func Append(st StateDB, kind Kind, height uint64, leaf common.Hash) (AppendResult, error) {
	if err := Release.Check(); err != nil {
		return AppendResult{}, err
	}
	return appendLeaf(Release, st, kind, height, leaf)
}

func appendLeaf(p Params, st StateDB, kind Kind, height uint64, leaf common.Hash) (AppendResult, error) {
	if err := p.usable(); err != nil {
		return AppendResult{}, err
	}
	if !kind.valid() {
		return AppendResult{}, ErrUnknownKind
	}
	if leaf == (common.Hash{}) {
		return AppendResult{}, ErrZeroLeaf
	}
	old, err := load(p, st, kind)
	if err != nil {
		return AppendResult{}, err
	}
	s := *old
	if s.count == p.capacity() {
		switch {
		case s.lastFilled == height:
			return AppendResult{}, ErrFillingBlock
		case s.index == math.MaxUint64:
			return AppendResult{}, ErrIndexExhausted
		}
		s.index++
		s.count = 0
		s.finalRoot = common.Hash{}
		s.frontier = [MaxDepth]common.Hash{}
	}
	position := s.count
	cur := leaf
	for l := 0; l < p.Depth; l++ {
		if position>>l&1 == 0 {
			s.frontier[l] = cur
			break
		}
		cur = node(kind, l, s.frontier[l], cur)
	}
	s.count++
	if s.count == p.capacity() {
		// The last position has every bit set, so cur is the full root.
		s.lastFilled = height
		s.finalRoot = cur
	}
	store(p, st, kind, old, &s)
	return AppendResult{Kind: kind, TreeIndex: s.index, Position: uint32(position), Leaf: leaf}, nil
}

// Root returns the root of the current tree of a kind.
func Root(st StateDB, kind Kind) (common.Hash, error) {
	if err := Release.Check(); err != nil {
		return common.Hash{}, err
	}
	return root(Release, st, kind)
}

func root(p Params, st StateDB, kind Kind) (common.Hash, error) {
	if err := p.usable(); err != nil {
		return common.Hash{}, err
	}
	if !kind.valid() {
		return common.Hash{}, ErrUnknownKind
	}
	s, err := load(p, st, kind)
	if err != nil {
		return common.Hash{}, err
	}
	if s.count == p.capacity() {
		return s.finalRoot, nil
	}
	z := p.zeros(kind)
	cur := z[0]
	for l := 0; l < p.Depth; l++ {
		if s.count>>l&1 == 1 {
			cur = node(kind, l, s.frontier[l], cur)
		} else {
			cur = node(kind, l, cur, z[l])
		}
	}
	return cur, nil
}

// HeaderRoot returns the header's root field of a kind, nil if it is unset
// or the kind is unknown.
func HeaderRoot(header *types.Header, kind Kind) *common.Hash {
	if header == nil {
		return nil
	}
	switch kind {
	case Coin:
		return header.CoinTreeRoot
	case Data:
		return header.DataTreeRoot
	}
	return nil
}

// VerifyMembership reports whether leaf sits at position of the tree whose
// root is the header's root field of the kind, with siblings[l] the sibling
// at height l on the path from the leaf. It needs nothing but the header; a
// nil root field is false.
func VerifyMembership(header *types.Header, kind Kind, position uint32, leaf common.Hash, siblings [32]common.Hash) bool {
	want := HeaderRoot(header, kind)
	if want == nil || Release.Check() != nil {
		return false
	}
	return pathRoot(Release, kind, uint64(position), leaf, siblings[:]) == *want
}

// pathRoot is the root over leaf at position with the given siblings.
func pathRoot(p Params, kind Kind, position uint64, leaf common.Hash, siblings []common.Hash) common.Hash {
	cur := leaf
	for l := 0; l < p.Depth; l++ {
		if position>>l&1 == 1 {
			cur = node(kind, l, siblings[l], cur)
		} else {
			cur = node(kind, l, cur, siblings[l])
		}
	}
	return cur
}

// IsSpent reports whether marker is in the spent set of the kind: its slot in
// the kind's marker account holds any non-zero value. An unknown kind counts
// as spent, so that uncertainty rejects.
func IsSpent(st StateDB, kind Kind, marker common.Hash) bool {
	if !kind.valid() {
		return true
	}
	return st.GetState(MarkerAccount(kind), marker) != (common.Hash{})
}

// MarkSpent adds marker to the spent set of the kind, writing 1 to the slot
// keyed by the marker. A marker already spent, including by an earlier
// transaction of the same block, is ErrMarkerSpent.
func MarkSpent(st StateDB, kind Kind, marker common.Hash) error {
	if !kind.valid() {
		return ErrUnknownKind
	}
	if IsSpent(st, kind, marker) {
		return ErrMarkerSpent
	}
	addr := MarkerAccount(kind)
	ensureAccount(st, addr)
	st.SetState(addr, marker, word(1))
	return nil
}
