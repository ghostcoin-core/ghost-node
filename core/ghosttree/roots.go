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

package ghosttree

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	// ErrIndexNotReady is returned by EligibleRoot while the root index does
	// not cover the including block's ancestry: there is no index yet, it is
	// being built, or it lags behind the canonical chain.
	ErrIndexNotReady = errors.New("tree-root index not ready")

	// ErrRootLookup is returned by EligibleRoot when a header or an index
	// entry it needs cannot be read or does not match.
	ErrRootLookup = errors.New("tree-root lookup failed")

	// errStaleIndex makes MoveRootIndex build the index again from genesis.
	errStaleIndex = errors.New("stored root index does not match the chain")
)

// HeaderLookup is the part of the chain EligibleRoot reads; it is satisfied
// by *core.BlockChain. The chain must also be a RootIndex.
type HeaderLookup interface {
	GetHeader(hash common.Hash, number uint64) *types.Header
	GetCanonicalHash(number uint64) common.Hash
}

// RootIndex is the index of the roots carried by the canonical chain's
// headers.
type RootIndex interface {
	// RootIndexHead returns the block whose ancestry the index holds, or an
	// error wrapping ErrIndexNotReady if there is none.
	RootIndexHead() (number uint64, hash common.Hash, err error)

	// RootFirstHeight returns the height of the first header of the indexed
	// chain whose root field of the kind is root, and false if there is none.
	RootFirstHeight(kind Kind, root common.Hash) (number uint64, found bool, err error)
}

// DBRootIndex is the RootIndex kept in a chain database by MoveRootIndex.
type DBRootIndex struct {
	DB ethdb.KeyValueReader
}

// RootIndexHead implements RootIndex.
func (ix DBRootIndex) RootIndexHead() (uint64, common.Hash, error) {
	number, hash, ok, err := rawdb.ReadGhostRootIndexHead(ix.DB)
	if err != nil {
		return 0, common.Hash{}, fmt.Errorf("%w: %v", ErrIndexNotReady, err)
	}
	if !ok {
		return 0, common.Hash{}, fmt.Errorf("%w: no index head", ErrIndexNotReady)
	}
	return number, hash, nil
}

// RootFirstHeight implements RootIndex.
func (ix DBRootIndex) RootFirstHeight(kind Kind, root common.Hash) (uint64, bool, error) {
	if !kind.valid() {
		return 0, false, ErrUnknownKind
	}
	return rawdb.ReadGhostRootHeight(ix.DB, uint8(kind), root)
}

// EligibleRoot reports whether root is the root field of the kind in the
// header of a block below the including block among its ancestors, where
// parent is the including block's parent (spec 05, sections 5 and 7). There
// is no age limit. The including block's own root counts only if an
// ancestor carries it too; a block outside the ancestry never counts, even
// one the node imported or once followed.
//
// The branch of parent is walked down to the canonical chain, and the index
// answers below that point. A missing header, an unreadable or mismatching
// index entry, or an index that does not cover the fork point is an error,
// never true.
func EligibleRoot(chain HeaderLookup, parent *types.Header, kind Kind, root common.Hash) (bool, error) {
	if !kind.valid() {
		return false, ErrUnknownKind
	}
	if parent == nil || parent.Number == nil || !parent.Number.IsUint64() {
		return false, fmt.Errorf("%w: no parent header", ErrRootLookup)
	}
	index, ok := chain.(RootIndex)
	if !ok {
		return false, fmt.Errorf("%w: the chain keeps no root index", ErrIndexNotReady)
	}
	headNumber, headHash, err := index.RootIndexHead()
	if err != nil {
		return false, err
	}
	if chain.GetCanonicalHash(headNumber) != headHash {
		return false, fmt.Errorf("%w: indexed block %d is not canonical", ErrIndexNotReady, headNumber)
	}
	// The including block's own branch, from the parent down to the first
	// canonical block.
	var (
		cur      = parent
		eligible = false
	)
	for {
		n := cur.Number.Uint64()
		if chain.GetCanonicalHash(n) == cur.Hash() {
			break
		}
		if r := HeaderRoot(cur, kind); r != nil && *r == root {
			eligible = true
		}
		if n == 0 {
			return false, fmt.Errorf("%w: branch of block %x reaches another genesis", ErrRootLookup, parent.Hash())
		}
		next := chain.GetHeader(cur.ParentHash, n-1)
		if next == nil {
			return false, fmt.Errorf("%w: header %d %x missing", ErrRootLookup, n-1, cur.ParentHash)
		}
		cur = next
	}
	fork, forkHash := cur.Number.Uint64(), cur.Hash()
	if fork > headNumber {
		return false, fmt.Errorf("%w: indexed up to block %d, needed up to %d", ErrIndexNotReady, headNumber, fork)
	}
	// Below the fork point, the first canonical header with the root.
	height, found, err := index.RootFirstHeight(kind, root)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrRootLookup, err)
	}
	if !eligible && found && height <= fork {
		h := chain.GetHeader(chain.GetCanonicalHash(height), height)
		if h == nil {
			return false, fmt.Errorf("%w: canonical header %d missing", ErrRootLookup, height)
		}
		if r := HeaderRoot(h, kind); r == nil || *r != root {
			return false, fmt.Errorf("%w: index entry at %d does not match the header", ErrRootLookup, height)
		}
		eligible = true
	}
	// Neither the index nor the canonical chain moved while they were read.
	if n, h, err := index.RootIndexHead(); err != nil || n != headNumber || h != headHash {
		return false, fmt.Errorf("%w: the index moved during the lookup", ErrIndexNotReady)
	}
	if chain.GetCanonicalHash(headNumber) != headHash || chain.GetCanonicalHash(fork) != forkHash {
		return false, fmt.Errorf("%w: the canonical chain moved during the lookup", ErrIndexNotReady)
	}
	return eligible, nil
}

// RootIndexStore is the database the root index is kept in.
type RootIndexStore interface {
	ethdb.KeyValueReader
	ethdb.Iteratee
}

type rootKey struct {
	kind Kind
	root common.Hash
}

// indexMove is the change of the root index for one move of its head.
type indexMove struct {
	clear   bool               // remove every stored entry first
	deletes map[rootKey]bool   // entries of blocks that leave the chain
	writes  map[rootKey]uint64 // entries of blocks that join it
}

var indexKinds = [...]Kind{Coin, Data}

// MoveRootIndex writes to w the change that makes the root index of db hold
// the ancestry of head: the entries of the blocks of the indexed chain above
// the fork point are removed and those of head's branch added, with the new
// index head, all in w, so a caller that writes w in the same batch as the
// canonical-chain pointers moves both together. When the stored index is
// missing or does not match the chain, the change rebuilds it from genesis
// along head's ancestry. On an error nothing is written to w.
func MoveRootIndex(db RootIndexStore, chain HeaderLookup, w ethdb.KeyValueWriter, head *types.Header) error {
	if head == nil || head.Number == nil || !head.Number.IsUint64() {
		return fmt.Errorf("%w: no head header", ErrRootLookup)
	}
	move, err := planIndexMove(db, chain, head)
	if errors.Is(err, errStaleIndex) {
		move, err = planIndexRebuild(chain, head)
	}
	if err != nil {
		return err
	}
	if move.clear {
		err := rawdb.IterateGhostRootHeights(db, func(kind uint8, root common.Hash, _ uint64) error {
			return rawdb.DeleteGhostRootHeight(w, kind, root)
		})
		if err != nil {
			return err
		}
	}
	for k := range move.deletes {
		if err := rawdb.DeleteGhostRootHeight(w, uint8(k.kind), k.root); err != nil {
			return err
		}
	}
	for k, number := range move.writes {
		if err := rawdb.WriteGhostRootHeight(w, uint8(k.kind), k.root, number); err != nil {
			return err
		}
	}
	return rawdb.WriteGhostRootIndexHead(w, head.Number.Uint64(), head.Hash())
}

// parentOf returns the parent header of h, errStaleIndex if it is missing.
func parentOf(chain HeaderLookup, h *types.Header) (*types.Header, error) {
	n := h.Number.Uint64()
	if n == 0 {
		return nil, fmt.Errorf("%w: genesis reached", errStaleIndex)
	}
	parent := chain.GetHeader(h.ParentHash, n-1)
	if parent == nil {
		return nil, fmt.Errorf("%w: header %d %x missing", errStaleIndex, n-1, h.ParentHash)
	}
	return parent, nil
}

// planIndexMove works out the change from the stored index to head's
// ancestry, walking the indexed chain and head's branch down to their common
// ancestor. A stored index that does not fit the chain is errStaleIndex.
func planIndexMove(db RootIndexStore, chain HeaderLookup, head *types.Header) (*indexMove, error) {
	number, hash, ok, err := rawdb.ReadGhostRootIndexHead(db)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: no index head", errStaleIndex)
	}
	old := chain.GetHeader(hash, number)
	if old == nil {
		return nil, fmt.Errorf("%w: indexed head %d %x missing", errStaleIndex, number, hash)
	}
	move := &indexMove{deletes: make(map[rootKey]bool), writes: make(map[rootKey]uint64)}
	added := make(map[rootKey]uint64)

	// A block leaving the chain takes the entries that start at it.
	disconnect := func(h *types.Header) error {
		n := h.Number.Uint64()
		for _, kind := range indexKinds {
			r := HeaderRoot(h, kind)
			if r == nil {
				continue
			}
			stored, found, err := rawdb.ReadGhostRootHeight(db, uint8(kind), *r)
			if err != nil {
				return err
			}
			if !found || stored > n {
				return fmt.Errorf("%w: no entry of the %v root of block %d", errStaleIndex, kind, n)
			}
			if stored == n {
				move.deletes[rootKey{kind, *r}] = true
			}
		}
		return nil
	}
	// The new branch is walked from the top, so the last height kept for a
	// root is its lowest on the branch.
	connect := func(h *types.Header) {
		for _, kind := range indexKinds {
			if r := HeaderRoot(h, kind); r != nil {
				added[rootKey{kind, *r}] = h.Number.Uint64()
			}
		}
	}
	cur := head
	for old.Number.Uint64() > cur.Number.Uint64() {
		if err := disconnect(old); err != nil {
			return nil, err
		}
		if old, err = parentOf(chain, old); err != nil {
			return nil, err
		}
	}
	for cur.Number.Uint64() > old.Number.Uint64() {
		connect(cur)
		if cur, err = parentOf(chain, cur); err != nil {
			return nil, err
		}
	}
	for old.Hash() != cur.Hash() {
		if err := disconnect(old); err != nil {
			return nil, err
		}
		connect(cur)
		if old, err = parentOf(chain, old); err != nil {
			return nil, err
		}
		if cur, err = parentOf(chain, cur); err != nil {
			return nil, err
		}
	}
	fork := cur.Number.Uint64()

	// A root of the new branch keeps an entry at or below the fork point;
	// otherwise its entry is its lowest height on the branch.
	for k, n := range added {
		if !move.deletes[k] {
			stored, found, err := rawdb.ReadGhostRootHeight(db, uint8(k.kind), k.root)
			if err != nil {
				return nil, err
			}
			if found && stored <= fork {
				continue
			}
			if found {
				return nil, fmt.Errorf("%w: entry of a %v root at %d above the fork point %d", errStaleIndex, k.kind, stored, fork)
			}
		}
		delete(move.deletes, k)
		move.writes[k] = n
	}
	return move, nil
}

// planIndexRebuild works out the whole index of head's ancestry.
func planIndexRebuild(chain HeaderLookup, head *types.Header) (*indexMove, error) {
	move := &indexMove{clear: true, writes: make(map[rootKey]uint64)}
	for cur := head; ; {
		for _, kind := range indexKinds {
			if r := HeaderRoot(cur, kind); r != nil {
				move.writes[rootKey{kind, *r}] = cur.Number.Uint64()
			}
		}
		if cur.Number.Uint64() == 0 {
			return move, nil
		}
		parent := chain.GetHeader(cur.ParentHash, cur.Number.Uint64()-1)
		if parent == nil {
			return nil, fmt.Errorf("%w: header %d %x missing", ErrRootLookup, cur.Number.Uint64()-1, cur.ParentHash)
		}
		cur = parent
	}
}
