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
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
)

// The history is served in whole pages and whole page-root lists, as of an
// anchor block, and nothing else: no lookup by commitment, position, marker,
// note or transaction, and no witness. A wallet asks for everything from its
// scan start and computes its own witnesses.

var (
	// ErrUnknownAnchor is returned for an anchor block the node does not have.
	ErrUnknownAnchor = errors.New("unknown anchor block")

	// ErrNotCanonical is returned for an anchor off the canonical chain.
	ErrNotCanonical = errors.New("anchor block not canonical")

	// ErrNoHeaderRoot is returned when the header to check against has no
	// tree root of the kind.
	ErrNoHeaderRoot = errors.New("header has no tree root")

	// ErrNoTree is returned for a tree index that has no leaf at the anchor
	// and is not the first.
	ErrNoTree = errors.New("tree index does not exist at the anchor")

	// ErrPageRange is returned for a page number beyond a full tree.
	ErrPageRange = errors.New("page number beyond the tree")

	// ErrRootMismatch is returned when the stored history does not reproduce
	// the header root.
	ErrRootMismatch = errors.New("tree history does not match the header root")
)

// PageEntry is one filled position of a page: the leaf, its note and, for a
// salted commit, its salt (nil for a leaf without one).
type PageEntry struct {
	Leaf common.Hash
	Note [NoteBytes]byte
	Salt *[SaltBytes]byte
}

// TreePage is one page as of an anchor: the filled positions in order from
// the first of the page, and their number.
type TreePage struct {
	Kind      Kind
	TreeIndex uint64
	Page      uint32
	Filled    uint32
	Entries   []PageEntry
}

// MarkerPage is one page of a marker list as of an anchor: the markers spent
// at its positions, in the order the chain spent them.
type MarkerPage struct {
	Kind    Kind
	Index   uint64
	Page    uint32
	Markers []common.Hash
}

// MarkerPage returns one page of the spent markers of a kind (CoinMarkers or
// DataMarkers) as of the anchor block: positions 4096 page to 4096 page +
// 4095 of list index, each list holding as many markers as a tree holds
// leaves, in the order the canonical chain up to the anchor spent them. A
// page past the last marker is empty. No header carries a root of a marker
// list, so the page is checked against the chain instead: the anchor must be
// canonical and applied to a history whose head is canonical, and anything
// else is an error.
func (h *History) MarkerPage(kind Kind, index uint64, page uint32, anchor common.Hash) (*MarkerPage, error) {
	if !kind.IsMarkers() {
		return nil, ErrUnknownKind
	}
	if err := h.p.pageable(); err != nil {
		return nil, err
	}
	if uint64(page) >= h.p.pagesPerTree() {
		return nil, fmt.Errorf("%w: page %d of %d", ErrPageRange, page, h.p.pagesPerTree())
	}
	h.lock.RLock()
	defer h.lock.RUnlock()

	number, _, err := h.canonicalHeader(anchor)
	if err != nil {
		return nil, err
	}
	if err := h.covers(anchor, number); err != nil {
		return nil, err
	}
	count, err := h.countAt(kind, index, number)
	if err != nil {
		return nil, err
	}
	if index > 0 {
		if count == 0 {
			return nil, fmt.Errorf("%w: %v list %d at block %d", ErrNoTree, kind, index, number)
		}
		if before, err := h.countAt(kind, index-1, number); err != nil {
			return nil, err
		} else if before != h.p.capacity() {
			return nil, fmt.Errorf("%w: %v list %d below a list that is not full", ErrCorruptHistory, kind, index)
		}
	}
	out := &MarkerPage{Kind: kind, Index: index, Page: page, Markers: []common.Hash{}}
	first := uint64(page) * PageLeaves
	for pos := first; pos < min(count, first+PageLeaves); pos++ {
		rec, err := h.mustRead(slot{kind, index, uint32(pos)})
		if err != nil {
			return nil, err
		}
		out.Markers = append(out.Markers, rec.leaf)
	}
	return out, nil
}

// treeView is one tree as of an anchor, checked against its header root.
type treeView struct {
	count uint64        // leaves of the tree at the anchor
	roots []common.Hash // page roots of pages 0 to the last with a leaf
}

// Page returns the filled positions of one page of a tree as of the anchor
// block, each as leaf, note and salt. A page past the last filled one is empty.
func (h *History) Page(kind Kind, treeIndex uint64, page uint32, anchor common.Hash) (*TreePage, error) {
	if err := h.p.pageable(); err != nil {
		return nil, err
	}
	if uint64(page) >= h.p.pagesPerTree() {
		return nil, fmt.Errorf("%w: page %d of %d", ErrPageRange, page, h.p.pagesPerTree())
	}
	h.lock.RLock()
	defer h.lock.RUnlock()

	v, err := h.view(kind, treeIndex, anchor)
	if err != nil {
		return nil, err
	}
	out := &TreePage{Kind: kind, TreeIndex: treeIndex, Page: page, Entries: []PageEntry{}}
	if uint64(page) >= uint64(len(v.roots)) {
		return out, nil
	}
	first := uint64(page) * PageLeaves
	end := min(v.count, first+PageLeaves)
	leaves := make([]common.Hash, 0, end-first)
	for pos := first; pos < end; pos++ {
		rec, err := h.mustRead(slot{kind, treeIndex, uint32(pos)})
		if err != nil {
			return nil, err
		}
		out.Entries = append(out.Entries, PageEntry{Leaf: rec.leaf, Note: rec.note, Salt: rec.salt})
		leaves = append(leaves, rec.leaf)
	}
	if PageRoot(kind, leaves) != v.roots[page] {
		return nil, fmt.Errorf("%w: %v tree %d page %d", ErrPageMismatch, kind, treeIndex, page)
	}
	out.Filled = uint32(len(out.Entries))
	return out, nil
}

// PageRoots returns the page roots of a tree as of the anchor block, of pages
// 0 to the last page with a leaf; an empty tree has none.
func (h *History) PageRoots(kind Kind, treeIndex uint64, anchor common.Hash) ([]common.Hash, error) {
	if err := h.p.pageable(); err != nil {
		return nil, err
	}
	h.lock.RLock()
	defer h.lock.RUnlock()

	v, err := h.view(kind, treeIndex, anchor)
	if err != nil {
		return nil, err
	}
	return v.roots, nil
}

// view finds the leaf count of a tree at a canonical anchor, builds its page
// roots and checks them against the header root: the anchor's, or for a tree
// that filled before the anchor and was followed by the next index, the root
// of the block that filled it.
func (h *History) view(kind Kind, treeIndex uint64, anchor common.Hash) (*treeView, error) {
	if !kind.valid() {
		return nil, ErrUnknownKind
	}
	number, header, err := h.canonicalHeader(anchor)
	if err != nil {
		return nil, err
	}
	count, err := h.countAt(kind, treeIndex, number)
	if err != nil {
		return nil, err
	}
	if count == 0 && treeIndex > 0 {
		return nil, fmt.Errorf("%w: %v tree %d at block %d", ErrNoTree, kind, treeIndex, number)
	}
	if count == h.p.capacity() && treeIndex < math.MaxUint64 {
		next, err := h.countAt(kind, treeIndex+1, number)
		if err != nil {
			return nil, err
		}
		if next > 0 {
			last, err := h.mustRead(slot{kind, treeIndex, h.lastPosition()})
			if err != nil {
				return nil, err
			}
			hash := rawdb.ReadCanonicalHash(h.db, last.number)
			if _, header, err = h.canonicalHeader(hash); err != nil {
				return nil, fmt.Errorf("block %d that filled %v tree %d: %w", last.number, kind, treeIndex, err)
			}
		}
	}
	want := HeaderRoot(header, kind)
	if want == nil {
		return nil, fmt.Errorf("%w: %v at block %d", ErrNoHeaderRoot, kind, header.Number)
	}
	roots, err := h.pageRoots(kind, treeIndex, count)
	if err != nil {
		return nil, err
	}
	if got := rootFromPageRoots(h.p, kind, roots); got != *want {
		return nil, fmt.Errorf("%w: %v tree %d at block %d: %x, header %x", ErrRootMismatch, kind, treeIndex, header.Number, got, *want)
	}
	return &treeView{count: count, roots: roots}, nil
}

// canonicalHeader returns the number and header of a block on the canonical
// chain.
func (h *History) canonicalHeader(hash common.Hash) (uint64, *types.Header, error) {
	number := rawdb.ReadHeaderNumber(h.db, hash)
	if number == nil {
		return 0, nil, fmt.Errorf("%w: %x", ErrUnknownAnchor, hash)
	}
	if rawdb.ReadCanonicalHash(h.db, *number) != hash {
		return 0, nil, fmt.Errorf("%w: %x at %d", ErrNotCanonical, hash, *number)
	}
	header := rawdb.ReadHeader(h.db, hash, *number)
	if header == nil {
		return 0, nil, fmt.Errorf("%w: header %x", ErrUnknownAnchor, hash)
	}
	return *number, header, nil
}

// countAt returns the number of leaves of a tree at block number: the length
// of the prefix of stored positions appended at or before it. ApplyBlock
// keeps the stored positions of a tree contiguous from 0 and their block
// numbers non-decreasing, so a binary search finds it.
func (h *History) countAt(kind Kind, treeIndex, number uint64) (uint64, error) {
	lo, hi := uint64(0), h.p.capacity()
	for lo < hi {
		mid := lo + (hi-lo)/2
		rec, err := h.read(slot{kind, treeIndex, uint32(mid)})
		if err != nil {
			return 0, err
		}
		if rec != nil && rec.number <= number {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo, nil
}

// pageRoots returns the page roots of a tree with count leaves, from the
// stored roots of full pages and the leaves of the last partial page.
func (h *History) pageRoots(kind Kind, treeIndex, count uint64) ([]common.Hash, error) {
	pages := (count + PageLeaves - 1) / PageLeaves
	roots := make([]common.Hash, 0, pages)
	for pg := uint64(0); pg < pages; pg++ {
		first := pg * PageLeaves
		end := min(count, first+PageLeaves)
		if end-first == PageLeaves {
			root, ok, err := rawdb.ReadGhostTreePageRoot(h.db, uint8(kind), treeIndex, uint32(pg))
			if err != nil {
				return nil, err
			}
			if ok {
				roots = append(roots, root)
				continue
			}
		}
		leaves := make([]common.Hash, 0, end-first)
		for pos := first; pos < end; pos++ {
			rec, err := h.mustRead(slot{kind, treeIndex, uint32(pos)})
			if err != nil {
				return nil, err
			}
			leaves = append(leaves, rec.leaf)
		}
		roots = append(roots, PageRoot(kind, leaves))
	}
	return roots, nil
}

// mustRead returns the stored record at a slot below the leaf count, which
// must be there.
func (h *History) mustRead(s slot) (*stored, error) {
	rec, err := h.read(s)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: %v tree %d position %d missing", ErrCorruptHistory, s.kind, s.treeIndex, s.position)
	}
	return rec, nil
}
