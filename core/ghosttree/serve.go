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
// anchor block, and in the fixed shapes a restoring wallet reads (spec 05,
// section 8): the tail of a page-root list from a multiple of TailPages, a
// set of PageSetPages pages, and the status of exactly StatusMarkers
// markers. Nothing else: no lookup by commitment, single position, single
// marker, note or transaction, and no witness. A wallet asks for everything
// from its scan start and computes its own witnesses.

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

	// ErrTailStart is returned for a page-root tail whose first page is not
	// a multiple of TailPages below the pages of a full tree.
	ErrTailStart = errors.New("page-root tail must start at a multiple of 65536 pages")

	// ErrPageSetShape is returned for a page set that is not 8 distinct
	// pages of the tree in ascending order, or every page of a tree of 8
	// pages or fewer.
	ErrPageSetShape = errors.New("page set must be 8 distinct pages in order, or every page of a smaller tree")

	// ErrStatusQuery is returned for a marker status query that is not
	// exactly 64 distinct markers.
	ErrStatusQuery = errors.New("marker status query must be exactly 64 distinct markers")
)

const (
	// TailPages is the step of the first page of a page-root tail.
	TailPages = 65536

	// PageSetPages is the number of pages of a page set: one page of the
	// wallet and seven decoys.
	PageSetPages = 8

	// StatusMarkers is the number of markers of a status query.
	StatusMarkers = 64
)

// MarkerStatus is the status of one marker as of an anchor: spent, with the
// number of the block whose reveal spent it, or not (Block 0).
type MarkerStatus struct {
	Spent bool
	Block uint64
}

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
	return h.readPage(kind, treeIndex, page, v)
}

// readPage reads one page of a tree view and checks it against the view's
// page root. The caller holds the lock.
func (h *History) readPage(kind Kind, treeIndex uint64, page uint32, v *treeView) (*TreePage, error) {
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

// PageRootTail returns the page roots of a tree as of the anchor block from
// page start to the last page with a leaf, checked like PageRoots: the whole
// list must reproduce the header root. start must be a multiple of TailPages
// below the pages of a full tree; a start past the last page gives an empty
// list. The tail is at most the page-root list of a full tree.
func (h *History) PageRootTail(kind Kind, treeIndex uint64, start uint32, anchor common.Hash) ([]common.Hash, error) {
	if !kind.valid() {
		return nil, ErrUnknownKind
	}
	if err := h.p.pageable(); err != nil {
		return nil, err
	}
	if start%TailPages != 0 || uint64(start) >= h.p.pagesPerTree() {
		return nil, fmt.Errorf("%w: page %d", ErrTailStart, start)
	}
	h.lock.RLock()
	defer h.lock.RUnlock()

	v, err := h.view(kind, treeIndex, anchor)
	if err != nil {
		return nil, err
	}
	if uint64(start) >= uint64(len(v.roots)) {
		return []common.Hash{}, nil
	}
	return v.roots[start:], nil
}

// PageSet returns whole pages of a tree as of the anchor block, each read
// and checked against its page root as Page does, all from one view of the
// tree. The tree must have a leaf at the anchor. A tree of PageSetPages
// pages or fewer is asked for every page, 0 to the last, in order; a larger
// one for exactly PageSetPages distinct pages in ascending order, each below
// its page count. Any other shape is ErrPageSetShape, and one that no tree
// accepts is refused before the store is read.
func (h *History) PageSet(kind Kind, treeIndex uint64, pages []uint32, anchor common.Hash) ([]*TreePage, error) {
	if !kind.valid() {
		return nil, ErrUnknownKind
	}
	if err := h.p.pageable(); err != nil {
		return nil, err
	}
	if len(pages) == 0 || len(pages) > PageSetPages {
		return nil, fmt.Errorf("%w: %d pages", ErrPageSetShape, len(pages))
	}
	for i, p := range pages {
		if uint64(p) >= h.p.pagesPerTree() || (i > 0 && p <= pages[i-1]) {
			return nil, fmt.Errorf("%w: page %d at %d", ErrPageSetShape, p, i)
		}
	}
	h.lock.RLock()
	defer h.lock.RUnlock()

	v, err := h.view(kind, treeIndex, anchor)
	if err != nil {
		return nil, err
	}
	count := uint64(len(v.roots))
	if count == 0 {
		return nil, fmt.Errorf("%w: %v tree %d has no page", ErrPageSetShape, kind, treeIndex)
	}
	if count <= PageSetPages {
		// Every page of the tree: with the pages ascending from 0, the
		// last is the last page.
		if uint64(len(pages)) != count || pages[0] != 0 || uint64(pages[len(pages)-1]) != count-1 {
			return nil, fmt.Errorf("%w: %d pages asked, the tree has %d", ErrPageSetShape, len(pages), count)
		}
	} else if len(pages) != PageSetPages || uint64(pages[len(pages)-1]) >= count {
		return nil, fmt.Errorf("%w: %d pages up to %d asked, the tree has %d", ErrPageSetShape, len(pages), pages[len(pages)-1], count)
	}
	out := make([]*TreePage, 0, len(pages))
	for _, p := range pages {
		page, err := h.readPage(kind, treeIndex, p, v)
		if err != nil {
			return nil, err
		}
		out = append(out, page)
	}
	return out, nil
}

// MarkerStatus returns, for each of exactly StatusMarkers distinct markers in
// request order, whether the chain up to the anchor block spent it in the
// marker list of a type (Coin reads CoinMarkers, Data reads DataMarkers),
// and the number of the block that did. Each is one lookup in the
// spent-marker index; no list is scanned. The anchor must be canonical and
// applied to a history whose head is canonical and that keeps the index.
// The coin and data lists are separate: a value spent in one is not spent
// in the other.
func (h *History) MarkerStatus(kind Kind, markers []common.Hash, anchor common.Hash) ([]MarkerStatus, error) {
	if !kind.valid() {
		return nil, ErrUnknownKind
	}
	if len(markers) != StatusMarkers {
		return nil, fmt.Errorf("%w: %d markers", ErrStatusQuery, len(markers))
	}
	seen := make(map[common.Hash]bool, len(markers))
	for _, m := range markers {
		if seen[m] {
			return nil, fmt.Errorf("%w: marker %x repeated", ErrStatusQuery, m)
		}
		seen[m] = true
	}
	list := CoinMarkers
	if kind == Data {
		list = DataMarkers
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
	if marked, err := rawdb.ReadGhostTreeMarked(h.db); err != nil {
		return nil, err
	} else if !marked {
		return nil, fmt.Errorf("%w: history without the spent-marker index", ErrHistoryNotReady)
	}
	out := make([]MarkerStatus, len(markers))
	for i, m := range markers {
		index, position, ok, err := rawdb.ReadGhostTreeMarker(h.db, uint8(list), m)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCorruptHistory, err)
		}
		if !ok {
			continue
		}
		rec, err := h.mustRead(slot{list, index, position})
		if err != nil {
			return nil, err
		}
		if rec.leaf != m {
			return nil, fmt.Errorf("%w: %v marker %x indexed at list %d position %d of another", ErrCorruptHistory, list, m, index, position)
		}
		if rec.number <= number {
			out[i] = MarkerStatus{Spent: true, Block: rec.number}
		}
	}
	return out, nil
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
