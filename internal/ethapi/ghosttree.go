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

package ethapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// GhostAPI serves the commitment tree history in whole pages and whole
// page-root lists as of an anchor block, the spent markers in whole pages,
// and the fixed-shape reads of a restoring wallet (a page-root tail and a set
// of 8 pages), and nothing else.
type GhostAPI struct {
	history *ghosttree.History
}

// NewGhostAPI returns the ghost namespace over a tree history.
func NewGhostAPI(history *ghosttree.History) *GhostAPI {
	return &GhostAPI{history: history}
}

// TreeKind is a kind in JSON: "coin" or "data" for a tree, "coin-markers" or
// "data-markers" for a list of spent markers.
type TreeKind ghosttree.Kind

func (k TreeKind) MarshalJSON() ([]byte, error) {
	switch ghosttree.Kind(k) {
	case ghosttree.Coin, ghosttree.Data, ghosttree.CoinMarkers, ghosttree.DataMarkers:
		return json.Marshal(ghosttree.Kind(k).String())
	}
	return nil, ghosttree.ErrUnknownKind
}

func (k *TreeKind) UnmarshalJSON(input []byte) error {
	var s string
	if err := json.Unmarshal(input, &s); err != nil {
		return fmt.Errorf("kind must be \"coin\", \"data\", \"coin-markers\" or \"data-markers\": %w", err)
	}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data, ghosttree.CoinMarkers, ghosttree.DataMarkers} {
		if s == kind.String() {
			*k = TreeKind(kind)
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ghosttree.ErrUnknownKind, s)
}

// RPCPageEntry is one filled position of a page. Salt is the 16-byte salt of
// a salted commit, left out for a leaf without one (a version 1 commit, or a
// reveal remainder, whose salt is in its note).
type RPCPageEntry struct {
	Leaf common.Hash   `json:"leaf"`
	Note hexutil.Bytes `json:"note"`
	Salt hexutil.Bytes `json:"salt,omitempty"`
}

// RPCTreePage is one page of a tree as of an anchor.
type RPCTreePage struct {
	Kind      TreeKind       `json:"kind"`
	TreeIndex hexutil.Uint64 `json:"treeIndex"`
	Page      hexutil.Uint64 `json:"page"`
	Filled    hexutil.Uint64 `json:"filled"`
	Entries   []RPCPageEntry `json:"entries"`
}

// RPCMarkerPage is one page of a list of spent markers as of an anchor: the
// markers in the order they were spent, and their number.
type RPCMarkerPage struct {
	Count   hexutil.Uint64 `json:"count"`
	Markers []common.Hash  `json:"markers"`
}

var (
	errNoTreeHistory = errors.New("tree history unavailable")
	errNoMarkerRoots = errors.New("a list of spent markers has no page roots")
)

// GetTreePage returns one whole page as of the anchor block. For a tree kind
// it is the filled positions of the page, each as leaf, note and salt (left
// out for a leaf without one), and their number (RPCTreePage); for a marker kind it is the markers spent at the
// page's positions and their number (RPCMarkerPage). A page past the last
// filled one is empty.
func (api *GhostAPI) GetTreePage(kind TreeKind, treeIndex hexutil.Uint64, page hexutil.Uint64, anchorHash common.Hash) (interface{}, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	if page > math.MaxUint32 {
		return nil, fmt.Errorf("%w: page %d", ghosttree.ErrPageRange, uint64(page))
	}
	if ghosttree.Kind(kind).IsMarkers() {
		p, err := api.history.MarkerPage(ghosttree.Kind(kind), uint64(treeIndex), uint32(page), anchorHash)
		if err != nil {
			return nil, err
		}
		return &RPCMarkerPage{Count: hexutil.Uint64(len(p.Markers)), Markers: p.Markers}, nil
	}
	p, err := api.history.Page(ghosttree.Kind(kind), uint64(treeIndex), uint32(page), anchorHash)
	if err != nil {
		return nil, err
	}
	return rpcTreePage(p), nil
}

// rpcTreePage is a page of a tree in JSON.
func rpcTreePage(p *ghosttree.TreePage) *RPCTreePage {
	out := &RPCTreePage{
		Kind:      TreeKind(p.Kind),
		TreeIndex: hexutil.Uint64(p.TreeIndex),
		Page:      hexutil.Uint64(p.Page),
		Filled:    hexutil.Uint64(p.Filled),
		Entries:   make([]RPCPageEntry, len(p.Entries)),
	}
	for i, e := range p.Entries {
		out.Entries[i] = RPCPageEntry{Leaf: e.Leaf, Note: append(hexutil.Bytes(nil), e.Note[:]...)}
		if e.Salt != nil {
			out.Entries[i].Salt = append(hexutil.Bytes(nil), e.Salt[:]...)
		}
	}
	return out
}

// GetPageRootTail returns the page roots of a tree (kind "coin" or "data")
// as of the anchor block from page start to the last page with a leaf. start
// must be a multiple of 65,536 pages below the pages of a full tree; a start
// past the last page gives an empty list.
func (api *GhostAPI) GetPageRootTail(kind TreeKind, treeIndex hexutil.Uint64, start hexutil.Uint64, anchorHash common.Hash) ([]common.Hash, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	if start > math.MaxUint32 {
		return nil, fmt.Errorf("%w: page %d", ghosttree.ErrTailStart, uint64(start))
	}
	return api.history.PageRootTail(ghosttree.Kind(kind), uint64(treeIndex), uint32(start), anchorHash)
}

// GetPageSet returns whole pages of a tree (kind "coin" or "data") as of the
// anchor block, as ghost_getTreePage returns one: exactly 8 distinct pages in
// ascending order, or every page of a tree of 8 pages or fewer.
func (api *GhostAPI) GetPageSet(kind TreeKind, treeIndex hexutil.Uint64, pages []hexutil.Uint64, anchorHash common.Hash) ([]*RPCTreePage, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	if len(pages) == 0 || len(pages) > ghosttree.PageSetPages {
		return nil, fmt.Errorf("%w: %d pages", ghosttree.ErrPageSetShape, len(pages))
	}
	numbers := make([]uint32, len(pages))
	for i, p := range pages {
		if p > math.MaxUint32 {
			return nil, fmt.Errorf("%w: page %d", ghosttree.ErrPageSetShape, uint64(p))
		}
		numbers[i] = uint32(p)
	}
	set, err := api.history.PageSet(ghosttree.Kind(kind), uint64(treeIndex), numbers, anchorHash)
	if err != nil {
		return nil, err
	}
	out := make([]*RPCTreePage, len(set))
	for i, p := range set {
		out[i] = rpcTreePage(p)
	}
	return out, nil
}

// GetPageRoots returns the page roots of a tree as of the anchor block, of
// pages 0 to the last page with a leaf. A marker list has none.
func (api *GhostAPI) GetPageRoots(kind TreeKind, treeIndex hexutil.Uint64, anchorHash common.Hash) ([]common.Hash, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	if ghosttree.Kind(kind).IsMarkers() {
		return nil, fmt.Errorf("%w: %v", errNoMarkerRoots, ghosttree.Kind(kind))
	}
	return api.history.PageRoots(ghosttree.Kind(kind), uint64(treeIndex), anchorHash)
}
