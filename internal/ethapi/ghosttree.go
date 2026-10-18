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
// page-root lists as of an anchor block, and nothing else.
type GhostAPI struct {
	history *ghosttree.History
}

// NewGhostAPI returns the ghost namespace over a tree history.
func NewGhostAPI(history *ghosttree.History) *GhostAPI {
	return &GhostAPI{history: history}
}

// TreeKind is a tree kind in JSON: "coin" or "data".
type TreeKind ghosttree.Kind

func (k TreeKind) MarshalJSON() ([]byte, error) {
	switch ghosttree.Kind(k) {
	case ghosttree.Coin, ghosttree.Data:
		return json.Marshal(ghosttree.Kind(k).String())
	}
	return nil, ghosttree.ErrUnknownKind
}

func (k *TreeKind) UnmarshalJSON(input []byte) error {
	var s string
	if err := json.Unmarshal(input, &s); err != nil {
		return fmt.Errorf("tree kind must be \"coin\" or \"data\": %w", err)
	}
	switch s {
	case "coin":
		*k = TreeKind(ghosttree.Coin)
	case "data":
		*k = TreeKind(ghosttree.Data)
	default:
		return fmt.Errorf("%w: %q", ghosttree.ErrUnknownKind, s)
	}
	return nil
}

// RPCPageEntry is one filled position of a page.
type RPCPageEntry struct {
	Leaf common.Hash   `json:"leaf"`
	Note hexutil.Bytes `json:"note"`
}

// RPCTreePage is one page of a tree as of an anchor.
type RPCTreePage struct {
	Kind      TreeKind       `json:"kind"`
	TreeIndex hexutil.Uint64 `json:"treeIndex"`
	Page      hexutil.Uint64 `json:"page"`
	Filled    hexutil.Uint64 `json:"filled"`
	Entries   []RPCPageEntry `json:"entries"`
}

var errNoTreeHistory = errors.New("tree history unavailable")

// GetTreePage returns the filled positions of one whole page of a tree as of
// the anchor block, each as leaf and note, and their number. A page past the
// last filled one is empty.
func (api *GhostAPI) GetTreePage(kind TreeKind, treeIndex hexutil.Uint64, page hexutil.Uint64, anchorHash common.Hash) (*RPCTreePage, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	if page > math.MaxUint32 {
		return nil, fmt.Errorf("%w: page %d", ghosttree.ErrPageRange, uint64(page))
	}
	p, err := api.history.Page(ghosttree.Kind(kind), uint64(treeIndex), uint32(page), anchorHash)
	if err != nil {
		return nil, err
	}
	out := &RPCTreePage{
		Kind:      kind,
		TreeIndex: treeIndex,
		Page:      page,
		Filled:    hexutil.Uint64(p.Filled),
		Entries:   make([]RPCPageEntry, len(p.Entries)),
	}
	for i, e := range p.Entries {
		out.Entries[i] = RPCPageEntry{Leaf: e.Leaf, Note: append(hexutil.Bytes(nil), e.Note[:]...)}
	}
	return out, nil
}

// GetPageRoots returns the page roots of a tree as of the anchor block, of
// pages 0 to the last page with a leaf.
func (api *GhostAPI) GetPageRoots(kind TreeKind, treeIndex hexutil.Uint64, anchorHash common.Hash) ([]common.Hash, error) {
	if api.history == nil {
		return nil, errNoTreeHistory
	}
	return api.history.PageRoots(ghosttree.Kind(kind), uint64(treeIndex), anchorHash)
}
