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
)

// Pages of spec 05, section 8: tree data is served in whole pages of
// consecutive positions, and a wallet checks them against the header root
// through the page-root list.
const (
	PageLeaves = 4096 // positions per page, a constant of the protocol
	NoteBytes  = 156  // bytes of the note stored with each leaf

	// PageLevels is the number of node levels inside a page: the page root
	// is the level-11 node, Z_12 for an empty page.
	PageLevels = 12
)

var (
	// ErrPageMismatch is returned when a page's leaves do not hash to the
	// page root of the list.
	ErrPageMismatch = errors.New("page does not match its page root")

	// ErrNotInPage is returned for a witness of a position outside the given
	// page or page-root list.
	ErrNotInPage = errors.New("position not covered by the page data")
)

// pagesPerTree is the number of pages of a full tree, 2^(Depth-12).
func (p Params) pagesPerTree() uint64 { return p.capacity() / PageLeaves }

func (p Params) pageable() error {
	if err := p.usable(); err != nil {
		return err
	}
	if p.Depth < PageLevels {
		return fmt.Errorf("%w: depth %d below a page", ErrDepth, p.Depth)
	}
	return nil
}

// up replaces the nodes at height l, in place, by the nodes above them,
// padding an odd last node with the empty subtree Z_l.
func up(kind Kind, z []common.Hash, l int, cur []common.Hash) []common.Hash {
	n := (len(cur) + 1) / 2
	for i := 0; i < n; i++ {
		right := z[l]
		if 2*i+1 < len(cur) {
			right = cur[2*i+1]
		}
		cur[i] = node(kind, l, cur[2*i], right)
	}
	return cur[:n]
}

// fold hashes nodes, which sit at height from, up by levels levels, and
// returns the single node on top.
func fold(kind Kind, z []common.Hash, from, levels int, nodes []common.Hash) common.Hash {
	if len(nodes) == 0 {
		return z[from+levels]
	}
	cur := append([]common.Hash(nil), nodes...)
	for l := from; l < from+levels; l++ {
		cur = up(kind, z, l, cur)
	}
	return cur[0]
}

// PageRoot returns the level-11 node over a page of the kind whose first
// positions hold leaves and the rest the empty leaf. It returns the zero
// hash, which is no root, for an unknown kind or more than PageLeaves leaves.
func PageRoot(kind Kind, leaves []common.Hash) common.Hash {
	if !kind.valid() || len(leaves) > PageLeaves {
		return common.Hash{}
	}
	return fold(kind, Release.zeros(kind), 0, PageLevels, leaves)
}

// RootFromPageRoots returns the root of a tree of the kind from its page-root
// list alone: the 20 levels above the pages, with Z_12 for every page past
// the list. It returns the zero hash for an unknown kind or a list longer
// than a tree's pages.
func RootFromPageRoots(kind Kind, roots []common.Hash) common.Hash {
	return rootFromPageRoots(Release, kind, roots)
}

func rootFromPageRoots(p Params, kind Kind, roots []common.Hash) common.Hash {
	if !kind.valid() || p.pageable() != nil || uint64(len(roots)) > p.pagesPerTree() {
		return common.Hash{}
	}
	return fold(kind, p.zeros(kind), PageLevels, p.Depth-PageLevels, roots)
}

// siblingsOf appends the siblings of index on the way from nodes, at height
// from, up by levels levels.
func siblingsOf(kind Kind, z []common.Hash, from, levels int, nodes []common.Hash, index uint64, out []common.Hash) []common.Hash {
	cur := append([]common.Hash(nil), nodes...)
	for l := from; l < from+levels; l++ {
		if s := index ^ 1; s < uint64(len(cur)) {
			out = append(out, cur[s])
		} else {
			out = append(out, z[l])
		}
		cur = up(kind, z, l, cur)
		index >>= 1
	}
	return out
}

// Witness builds the path of the leaf at position the way a wallet does,
// from data it downloaded and checked: the 12 siblings inside the page from
// page, the leaves of the position's page, and the 20 above it from roots,
// the page-root list. The page must hash to its entry of the list. The path
// verifies with VerifyMembership.
func Witness(kind Kind, position uint32, page []common.Hash, roots []common.Hash) ([32]common.Hash, error) {
	var path [32]common.Hash
	if !kind.valid() {
		return path, ErrUnknownKind
	}
	pageNo, offset := uint64(position)/PageLeaves, uint64(position)%PageLeaves
	if pageNo >= uint64(len(roots)) || uint64(len(roots)) > Release.pagesPerTree() {
		return path, fmt.Errorf("%w: page %d of a list of %d", ErrNotInPage, pageNo, len(roots))
	}
	if offset >= uint64(len(page)) || len(page) > PageLeaves {
		return path, fmt.Errorf("%w: offset %d of a page of %d leaves", ErrNotInPage, offset, len(page))
	}
	if PageRoot(kind, page) != roots[pageNo] {
		return path, fmt.Errorf("%w: page %d", ErrPageMismatch, pageNo)
	}
	z := Release.zeros(kind)
	siblings := siblingsOf(kind, z, 0, PageLevels, page, offset, make([]common.Hash, 0, Release.Depth))
	siblings = siblingsOf(kind, z, PageLevels, Release.Depth-PageLevels, roots, pageNo, siblings)
	copy(path[:], siblings)
	return path, nil
}
