// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// The values of the genesis Bitcoin-block rule (spec 06, section 8) that the
// section gives as proposed. Each is named here once, so it changes in one
// place; nothing else in the command repeats a value.
const (
	// Confirmations is the depth the selected Bitcoin block must have on the
	// heaviest branch of the given headers, counting the block itself.
	Confirmations = 6

	// MedianTimeBlocks is the number of blocks, ending with a block, whose
	// median timestamp is that block's median time past (Bitcoin's 11).
	MedianTimeBlocks = 11

	// GenesisBlockTime selects the chain preset, by its target seconds
	// between blocks, whose starting difficulty the genesis carries.
	GenesisBlockTime = 30

	// GenesisGasLimit is the gas limit of the genesis block.
	GenesisGasLimit = 30_000_000

	// GenesisOffset is the number of seconds the genesis timestamp lies after
	// the selected block's median time past (spec 06 section 8.3, spec 05
	// section 10).
	GenesisOffset = 6000
)

var (
	// ErrHeaderFile is returned for a header file that is empty or not a
	// whole number of 80-byte headers.
	ErrHeaderFile = errors.New("header file is not a sequence of 80-byte headers")

	// ErrHeaderLink is returned for a header, other than the first, whose
	// previous-block hash names no earlier header of the file.
	ErrHeaderLink = errors.New("header does not link to an earlier header")

	// ErrDuplicateHeader is returned for a header given twice.
	ErrDuplicateHeader = errors.New("header given twice")

	// ErrMedianTime is returned for a header whose timestamp is not above
	// its parent's median time past.
	ErrMedianTime = errors.New("header time is not above its parent's median time past")

	// ErrNotReached is returned when no block of the heaviest branch has a
	// median time past at or above T_L yet.
	ErrNotReached = errors.New("no block's median time past reaches T_L")

	// ErrStartsLate is returned when the headers start too late to show
	// that the selected block's parent is below T_L: the first block at or
	// above T_L has no parent with a known median time past.
	ErrStartsLate = errors.New("headers start too late to show the first block at or above T_L")

	// ErrTooFewConfirmations is returned when the selected block is not yet
	// Confirmations deep.
	ErrTooFewConfirmations = errors.New("selected block has too few confirmations")

	// ErrTiedBranches is returned when branches of equal greatest work do
	// not agree on the selected block.
	ErrTiedBranches = errors.New("branches of equal work disagree on the selected block")
)

// headerNode is a header of the file with what the rule derives for it.
type headerNode struct {
	header *bitcoinHeader
	hash   [32]byte
	parent *headerNode
	index  int      // position in the file
	height int      // Bitcoin height, counted from the checkpoint's
	work   *big.Int // work of the branch from the first header to here
	mtp    uint32   // median time past, valid when hasMTP
	hasMTP bool
}

// headerTree is every header of a file, linked to its parent.
type headerTree struct {
	nodes  []*headerNode
	byHash map[[32]byte]*headerNode
}

// readHeaders decodes and checks a header file of the chain c: the first
// header is c's checkpoint, every header carries proof of work for its own
// bits within c's proof-of-work limit, and each header after the first links
// to an earlier one, has the bits c's difficulty rules require, and has a
// timestamp above its parent's median time past where the file holds enough
// of the parent's ancestry to know it. The checkpoint's own parent is not
// checked.
func readHeaders(c chain, data []byte) (*headerTree, error) {
	if len(data) == 0 || len(data)%BitcoinHeaderSize != 0 {
		return nil, fmt.Errorf("%w: %d bytes", ErrHeaderFile, len(data))
	}
	tree := &headerTree{byHash: make(map[[32]byte]*headerNode)}
	for i := 0; i < len(data)/BitcoinHeaderSize; i++ {
		h, err := decodeBitcoinHeader(data[i*BitcoinHeaderSize : (i+1)*BitcoinHeaderSize])
		if err != nil {
			return nil, err
		}
		n := &headerNode{header: h, hash: h.Hash(), index: i}
		if _, ok := tree.byHash[n.hash]; ok {
			return nil, fmt.Errorf("%w: header %d, block %x", ErrDuplicateHeader, i, Display(n.hash))
		}
		work, err := h.checkProofOfWork(c.powLimit)
		if err != nil {
			return nil, fmt.Errorf("header %d: %w", i, err)
		}
		n.work = work
		if i == 0 {
			if err := c.checkCheckpoint(n); err != nil {
				return nil, err
			}
			n.height = c.checkpointHeight
		} else {
			parent, ok := tree.byHash[h.PrevBlock]
			if !ok {
				return nil, fmt.Errorf("%w: header %d names %x", ErrHeaderLink, i, Display(h.PrevBlock))
			}
			want, err := c.requiredBits(parent)
			if err != nil {
				return nil, fmt.Errorf("header %d: %w", i, err)
			}
			if h.Bits != want {
				return nil, fmt.Errorf("%w: header %d, bits %#08x, want %#08x", ErrDifficulty, i, h.Bits, want)
			}
			if parent.hasMTP && h.Time <= parent.mtp {
				return nil, fmt.Errorf("%w: header %d, time %d, parent's median time past %d", ErrMedianTime, i, h.Time, parent.mtp)
			}
			n.parent = parent
			n.height = parent.height + 1
			n.work.Add(n.work, parent.work)
		}
		n.mtp, n.hasMTP = medianTimePast(n)
		tree.nodes = append(tree.nodes, n)
		tree.byHash[n.hash] = n
	}
	return tree, nil
}

// medianTimePast is the median timestamp of the MedianTimeBlocks blocks
// ending with n, if the file holds all of them.
func medianTimePast(n *headerNode) (uint32, bool) {
	times := make([]uint32, 0, MedianTimeBlocks)
	for b := n; b != nil && len(times) < MedianTimeBlocks; b = b.parent {
		times = append(times, b.header.Time)
	}
	if len(times) < MedianTimeBlocks {
		return 0, false
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times[MedianTimeBlocks/2], true
}

// selection is the Bitcoin block the rule selects.
type selection struct {
	block         *headerNode
	tip           *headerNode // tip of the branch it was selected on
	confirmations int
}

// selectOn applies the selection rule on the branch ending at tip: the
// selected block is the first block whose median time past is at or above
// tl, and it must have Confirmations blocks on the branch, counting itself.
func selectOn(tip *headerNode, tl uint64) (*selection, error) {
	var branch []*headerNode
	for n := tip; n != nil; n = n.parent {
		branch = append(branch, n)
	}
	// branch runs from the tip down; walk it from the first header up.
	for i := len(branch) - 1; i >= 0; i-- {
		n := branch[i]
		if !n.hasMTP || uint64(n.mtp) < tl {
			continue
		}
		if n.parent == nil || !n.parent.hasMTP {
			return nil, fmt.Errorf("%w: block %x at height %d", ErrStartsLate, Display(n.hash), n.height)
		}
		sel := &selection{block: n, tip: tip, confirmations: tip.height - n.height + 1}
		if sel.confirmations < Confirmations {
			return nil, fmt.Errorf("%w: block %x has %d, want %d", ErrTooFewConfirmations, Display(n.hash), sel.confirmations, Confirmations)
		}
		return sel, nil
	}
	return nil, fmt.Errorf("%w: tip %x at height %d", ErrNotReached, Display(tip.hash), tip.height)
}

// selectBlock applies the rule to the headers. The branch with the most
// cumulative work is the one the rule reads; when several tips share the
// greatest work, they must all select the same block, or the headers do not
// settle the choice.
func selectBlock(tree *headerTree, tl uint64) (*selection, error) {
	var best []*headerNode
	for _, n := range tree.nodes {
		switch {
		case len(best) == 0 || n.work.Cmp(best[0].work) > 0:
			best = []*headerNode{n}
		case n.work.Cmp(best[0].work) == 0:
			best = append(best, n)
		}
	}
	sel, err := selectOn(best[0], tl)
	for _, tip := range best[1:] {
		other, otherErr := selectOn(tip, tl)
		if (err == nil) != (otherErr == nil) || (err == nil && other.block != sel.block) {
			return nil, fmt.Errorf("%w: tips %x and %x", ErrTiedBranches, Display(best[0].hash), Display(tip.hash))
		}
	}
	if err != nil {
		return nil, err
	}
	return sel, nil
}
