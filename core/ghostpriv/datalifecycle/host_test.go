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

package datalifecycle

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
)

// host is the test-local stand-in for the off-chain host: an in-memory store
// of ciphertexts under the locators wallets choose. It never sees a key and
// cannot tell one wallet's ciphertext from another's. A test can make it
// answer wrongly or lose everything.
type host struct {
	blobs map[common.Hash][]byte
}

func newHost() *host { return &host{blobs: make(map[common.Hash][]byte)} }

func (h *host) put(locator common.Hash, ciphertext []byte) {
	h.blobs[locator] = common.CopyBytes(ciphertext)
}

func (h *host) get(locator common.Hash) ([]byte, bool) {
	c, ok := h.blobs[locator]
	return common.CopyBytes(c), ok
}

// wipe deletes every ciphertext: the host is lost.
func (h *host) wipe() { clear(h.blobs) }

// all is every ciphertext the host keeps.
func (h *host) all() [][]byte {
	var out [][]byte
	for _, c := range h.blobs {
		out = append(out, common.CopyBytes(c))
	}
	return out
}

// noteRecord is a data commit read from a receipt: where the leaf went, the
// leaf and its note.
type noteRecord struct {
	tree     uint32
	position uint32
	leaf     common.Hash
	note     [ghostpriv.NoteSize]byte
	block    uint64
}

// The data tree's receipt logs.
var (
	dataTreeAccount = ghosttree.TreeAccount(ghosttree.Data)
	dataCommitTopic = ghosttree.K(ghostpriv.TagDataCommitReceipt)
	dataRevealTopic = ghosttree.K(ghostpriv.TagDataRevealReceipt)
)

const (
	dataCommitLogSize = 8 + 32 + ghostpriv.NoteSize + ghostpriv.SaltSize
	dataRevealLogSize = 1 + 20
)

// parseDataCommitLog reads a data commit log; ok is false for any other log.
func parseDataCommitLog(t *testing.T, l *types.Log) (noteRecord, bool) {
	t.Helper()
	if l.Address != dataTreeAccount || len(l.Topics) == 0 || l.Topics[0] != dataCommitTopic {
		return noteRecord{}, false
	}
	if len(l.Topics) != 1 || len(l.Data) != dataCommitLogSize {
		t.Fatalf("data commit log of %d topics and %d bytes in block %d", len(l.Topics), len(l.Data), l.BlockNumber)
	}
	rec := noteRecord{
		tree:     binary.BigEndian.Uint32(l.Data[0:4]),
		position: binary.BigEndian.Uint32(l.Data[4:8]),
		leaf:     common.BytesToHash(l.Data[8:40]),
		block:    l.BlockNumber,
	}
	copy(rec.note[:], l.Data[40:])
	return rec, true
}

// dataRevealLog is a data reveal read from a receipt.
type dataRevealLog struct {
	marker   common.Hash
	purpose  byte
	verifier common.Address
	block    uint64
}

// parseDataRevealLog reads a data reveal log; ok is false for any other log.
func parseDataRevealLog(t *testing.T, l *types.Log) (dataRevealLog, bool) {
	t.Helper()
	if l.Address != dataTreeAccount || len(l.Topics) == 0 || l.Topics[0] != dataRevealTopic {
		return dataRevealLog{}, false
	}
	if len(l.Topics) != 2 || len(l.Data) != dataRevealLogSize {
		t.Fatalf("data reveal log of %d topics and %d bytes in block %d", len(l.Topics), len(l.Data), l.BlockNumber)
	}
	return dataRevealLog{
		marker:   l.Topics[1],
		purpose:  l.Data[0],
		verifier: common.BytesToAddress(l.Data[1:]),
		block:    l.BlockNumber,
	}, true
}

// endpoint is the test-local stand-in for the chain endpoint a wallet asks:
// it answers from one node's canonical chain and offers only bulk requests,
// every data note and the whole data marker set, so no request can name one
// commitment, position or marker. It logs every request it serves.
type endpoint struct {
	t        *testing.T
	n        *node
	requests []string

	// alter, if set, changes the notes before they are served, for a test of
	// a wrong answer.
	alter func([]noteRecord) []noteRecord

	// at, if set, is the canonical block the endpoint answers for; else its
	// node's head.
	at *types.Header
}

func newEndpoint(t *testing.T, n *node) *endpoint { return &endpoint{t: t, n: n} }

func (ep *endpoint) header() *types.Header {
	if ep.at != nil {
		return ep.at
	}
	return ep.n.head()
}

// notes serves every data commit of the canonical chain. The endpoint checks
// its own answer: positions in tree 0 in order, and a data tree root from
// the receipts equal to the head's and the head state's.
func (ep *endpoint) notes() []noteRecord {
	t := ep.t
	t.Helper()
	ep.requests = append(ep.requests, "notes")
	head := ep.header()
	var out []noteRecord
	ep.eachLog(head, func(l *types.Log) {
		if rec, ok := parseDataCommitLog(t, l); ok {
			if rec.tree != 0 || rec.position != uint32(len(out)) {
				t.Fatalf("node %s: data leaf at %d/%d, want 0/%d", ep.n.name, rec.tree, rec.position, len(out))
			}
			out = append(out, rec)
		}
	})
	leaves := make([]common.Hash, len(out))
	for i, rec := range out {
		leaves[i] = rec.leaf
	}
	fromReceipts := ghosttree.RootFromPageRoots(ghosttree.Data, pageRoots(leaves))
	fromState, err := ghosttree.Root(ep.n.stateAt(head), ghosttree.Data)
	if err != nil {
		t.Fatal(err)
	}
	if fromReceipts != *head.DataTreeRoot || fromState != *head.DataTreeRoot {
		t.Fatalf("node %s: data tree root %x from the receipts, %x from the state, %x in the head", ep.n.name, fromReceipts, fromState, *head.DataTreeRoot)
	}
	if ep.alter != nil {
		out = ep.alter(out)
	}
	return out
}

// markers serves the whole data marker set of the canonical chain, read from
// the receipts and checked against the head state.
func (ep *endpoint) markers() map[common.Hash]bool {
	t := ep.t
	t.Helper()
	ep.requests = append(ep.requests, "markers")
	head := ep.header()
	st := ep.n.stateAt(head)
	set := make(map[common.Hash]bool)
	ep.eachLog(head, func(l *types.Log) {
		if r, ok := parseDataRevealLog(t, l); ok {
			if set[r.marker] {
				t.Fatalf("node %s: data marker %x spent twice", ep.n.name, r.marker)
			}
			if !ghosttree.IsSpent(st, ghosttree.Data, r.marker) {
				t.Fatalf("node %s: data marker %x in a receipt but not spent in the head state", ep.n.name, r.marker)
			}
			set[r.marker] = true
		}
	})
	return set
}

// eachLog walks the logs of the canonical blocks up to head.
func (ep *endpoint) eachLog(head *types.Header, fn func(*types.Log)) {
	t := ep.t
	t.Helper()
	for num := uint64(1); num <= head.Number.Uint64(); num++ {
		block := ep.n.chain.GetBlockByNumber(num)
		if block == nil {
			t.Fatalf("node %s: no canonical block %d", ep.n.name, num)
		}
		for _, receipt := range ep.n.chain.GetReceiptsByHash(block.Hash()) {
			if receipt.Status != types.ReceiptStatusSuccessful {
				continue
			}
			for _, l := range receipt.Logs {
				fn(l)
			}
		}
	}
}

// pageRoots is the page-root list of the data tree's leaves.
func pageRoots(leaves []common.Hash) []common.Hash {
	var roots []common.Hash
	for p := 0; p < len(leaves); p += ghosttree.PageLeaves {
		roots = append(roots, ghosttree.PageRoot(ghosttree.Data, leaves[p:min(p+ghosttree.PageLeaves, len(leaves))]))
	}
	return roots
}

// witness is the membership path of the leaf at position among notes.
func witness(t *testing.T, notes []noteRecord, position uint32) [32]common.Hash {
	t.Helper()
	leaves := make([]common.Hash, len(notes))
	for i, rec := range notes {
		leaves[i] = rec.leaf
	}
	page := int(position) / ghosttree.PageLeaves * ghosttree.PageLeaves
	path, err := ghosttree.Witness(ghosttree.Data, position, leaves[page:min(page+ghosttree.PageLeaves, len(leaves))], pageRoots(leaves))
	if err != nil {
		t.Fatalf("witness of position %d: %v", position, err)
	}
	return path
}
