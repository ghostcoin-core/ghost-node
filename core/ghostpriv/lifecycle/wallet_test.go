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

package lifecycle

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// The wallet here is a stand-in for the real one, whose key derivation is
// not reimplemented: a seed, the digits, gives each commitment number i a
// fingerprint F_i, a reveal secret r_i and a blinding b_i under test tags.
// The marker is K("ghost/coin-marker/v1", r_i, b_i) and the commitment
// K("ghost/coin-commitment/v1", COIN, F_i, v). The note carries v masked
// under the digits and a check value, so only the wallet can read it.
const (
	tagFingerprint = "ghost/test-wallet/fingerprint/v1"
	tagRevealKey   = "ghost/test-wallet/reveal-secret/v1"
	tagBlinding    = "ghost/test-wallet/blinding/v1"
	tagNoteMask    = "ghost/test-wallet/note-mask/v1"
	tagNoteCheck   = "ghost/test-wallet/note-check/v1"
	tagMarker      = "ghost/coin-marker/v1"

	// gapLimit is the number of unused commitment numbers after which a
	// restore stops looking.
	gapLimit = 3
)

type wallet struct {
	digits string
}

func newWallet(digits string) *wallet { return &wallet{digits: digits} }

func (w *wallet) secret(tag string, i int) common.Hash {
	return ghosttree.K(tag, []byte(w.digits), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

func (w *wallet) fingerprint(i int) common.Hash { return w.secret(tagFingerprint, i) }

func (w *wallet) marker(i int) common.Hash {
	r, b := w.secret(tagRevealKey, i), w.secret(tagBlinding, i)
	return ghosttree.K(tagMarker, r[:], b[:])
}

// note is the note of commitment i with value v: v masked, then the check
// value, then zeros.
func (w *wallet) note(i int, v *uint256.Int) [ghostpriv.NoteSize]byte {
	var note [ghostpriv.NoteSize]byte
	word, mask, check := v.Bytes32(), w.secret(tagNoteMask, i), w.secret(tagNoteCheck, i)
	for j := range word {
		note[j] = word[j] ^ mask[j]
	}
	copy(note[32:64], check[:])
	return note
}

// openNote reads the value of commitment i from a note, if the note is the
// wallet's note for i.
func (w *wallet) openNote(i int, note [ghostpriv.NoteSize]byte) (*uint256.Int, bool) {
	check := w.secret(tagNoteCheck, i)
	if !bytes.Equal(note[32:64], check[:]) {
		return nil, false
	}
	mask := w.secret(tagNoteMask, i)
	var word [32]byte
	for j := range word {
		word[j] = note[j] ^ mask[j]
	}
	v := new(uint256.Int).SetBytes32(word[:])
	if v.Gt(ghostpriv.VMax) {
		return nil, false
	}
	return v, true
}

func (w *wallet) coin(i int, v *uint256.Int) coin {
	return coin{owner: w, index: i, value: new(uint256.Int).Set(v)}
}

// coin is commitment number index of a wallet, with its value.
type coin struct {
	owner *wallet
	index int
	value *uint256.Int
}

func (c coin) leaf() common.Hash   { return ghostpriv.Commitment(c.owner.fingerprint(c.index), c.value) }
func (c coin) marker() common.Hash { return c.owner.marker(c.index) }

func (c coin) note() [ghostpriv.NoteSize]byte { return c.owner.note(c.index, c.value) }

// newReveal is a reveal of spend that leaves rest, with the stub proof of
// its binding digest on the network's chain.
func newReveal(n *node, spend, rest coin, root common.Hash, recipient common.Address, out, fee *uint256.Int) *ghostpriv.Reveal {
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   n.chain.Config().GetChainID().Uint64(),
		Marker:    spend.marker(),
		Root:      root,
		Remainder: rest.leaf(),
		Recipient: recipient,
		Out:       new(uint256.Int).Set(out),
		Fee:       new(uint256.Int).Set(fee),
		Note:      rest.note(),
	}
	r.Proof = ghostprivtest.Proof(r.BindingDigest(r.ChainID, n.chain.Genesis().Hash()))
	return r
}

// The coin tree's receipt logs.
var (
	coinTreeAccount = ghosttree.TreeAccount(ghosttree.Coin)
	commitTopic     = ghosttree.K(ghostpriv.TagCommitReceipt)
	revealTopic     = ghosttree.K(ghostpriv.TagRevealReceipt)
)

const (
	commitLogSize = 8 + 32 + 32 + ghostpriv.NoteSize
	revealLogSize = 8 + 32 + ghostpriv.NoteSize + 20 + 32
)

// leafLog is an append to the coin tree read from a receipt.
type leafLog struct {
	tree     uint32
	position uint32
	leaf     common.Hash
	note     [ghostpriv.NoteSize]byte
	block    uint64
	commit   bool         // a commit's leaf, else a reveal's remainder
	amount   *uint256.Int // the commit's value
}

// revealLog is a reveal read from a receipt.
type revealLog struct {
	marker    common.Hash
	remainder common.Hash
	recipient common.Address
	out       *uint256.Int
	block     uint64
}

// chainScan is everything the receipts of a node's canonical chain say
// about the coin tree.
type chainScan struct {
	head    *types.Header
	leaves  []leafLog
	reveals map[common.Hash]revealLog
}

// parseCoinLog reads a coin tree log; ok is false for a log of another
// account.
func parseCoinLog(t *testing.T, l *types.Log) (leaf leafLog, reveal *revealLog, ok bool) {
	t.Helper()
	if l.Address != coinTreeAccount {
		return leafLog{}, nil, false
	}
	if len(l.Topics) == 0 {
		t.Fatalf("coin tree log without a topic in block %d", l.BlockNumber)
	}
	d := l.Data
	switch l.Topics[0] {
	case commitTopic:
		if len(l.Topics) != 1 || len(d) != commitLogSize {
			t.Fatalf("commit log of %d topics and %d bytes in block %d", len(l.Topics), len(d), l.BlockNumber)
		}
		leaf = leafLog{
			tree:     binary.BigEndian.Uint32(d[0:4]),
			position: binary.BigEndian.Uint32(d[4:8]),
			leaf:     common.BytesToHash(d[8:40]),
			commit:   true,
			amount:   new(uint256.Int).SetBytes(d[40:72]),
			block:    l.BlockNumber,
		}
		copy(leaf.note[:], d[72:])
		return leaf, nil, true
	case revealTopic:
		if len(l.Topics) != 2 || len(d) != revealLogSize {
			t.Fatalf("reveal log of %d topics and %d bytes in block %d", len(l.Topics), len(d), l.BlockNumber)
		}
		leaf = leafLog{
			tree:     binary.BigEndian.Uint32(d[0:4]),
			position: binary.BigEndian.Uint32(d[4:8]),
			leaf:     common.BytesToHash(d[8:40]),
			block:    l.BlockNumber,
		}
		copy(leaf.note[:], d[40:40+ghostpriv.NoteSize])
		rest := d[40+ghostpriv.NoteSize:]
		reveal = &revealLog{
			marker:    l.Topics[1],
			remainder: leaf.leaf,
			recipient: common.BytesToAddress(rest[:20]),
			out:       new(uint256.Int).SetBytes(rest[20:]),
			block:     l.BlockNumber,
		}
		return leaf, reveal, true
	default:
		t.Fatalf("coin tree log with unknown topic %x in block %d", l.Topics[0], l.BlockNumber)
	}
	return leafLog{}, nil, false
}

// scan reads the receipts of every canonical block of the node. The leaves
// must come in tree 0 at consecutive positions and no marker may appear
// twice; anything else fails the test.
func scan(t *testing.T, n *node) *chainScan {
	t.Helper()
	s := &chainScan{head: n.head(), reveals: make(map[common.Hash]revealLog)}
	for num := uint64(1); num <= s.head.Number.Uint64(); num++ {
		block := n.chain.GetBlockByNumber(num)
		if block == nil {
			t.Fatalf("node %s: no canonical block %d", n.name, num)
		}
		receipts := n.chain.GetReceiptsByHash(block.Hash())
		if len(receipts) != len(block.Transactions()) {
			t.Fatalf("node %s: block %d has %d receipts for %d transactions", n.name, num, len(receipts), len(block.Transactions()))
		}
		for _, receipt := range receipts {
			for _, l := range receipt.Logs {
				leaf, reveal, ok := parseCoinLog(t, l)
				if !ok {
					continue
				}
				if receipt.Status != types.ReceiptStatusSuccessful {
					t.Fatalf("node %s: coin tree log in a failed receipt of block %d", n.name, num)
				}
				if leaf.tree != 0 || leaf.position != uint32(len(s.leaves)) {
					t.Fatalf("node %s: leaf at tree %d position %d in block %d, want tree 0 position %d", n.name, leaf.tree, leaf.position, num, len(s.leaves))
				}
				s.leaves = append(s.leaves, leaf)
				if reveal != nil {
					if prev, dup := s.reveals[reveal.marker]; dup {
						t.Fatalf("node %s: marker %x revealed in block %d and again in block %d", n.name, reveal.marker, prev.block, num)
					}
					s.reveals[reveal.marker] = *reveal
				}
			}
		}
	}
	return s
}

func (s *chainScan) leafHashes() []common.Hash {
	hashes := make([]common.Hash, len(s.leaves))
	for i, l := range s.leaves {
		hashes[i] = l.leaf
	}
	return hashes
}

// pageRoots is the page-root list of the leaves.
func (s *chainScan) pageRoots() []common.Hash {
	hashes := s.leafHashes()
	var roots []common.Hash
	for p := 0; p < len(hashes); p += ghosttree.PageLeaves {
		roots = append(roots, ghosttree.PageRoot(ghosttree.Coin, hashes[p:min(p+ghosttree.PageLeaves, len(hashes))]))
	}
	return roots
}

// restored is a coin a wallet found again.
type restored struct {
	coin     coin
	position uint32
	block    uint64
	spent    bool
}

// restore finds a wallet's coins from its digits and the node's chain alone.
// It reads the coins and the marker status from the receipts, then checks
// the same answer from the head state: the leaf count, the coin tree root,
// the membership of every coin found, and ghosttree.IsSpent for every
// marker. Any disagreement fails the test.
func restore(t *testing.T, n *node, w *wallet) []restored {
	t.Helper()
	s := scan(t, n)
	st := n.stateAt(s.head)

	// The tree the receipts describe is the tree of the head.
	if count := leafCount(st); count != uint64(len(s.leaves)) {
		t.Fatalf("node %s: %d leaves in the receipts, %d in the head state", n.name, len(s.leaves), count)
	}
	if index := st.GetState(coinTreeAccount, ghosttree.Slot(ghosttree.SlotTreeIndex)).Big(); index.Sign() != 0 {
		t.Fatalf("node %s: coin tree index %v, the scan covers tree 0 only", n.name, index)
	}
	roots := s.pageRoots()
	fromReceipts := ghosttree.RootFromPageRoots(ghosttree.Coin, roots)
	fromState, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		t.Fatal(err)
	}
	if fromReceipts != *s.head.CoinTreeRoot || fromState != *s.head.CoinTreeRoot {
		t.Fatalf("node %s: coin tree root %x from the receipts, %x from the state, %x in the head", n.name, fromReceipts, fromState, *s.head.CoinTreeRoot)
	}

	var found []restored
	for i, misses := 0, 0; misses < gapLimit; i++ {
		var match *restored
		for _, l := range s.leaves {
			v, ok := w.openNote(i, l.note)
			if !ok {
				continue
			}
			c := w.coin(i, v)
			if c.leaf() != l.leaf {
				t.Fatalf("node %s: the note at position %d opens for commitment %d, but the leaf is not its commitment", n.name, l.position, i)
			}
			if l.commit && !l.amount.Eq(v) {
				t.Fatalf("node %s: commit at position %d of %v, the note says %v", n.name, l.position, l.amount, v)
			}
			if match != nil {
				t.Fatalf("node %s: commitment %d found at positions %d and %d", n.name, i, match.position, l.position)
			}
			match = &restored{coin: c, position: l.position, block: l.block}
		}
		if match == nil {
			misses++
			continue
		}
		misses = 0
		_, byReceipts := s.reveals[match.coin.marker()]
		byState := ghosttree.IsSpent(st, ghosttree.Coin, match.coin.marker())
		if byReceipts != byState {
			t.Fatalf("node %s: commitment %d spent %v by the receipts, %v by the head state", n.name, i, byReceipts, byState)
		}
		match.spent = byState
		page := int(match.position) / ghosttree.PageLeaves * ghosttree.PageLeaves
		hashes := s.leafHashes()
		path, err := ghosttree.Witness(ghosttree.Coin, match.position, hashes[page:min(page+ghosttree.PageLeaves, len(hashes))], roots)
		if err != nil {
			t.Fatalf("node %s: witness of commitment %d: %v", n.name, i, err)
		}
		if !ghosttree.VerifyMembership(s.head, ghosttree.Coin, match.position, match.coin.leaf(), path) {
			t.Fatalf("node %s: commitment %d is not a member of the head's coin tree", n.name, i)
		}
		found = append(found, *match)
	}
	return found
}

// unspent restores a wallet and returns its unspent coins.
func unspent(t *testing.T, n *node, w *wallet) []restored {
	t.Helper()
	var out []restored
	for _, r := range restore(t, n, w) {
		if !r.spent {
			out = append(out, r)
		}
	}
	return out
}

// requireCurrent restores a wallet on the node and checks that its one
// unspent coin is want.
func requireCurrent(t *testing.T, n *node, w *wallet, want coin) restored {
	t.Helper()
	coins := unspent(t, n, w)
	if len(coins) != 1 {
		t.Fatalf("node %s: %d unspent coins restored, want 1", n.name, len(coins))
	}
	got := coins[0]
	if got.coin.index != want.index || !got.coin.value.Eq(want.value) || got.coin.leaf() != want.leaf() {
		t.Fatalf("node %s: restored commitment %d of %v, want %d of %v", n.name, got.coin.index, got.coin.value, want.index, want.value)
	}
	return got
}

// requireNothingUnspent restores a wallet on the node and checks it has no
// unspent coin.
func requireNothingUnspent(t *testing.T, n *node, w *wallet) {
	t.Helper()
	if coins := unspent(t, n, w); len(coins) != 0 {
		t.Fatalf("node %s: %d unspent coins restored, want none; the first is commitment %d of %v", n.name, len(coins), coins[0].coin.index, coins[0].coin.value)
	}
}

// leafCount is the number of leaves in the current coin tree.
func leafCount(st ghosttree.StateDB) uint64 {
	return new(big.Int).SetBytes(st.GetState(coinTreeAccount, ghosttree.Slot(ghosttree.SlotLeafCount)).Bytes()).Uint64()
}
