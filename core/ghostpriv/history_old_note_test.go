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

package ghostpriv_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

// oldCommitLog is the 244-byte receipt log of a salted commit of c made
// before notes were 380 bytes: the location, the leaf, the amount, the first
// 156 bytes of c's note and the salt.
func oldCommitLog(index, position uint32, leaf common.Hash, c coin, salt []byte) []byte {
	short := coin{f: c.f, value: c.value, note: c.note[:156]}
	return append(commitLogOf(index, position, leaf, short), salt...)
}

// TestHistoryRecordsOldNoteCommitLog checks that HistoryRecords reads the
// 244-byte coin commit log of a salted commit made with the old 156-byte note,
// which the test chain still holds (block 1394), as the leaf the block
// appended: its tree index, position, leaf and salt, with the note zero-padded
// on the right to 380 bytes. The history built from such a record serves the
// page roots of the header root, which the leaves alone fix. Logs one byte
// shorter or longer, the unsalted old length, a 381-byte log and the old
// length on the data tree account are still ErrReceiptLog.
func TestHistoryRecordsOldNoteCommitLog(t *testing.T) {
	c := testCoin("old 156-byte note", oneGhost)
	salt := testSalt(0x44)
	leaf := saltedCommitment(c)
	if c.note[155] == 0 || c.note[156] == 0 {
		t.Fatalf("test note %x has a zero byte where the old note ends", c.note[150:160])
	}
	coinAccount := ghosttree.TreeAccount(ghosttree.Coin)
	commitTopics := []common.Hash{ghosttree.K(ghostpriv.TagCommitReceipt)}
	logOf := func(data []byte) *types.Log {
		return &types.Log{Address: coinAccount, Topics: commitTopics, Data: data}
	}

	// One old log on its own, at a tree index and position that show which
	// bytes are read for each.
	data := oldCommitLog(0x01020304, 0x0a0b, leaf, c, salt)
	if len(data) != 244 {
		t.Fatalf("old commit log of %d bytes, want 244", len(data))
	}
	records, err := ghostpriv.HistoryRecords(types.Receipts{{Logs: []*types.Log{logOf(data)}}})
	if err != nil {
		t.Fatalf("old commit log: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("%d records, want 1", len(records))
	}
	r := records[0]
	if r.Kind != ghosttree.Coin {
		t.Errorf("kind %v, want %v", r.Kind, ghosttree.Coin)
	}
	if r.TreeIndex != 0x01020304 || r.Position != 0x0a0b {
		t.Errorf("tree index %#x position %#x, want 0x1020304 and 0xa0b", r.TreeIndex, r.Position)
	}
	if r.Leaf != leaf {
		t.Errorf("leaf %x, want %x", r.Leaf, leaf)
	}
	if len(r.Note) != 380 || !bytes.Equal(r.Note[:156], c.note[:156]) || !bytes.Equal(r.Note[156:], make([]byte, 224)) {
		t.Errorf("note %x, want the 156-byte note and 224 zero bytes", r.Note[:])
	}
	checkSalt(t, "old commit record", r.Salt, salt)

	// A block with a commit of the current layout at position 0 and an old
	// commit at position 1. The coin tree the chain builds from the two
	// leaves gives the header root; the history built from the records
	// serves page roots that rebuild it, and the page carries the old note
	// padded and its salt.
	now, then := testCoin("current note", oneGhost), c
	nowSalt := testSalt(0x45)
	receipts := types.Receipts{
		{Logs: []*types.Log{logOf(append(commitLogOf(0, 0, saltedCommitment(now), now), nowSalt...))}},
		{Logs: []*types.Log{logOf(oldCommitLog(0, 1, leaf, then, salt))}},
	}
	records, err = ghostpriv.HistoryRecords(receipts)
	if err != nil {
		t.Fatalf("block with an old commit log: %v", err)
	}
	if len(records) != 2 || records[0].Leaf != saltedCommitment(now) || records[1].Leaf != leaf || records[1].Position != 1 {
		t.Fatalf("history records %+v", records)
	}

	const number = 1394
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range []common.Hash{saltedCommitment(now), leaf} {
		res, err := ghosttree.Append(st, ghosttree.Coin, number, l)
		if err != nil {
			t.Fatal(err)
		}
		if res.TreeIndex != records[i].TreeIndex || res.Position != records[i].Position {
			t.Fatalf("leaf %d appended at tree %d position %d, record at %d and %d", i, res.TreeIndex, res.Position, records[i].TreeIndex, records[i].Position)
		}
	}
	coinRoot, err := ghosttree.Root(st, ghosttree.Coin)
	if err != nil {
		t.Fatal(err)
	}
	fromLeaves := ghosttree.RootFromPageRoots(ghosttree.Coin, []common.Hash{ghosttree.PageRoot(ghosttree.Coin, []common.Hash{records[0].Leaf, records[1].Leaf})})
	if fromLeaves != coinRoot {
		t.Fatalf("root of the record leaves %x, header root %x", fromLeaves, coinRoot)
	}

	db := rawdb.NewMemoryDatabase()
	history := ghosttree.NewHistory(db)
	dataRoot, err := ghosttree.Root(st, ghosttree.Data)
	if err != nil {
		t.Fatal(err)
	}
	markerRoot, err := ghosttree.DataMarkerRoot(st)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coinRoot, DataTreeRoot: &dataRoot, DataMarkerRoot: &markerRoot}
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, header.Hash(), number)
	if err := history.ApplyBlock(header.Hash(), number, records); err != nil {
		t.Fatalf("apply block with an old commit record: %v", err)
	}
	roots, err := history.PageRoots(ghosttree.Coin, 0, header.Hash())
	if err != nil {
		t.Fatalf("page roots: %v", err)
	}
	if got := ghosttree.RootFromPageRoots(ghosttree.Coin, roots); len(roots) != 1 || got != coinRoot {
		t.Fatalf("%d page roots rebuild %x, header root %x", len(roots), got, coinRoot)
	}
	page, err := history.Page(ghosttree.Coin, 0, 0, header.Hash())
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if page.Filled != 2 {
		t.Fatalf("page of %d entries, want 2", page.Filled)
	}
	if e := page.Entries[1]; e.Leaf != leaf || !bytes.Equal(e.Note[:156], then.note[:156]) || !bytes.Equal(e.Note[156:], make([]byte, 224)) {
		t.Errorf("old commit entry: leaf %x note %x", e.Leaf, e.Note[:])
	}
	checkSalt(t, "old commit entry", page.Entries[1].Salt, salt)
	if e := page.Entries[0]; e.Leaf != saltedCommitment(now) || !bytes.Equal(e.Note[:], now.note) {
		t.Errorf("current commit entry: leaf %x note %x", e.Leaf, e.Note[:])
	}
	checkSalt(t, "current commit entry", page.Entries[0].Salt, nowSalt)

	// No other length is read as an old commit log.
	wrong := []struct {
		name string
		log  *types.Log
	}{
		{"243-byte commit log", logOf(data[:243])},
		{"245-byte commit log", logOf(append(append([]byte{}, data...), 0))},
		{"381-byte commit log", logOf(append(append([]byte{}, data...), make([]byte, 381-244)...))},
		{"228-byte commit log without a salt", logOf(data[:228])},
		{"244-byte log with a second topic", &types.Log{Address: coinAccount, Topics: []common.Hash{commitTopics[0], testMarker("old")}, Data: data}},
		{"212-byte data commit log", &types.Log{
			Address: ghosttree.TreeAccount(ghosttree.Data),
			Topics:  []common.Hash{ghosttree.K(ghostpriv.TagDataCommitReceipt)},
			Data:    append(append(append([]byte{}, data[:40]...), c.note[:156]...), salt...),
		}},
	}
	for _, w := range wrong {
		if _, err := ghostpriv.HistoryRecords(types.Receipts{{Logs: []*types.Log{w.log}}}); !errors.Is(err, ghostpriv.ErrReceiptLog) {
			t.Errorf("%s: %v, want %v", w.name, err, ghostpriv.ErrReceiptLog)
		}
	}
}
