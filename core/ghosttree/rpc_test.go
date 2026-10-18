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

package ghosttree_test

import (
	"encoding/binary"
	"math/big"
	"reflect"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
)

func exportedMethods(v interface{}) []string {
	typ := reflect.TypeOf(v)
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	slices.Sort(names)
	return names
}

func rpcLeaf(i int) common.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return ghosttree.K("ghost/test-rpc-leaf", b[:])
}

// rpcFixture is a two-block header chain whose block 1 appends 5,000 coin
// leaves, with its history, served over an in-process RPC server.
func rpcFixture(t *testing.T) (*rpc.Client, *types.Header) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	history := ghosttree.NewHistory(db)
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	var parent common.Hash
	for number := uint64(0); number < 2; number++ {
		var records []ghosttree.Record
		if number == 1 {
			for i := 0; i < 5000; i++ {
				res, err := ghosttree.Append(st, ghosttree.Coin, number, rpcLeaf(i))
				if err != nil {
					t.Fatal(err)
				}
				records = append(records, ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: res.Leaf})
			}
		}
		coin, _ := ghosttree.Root(st, ghosttree.Coin)
		data, _ := ghosttree.Root(st, ghosttree.Data)
		header := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data}
		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, header.Hash(), number)
		if err := history.ApplyBlock(header.Hash(), number, records); err != nil {
			t.Fatal(err)
		}
		parent = header.Hash()
	}
	server := rpc.NewServer()
	if err := server.RegisterName("ghost", ethapi.NewGhostAPI(history)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)
	return client, rawdb.ReadHeader(db, parent, 1)
}

func TestWholePagesOnly(t *testing.T) {
	// The whole surface: pages and page-root lists, and the two calls that
	// keep the store equal to the canonical chain.
	if got, want := exportedMethods(&ghosttree.History{}), []string{"ApplyBlock", "Page", "PageRoots", "RevertBlock"}; !reflect.DeepEqual(got, want) {
		t.Errorf("history methods %v, want %v", got, want)
	}
	if got, want := exportedMethods(&ethapi.GhostAPI{}), []string{"GetPageRoots", "GetTreePage"}; !reflect.DeepEqual(got, want) {
		t.Errorf("ghost namespace methods %v, want %v", got, want)
	}

	client, head := rpcFixture(t)
	anchor := head.Hash()

	var roots []common.Hash
	if err := client.Call(&roots, "ghost_getPageRoots", "coin", "0x0", anchor); err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || ghosttree.RootFromPageRoots(ghosttree.Coin, roots) != *head.CoinTreeRoot {
		t.Fatalf("%d page roots not matching the header", len(roots))
	}
	var scanned []common.Hash
	for p, want := range []uint64{4096, 904, 0, 0} {
		var page ethapi.RPCTreePage
		if err := client.Call(&page, "ghost_getTreePage", "coin", "0x0", hexutil.Uint64(p), anchor); err != nil {
			t.Fatalf("page %d: %v", p, err)
		}
		if uint64(page.Filled) != want || len(page.Entries) != int(want) {
			t.Errorf("page %d: %d filled, %d entries, want %d", p, page.Filled, len(page.Entries), want)
		}
		var leaves []common.Hash
		for _, e := range page.Entries {
			if len(e.Note) != ghosttree.NoteBytes {
				t.Fatalf("page %d: note of %d bytes", p, len(e.Note))
			}
			leaves = append(leaves, e.Leaf)
		}
		if p < len(roots) && ghosttree.PageRoot(ghosttree.Coin, leaves) != roots[p] {
			t.Errorf("page %d does not match its page root", p)
		}
		scanned = append(scanned, leaves...)
	}
	for i, leaf := range scanned {
		if leaf != rpcLeaf(i) {
			t.Fatalf("position %d: %x", i, leaf)
		}
	}
	var empty []common.Hash
	if err := client.Call(&empty, "ghost_getPageRoots", "data", "0x0", anchor); err != nil || len(empty) != 0 {
		t.Errorf("empty data tree: %v, %v", empty, err)
	}

	// Refused: out of range, trees that do not exist, missing, partial or
	// per-position arguments, and other kinds of key.
	var out interface{}
	for _, c := range []struct {
		name   string
		method string
		args   []interface{}
	}{
		{"page beyond the tree", "ghost_getTreePage", []interface{}{"coin", "0x0", "0x100000", anchor}},
		{"page beyond 32 bits", "ghost_getTreePage", []interface{}{"coin", "0x0", "0x100000000", anchor}},
		{"tree that does not exist", "ghost_getTreePage", []interface{}{"coin", "0x7", "0x0", anchor}},
		{"tree that does not exist, page out of range", "ghost_getTreePage", []interface{}{"coin", "0x7", "0x100000", anchor}},
		{"page roots of a tree that does not exist", "ghost_getPageRoots", []interface{}{"coin", "0x1", anchor}},
		{"no anchor", "ghost_getTreePage", []interface{}{"coin", "0x0", "0x0"}},
		{"no page", "ghost_getTreePage", []interface{}{"coin", "0x0"}},
		{"no arguments", "ghost_getTreePage", nil},
		{"page roots without anchor", "ghost_getPageRoots", []interface{}{"coin", "0x0"}},
		{"a count after the page", "ghost_getTreePage", []interface{}{"coin", "0x0", "0x0", anchor, "0x10"}},
		{"a position after the anchor", "ghost_getPageRoots", []interface{}{"coin", "0x0", anchor, "0x5"}},
		{"a range for the page", "ghost_getTreePage", []interface{}{"coin", "0x0", map[string]string{"from": "0x0", "to": "0x10"}, anchor}},
		{"a list of positions for the page", "ghost_getTreePage", []interface{}{"coin", "0x0", []string{"0x5", "0x6"}, anchor}},
		{"a commitment for the page", "ghost_getTreePage", []interface{}{"coin", "0x0", rpcLeaf(5), anchor}},
		{"a block number for the anchor", "ghost_getTreePage", []interface{}{"coin", "0x0", "0x0", "0x1"}},
		{"unknown anchor", "ghost_getTreePage", []interface{}{"coin", "0x0", "0x0", common.Hash{1}}},
		{"marker kind", "ghost_getTreePage", []interface{}{"marker", "0x0", "0x0", anchor}},
		{"numeric kind", "ghost_getTreePage", []interface{}{0, "0x0", "0x0", anchor}},
		{"lookup by commitment", "ghost_getCommitment", []interface{}{rpcLeaf(5), anchor}},
		{"lookup by position", "ghost_getPosition", []interface{}{"coin", "0x0", "0x5", anchor}},
		{"lookup by note", "ghost_getNote", []interface{}{"coin", "0x0", "0x5", anchor}},
		{"lookup by transaction", "ghost_getTransactionLeaves", []interface{}{common.Hash{2}}},
		{"range of positions", "ghost_getTreeRange", []interface{}{"coin", "0x0", "0x0", "0x10", anchor}},
	} {
		if err := client.Call(&out, c.method, c.args...); err == nil {
			t.Errorf("%s: answered %v", c.name, out)
		}
	}
}
