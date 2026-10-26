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
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
)

func restoreDecoy(i int) common.Hash {
	return crypto.Keccak256Hash([]byte("decoy"), []byte{byte(i)})
}

func TestGhostRestoreReadsOverRPC(t *testing.T) {
	// Block 1 appends 5,000 coin leaves (2 pages) and spends decoy 3 as a
	// coin marker and decoy 9 as a data marker; block 2 is empty. The
	// history is kept by Sync, as a node keeps it.
	db := rawdb.NewMemoryDatabase()
	history := ghosttree.NewHistory(db)
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	records := make(map[common.Hash][]ghosttree.Record)
	var (
		parent  common.Hash
		headers []*types.Header
	)
	for number := uint64(0); number < 3; number++ {
		var recs []ghosttree.Record
		if number == 1 {
			for i := 0; i < 5000; i++ {
				res, err := ghosttree.Append(st, ghosttree.Coin, number, rpcLeaf(i))
				if err != nil {
					t.Fatal(err)
				}
				recs = append(recs, ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: res.Leaf})
			}
			recs = append(recs, ghosttree.Record{Kind: ghosttree.CoinMarkers, Leaf: restoreDecoy(3)}, ghosttree.Record{Kind: ghosttree.DataMarkers, Leaf: restoreDecoy(9)})
		}
		coin, _ := ghosttree.Root(st, ghosttree.Coin)
		data, _ := ghosttree.Root(st, ghosttree.Data)
		marker, _ := ghosttree.DataMarkerRoot(st)
		header := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data, DataMarkerRoot: &marker}
		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, header.Hash(), number)
		records[header.Hash()] = recs
		headers = append(headers, header)
		parent = header.Hash()
	}
	if err := history.Sync(headers[2], func(h *types.Header) ([]ghosttree.Record, error) { return records[h.Hash()], nil }); err != nil {
		t.Fatal(err)
	}
	server := rpc.NewServer()
	if err := server.RegisterName("ghost", ethapi.NewGhostAPI(history)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)
	head := headers[2]
	anchor := head.Hash()

	// The tail from page 0 is the page-root list, as hashes.
	var roots, tail []common.Hash
	if err := client.Call(&roots, "ghost_getPageRoots", "coin", "0x0", anchor); err != nil {
		t.Fatal(err)
	}
	var rawTail []string
	if err := client.Call(&rawTail, "ghost_getPageRootTail", "coin", "0x0", "0x0", anchor); err != nil {
		t.Fatal(err)
	}
	for _, s := range rawTail {
		tail = append(tail, common.HexToHash(s))
		if len(s) != 2+2*common.HashLength {
			t.Errorf("tail root %q", s)
		}
	}
	if len(tail) != 2 || !reflect.DeepEqual(tail, roots) || ghosttree.RootFromPageRoots(ghosttree.Coin, tail) != *head.CoinTreeRoot {
		t.Fatalf("tail %x, page roots %x", tail, roots)
	}
	var empty []common.Hash
	if err := client.Call(&empty, "ghost_getPageRootTail", "coin", "0x0", "0x10000", anchor); err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("tail past the last page: %v, %v", empty, err)
	}

	// The page set of a 2-page tree is both pages, each as ghost_getTreePage
	// serves it.
	var rawSet []map[string]json.RawMessage
	if err := client.Call(&rawSet, "ghost_getPageSet", "coin", "0x0", []string{"0x0", "0x1"}, anchor); err != nil {
		t.Fatal(err)
	}
	if len(rawSet) != 2 {
		t.Fatalf("%d pages in the set", len(rawSet))
	}
	for p, raw := range rawSet {
		for _, field := range []string{"kind", "treeIndex", "page", "filled", "entries"} {
			if raw[field] == nil {
				t.Errorf("set page %d: no field %s", p, field)
			}
		}
		var got, want ethapi.RPCTreePage
		blob, _ := json.Marshal(raw)
		if err := json.Unmarshal(blob, &got); err != nil {
			t.Fatal(err)
		}
		if err := client.Call(&want, "ghost_getTreePage", "coin", "0x0", hexutil.Uint64(p), anchor); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) || int(got.Page) != p {
			t.Errorf("set page %d differs from ghost_getTreePage", p)
		}
	}

	// The status query: decoy 3 is spent as a coin marker in block 1, decoy
	// 9 as a data marker; every other answer is not spent, without a block.
	query := make([]common.Hash, ghosttree.StatusMarkers)
	for i := range query {
		query[i] = restoreDecoy(i)
	}
	for _, c := range []struct {
		kind  string
		spent int
	}{{"coin", 3}, {"data", 9}} {
		var raw []map[string]json.RawMessage
		if err := client.Call(&raw, "ghost_getMarkerStatus", c.kind, query, anchor); err != nil {
			t.Fatalf("%s status: %v", c.kind, err)
		}
		if len(raw) != ghosttree.StatusMarkers {
			t.Fatalf("%s status: %d answers", c.kind, len(raw))
		}
		for i, a := range raw {
			if i == c.spent {
				if len(a) != 2 || string(a["spent"]) != "true" || string(a["block"]) != `"0x1"` {
					t.Errorf("%s status of marker %d: %v, want spent in block 1", c.kind, i, a)
				}
				continue
			}
			if len(a) != 1 || string(a["spent"]) != "false" {
				t.Errorf("%s status of marker %d: %v, want only spent false", c.kind, i, a)
			}
		}
		var typed []ethapi.RPCMarkerStatus
		if err := client.Call(&typed, "ghost_getMarkerStatus", c.kind, query, headers[0].Hash()); err != nil {
			t.Fatal(err)
		}
		for i, s := range typed {
			if s.Spent || s.Block != nil {
				t.Errorf("%s status of marker %d at genesis: %+v", c.kind, i, s)
			}
		}
	}

	// Refused over the wire.
	sevenPages := []string{"0x0", "0x1", "0x2", "0x3", "0x4", "0x5", "0x6"}
	var out interface{}
	for _, c := range []struct {
		name   string
		method string
		args   []interface{}
	}{
		{"tail start 1", "ghost_getPageRootTail", []interface{}{"coin", "0x0", "0x1", anchor}},
		{"tail start beyond 32 bits", "ghost_getPageRootTail", []interface{}{"coin", "0x0", "0x100000000", anchor}},
		{"tail of a marker list", "ghost_getPageRootTail", []interface{}{"coin-markers", "0x0", "0x0", anchor}},
		{"63 markers", "ghost_getMarkerStatus", []interface{}{"coin", query[:63], anchor}},
		{"status of a marker kind", "ghost_getMarkerStatus", []interface{}{"data-markers", query, anchor}},
		{"7-page set", "ghost_getPageSet", []interface{}{"coin", "0x0", sevenPages, anchor}},
		{"one page of a 2-page tree", "ghost_getPageSet", []interface{}{"coin", "0x0", []string{"0x1"}, anchor}},
		{"empty page set", "ghost_getPageSet", []interface{}{"coin", "0x0", []string{}, anchor}},
		{"one page as a number", "ghost_getPageSet", []interface{}{"coin", "0x0", "0x0", anchor}},
		{"one marker as a hash", "ghost_getMarkerStatus", []interface{}{"coin", restoreDecoy(3), anchor}},
		{"status without anchor", "ghost_getMarkerStatus", []interface{}{"coin", query}},
	} {
		if err := client.Call(&out, c.method, c.args...); err == nil {
			t.Errorf("%s: answered %v", c.name, out)
		}
	}

	// The whole-page reads still answer.
	var page ethapi.RPCTreePage
	if err := client.Call(&page, "ghost_getTreePage", "coin", "0x0", "0x1", anchor); err != nil || page.Filled != 904 {
		t.Errorf("ghost_getTreePage: %d filled, %v", page.Filled, err)
	}
	var markers ethapi.RPCMarkerPage
	if err := client.Call(&markers, "ghost_getTreePage", "coin-markers", "0x0", "0x0", anchor); err != nil || len(markers.Markers) != 1 || markers.Markers[0] != restoreDecoy(3) {
		t.Errorf("marker page: %v, %v", markers, err)
	}
}
