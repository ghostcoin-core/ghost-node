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
	"encoding/json"
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

// bucketRPCTag is the tag of the note at position i: the spec vector 7c28b7
// at position 9, 4d6c00 at position 10, and otherwise a spread of values.
func bucketRPCTag(i int) uint32 {
	switch i {
	case 9:
		return 0x7c28b7
	case 10:
		return 0x4d6c00
	}
	return uint32(i) * 2246822519 >> 8 & 0xffffff
}

func bucketRPCLeaf(i int) common.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return ghosttree.K("ghost/test-bucket-rpc-leaf", b[:])
}

func TestGhostGetNoteBucketOverRPC(t *testing.T) {
	const leaves = 8300 // 1 bucket bit
	db := rawdb.NewMemoryDatabase()
	history := ghosttree.NewHistory(db)
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	var (
		parent common.Hash
		head   *types.Header
		stored []ghosttree.Record
	)
	for number := uint64(0); number < 2; number++ {
		var records []ghosttree.Record
		if number == 1 {
			for i := 0; i < leaves; i++ {
				res, err := ghosttree.Append(st, ghosttree.Coin, number, bucketRPCLeaf(i))
				if err != nil {
					t.Fatal(err)
				}
				r := ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: res.Leaf}
				tag := bucketRPCTag(i)
				r.Note[0], r.Note[1], r.Note[2], r.Note[ghosttree.NoteBytes-1] = byte(tag>>16), byte(tag>>8), byte(tag), byte(i)
				if i%5 == 0 {
					var s [ghosttree.SaltBytes]byte
					s[0], s[1] = byte(i>>8), byte(i)
					r.Salt = &s
				}
				records = append(records, r)
			}
			stored = records
		}
		coin, _ := ghosttree.Root(st, ghosttree.Coin)
		data, _ := ghosttree.Root(st, ghosttree.Data)
		marker, _ := ghosttree.DataMarkerRoot(st)
		head = &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data, DataMarkerRoot: &marker}
		rawdb.WriteHeader(db, head)
		rawdb.WriteCanonicalHash(db, head.Hash(), number)
		if err := history.ApplyBlock(head.Hash(), number, records); err != nil {
			t.Fatal(err)
		}
		parent = head.Hash()
	}
	server := rpc.NewServer()
	if err := server.RegisterName("ghost", ethapi.NewGhostAPI(history)); err != nil {
		t.Fatal(err)
	}
	if err := server.RegisterName("ghost", ethapi.NewGhostBucketAPI(history)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)
	anchor := head.Hash()

	// The bucket service has the one read.
	typ := reflect.TypeOf(&ethapi.GhostBucketAPI{})
	var methods []string
	for i := 0; i < typ.NumMethod(); i++ {
		methods = append(methods, typ.Method(i).Name)
	}
	if want := []string{"GetNoteBucket"}; !reflect.DeepEqual(methods, want) {
		t.Errorf("bucket service methods %v, want %v", methods, want)
	}

	total := 0
	for prefix := uint32(0); prefix < 2; prefix++ {
		var raw struct {
			Kind      string                       `json:"kind"`
			TreeIndex hexutil.Uint64               `json:"treeIndex"`
			Bits      hexutil.Uint64               `json:"bits"`
			Prefix    hexutil.Uint64               `json:"prefix"`
			Count     hexutil.Uint64               `json:"count"`
			Entries   []map[string]json.RawMessage `json:"entries"`
		}
		if err := client.Call(&raw, "ghost_getNoteBucket", "coin", "0x0", "0x1", hexutil.Uint64(prefix), anchor); err != nil {
			t.Fatalf("bucket %d: %v", prefix, err)
		}
		if raw.Kind != "coin" || raw.TreeIndex != 0 || raw.Bits != 1 || uint32(raw.Prefix) != prefix || int(raw.Count) != len(raw.Entries) {
			t.Errorf("bucket %d: header %s %d %d %d %d with %d entries", prefix, raw.Kind, raw.TreeIndex, raw.Bits, raw.Prefix, raw.Count, len(raw.Entries))
		}
		var want []int
		for i := 0; i < leaves; i++ {
			if bucketRPCTag(i)>>23 == prefix {
				want = append(want, i)
			}
		}
		if len(raw.Entries) != len(want) {
			t.Fatalf("bucket %d: %d entries, want %d", prefix, len(raw.Entries), len(want))
		}
		for j, e := range raw.Entries {
			i := want[j]
			r := stored[i]
			fields := []string{}
			for k := range e {
				fields = append(fields, k)
			}
			slices.Sort(fields)
			wantFields := []string{"leaf", "note", "position", "salt"}
			if r.Salt == nil {
				wantFields = []string{"leaf", "note", "position"}
			}
			if !reflect.DeepEqual(fields, wantFields) {
				t.Fatalf("bucket %d entry %d: fields %v, want %v", prefix, j, fields, wantFields)
			}
			var entry ethapi.RPCBucketEntry
			blob, _ := json.Marshal(e)
			if err := json.Unmarshal(blob, &entry); err != nil {
				t.Fatal(err)
			}
			if int(entry.Position) != i || entry.Leaf != r.Leaf || !slices.Equal([]byte(entry.Note), r.Note[:]) {
				t.Errorf("bucket %d entry %d: position %d, want %d with its leaf and note", prefix, j, entry.Position, i)
			}
			if r.Salt != nil && !slices.Equal([]byte(entry.Salt), r.Salt[:]) {
				t.Errorf("bucket %d position %d: salt %x", prefix, i, []byte(entry.Salt))
			}
		}
		if prefix == 0 && (!slices.Contains(want, 9) || !slices.Contains(want, 10)) {
			t.Error("the spec vector tags are not in bucket 0")
		}
		total += len(raw.Entries)
	}
	if total != leaves {
		t.Errorf("the buckets hold %d leaves, want %d", total, leaves)
	}

	// The pages are served beside the buckets.
	var roots []common.Hash
	if err := client.Call(&roots, "ghost_getPageRoots", "coin", "0x0", anchor); err != nil || len(roots) != 3 {
		t.Errorf("page roots: %d, %v", len(roots), err)
	}
	var page ethapi.RPCTreePage
	if err := client.Call(&page, "ghost_getTreePage", "coin", "0x0", "0x2", anchor); err != nil || int(page.Filled) != leaves-2*ghosttree.PageLeaves {
		t.Errorf("page 2: %d filled, %v", page.Filled, err)
	}

	// Refused over the wire.
	var out interface{}
	for _, c := range []struct {
		name string
		args []interface{}
	}{
		{"coin marker kind", []interface{}{"coin-markers", "0x0", "0x0", "0x0", anchor}},
		{"data marker kind", []interface{}{"data-markers", "0x0", "0x0", "0x0", anchor}},
		{"bits below the rule", []interface{}{"coin", "0x0", "0x0", "0x0", anchor}},
		{"bits above the rule", []interface{}{"coin", "0x0", "0x2", "0x0", anchor}},
		{"25 bits", []interface{}{"coin", "0x0", "0x19", "0x0", anchor}},
		{"bits beyond 32 bits", []interface{}{"coin", "0x0", "0x100000001", "0x0", anchor}},
		{"prefix 2^bits", []interface{}{"coin", "0x0", "0x1", "0x2", anchor}},
		{"tree that does not exist", []interface{}{"coin", "0x1", "0x0", "0x0", anchor}},
		{"unknown anchor", []interface{}{"coin", "0x0", "0x1", "0x0", common.Hash{1}}},
		{"no anchor", []interface{}{"coin", "0x0", "0x1", "0x0"}},
	} {
		if err := client.Call(&out, "ghost_getNoteBucket", c.args...); err == nil {
			t.Errorf("%s: answered %v", c.name, out)
		}
	}
}
