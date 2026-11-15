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
	"math/big"
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

// TestGhostGetNoteBucketPagesAFloodedBucketOverRPC fills one bucket of a
// tree of one bucket bit far past the reply cap, as a committer who picks
// one tag for many notes can, and reads it over RPC from start 0: the first
// reply holds the cap and points at the next page, and the pages together
// are the bucket. Asked without a start, as before paging, the flooded
// bucket is refused, never served in part, and the other comes whole.
func TestGhostGetNoteBucketPagesAFloodedBucketOverRPC(t *testing.T) {
	const leaves = 12000 // 1 bucket bit
	tagOf := func(i int) uint32 {
		if i%12 == 0 {
			return 0x800000 | uint32(i)
		}
		return 0x000001 // the flooded tag, in bucket 0
	}
	db := rawdb.NewMemoryDatabase()
	history := ghosttree.NewHistory(db)
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	var parent common.Hash
	var head *types.Header
	for number := uint64(0); number < 2; number++ {
		var records []ghosttree.Record
		if number == 1 {
			for i := 0; i < leaves; i++ {
				res, err := ghosttree.Append(st, ghosttree.Coin, number, bucketRPCLeaf(i))
				if err != nil {
					t.Fatal(err)
				}
				r := ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: res.Leaf}
				tag := tagOf(i)
				r.Note[0], r.Note[1], r.Note[2] = byte(tag>>16), byte(tag>>8), byte(tag)
				records = append(records, r)
			}
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
	if ghosttree.BucketBits(leaves) != 1 {
		t.Fatal("tree is not of one bucket bit")
	}
	server := rpc.NewServer()
	if err := server.RegisterName("ghost", ethapi.NewGhostBucketAPI(history)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	client := rpc.DialInProc(server)
	t.Cleanup(client.Close)
	anchor := head.Hash()

	for prefix := uint32(0); prefix < 2; prefix++ {
		var want []uint64
		for i := 0; i < leaves; i++ {
			if tagOf(i)>>23 == prefix {
				want = append(want, uint64(i))
			}
		}
		var got []uint64
		var replies int
		args := []interface{}{"coin", "0x0", "0x1", hexutil.Uint64(prefix), anchor, "0x0"}
		for {
			var reply ethapi.RPCNoteBucket
			if err := client.Call(&reply, "ghost_getNoteBucket", args...); err != nil {
				t.Fatalf("bucket %d reply %d: %v", prefix, replies, err)
			}
			replies++
			if len(reply.Entries) > ghosttree.MaxBucketEntries || int(reply.Count) != len(reply.Entries) {
				t.Fatalf("bucket %d reply %d: %d entries, count %d", prefix, replies, len(reply.Entries), reply.Count)
			}
			for _, e := range reply.Entries {
				got = append(got, uint64(e.Position))
			}
			if reply.Next == nil {
				break
			}
			if len(reply.Entries) != ghosttree.MaxBucketEntries || uint64(*reply.Next) != got[len(got)-1]+1 {
				t.Fatalf("bucket %d reply %d: %d entries with next %d", prefix, replies, len(reply.Entries), *reply.Next)
			}
			if replies > 10 {
				t.Fatal("bucket pages never end")
			}
			args = []interface{}{"coin", "0x0", "0x1", hexutil.Uint64(prefix), anchor, *reply.Next}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("bucket %d: %d positions over %d replies, want %d", prefix, len(got), replies, len(want))
		}
		wantReplies := 1
		if len(want) > ghosttree.MaxBucketEntries {
			wantReplies = 2
		}
		if replies != wantReplies {
			t.Errorf("bucket %d of %d entries in %d replies, want %d", prefix, len(want), replies, wantReplies)
		}

		// Without a start: the whole bucket, or an error past the cap.
		var whole ethapi.RPCNoteBucket
		err := client.Call(&whole, "ghost_getNoteBucket", "coin", "0x0", "0x1", hexutil.Uint64(prefix), anchor)
		if len(want) > ghosttree.MaxBucketEntries {
			if err == nil || len(whole.Entries) != 0 {
				t.Fatalf("bucket %d of %d entries without a start: %d entries, %v; want an error", prefix, len(want), len(whole.Entries), err)
			}
			continue
		}
		if err != nil || whole.Next != nil || len(whole.Entries) != len(want) {
			t.Fatalf("bucket %d without a start: %d entries, next %v, %v", prefix, len(whole.Entries), whole.Next, err)
		}
	}
	if n := leaves - leaves/12; n <= ghosttree.MaxBucketEntries {
		t.Fatalf("flooded bucket of %d is not over the cap", n)
	}
}
