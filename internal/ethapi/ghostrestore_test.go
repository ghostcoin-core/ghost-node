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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghostpir"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
)

// The restore fixture: a chain whose block 1 appends n coin leaves, leaf i
// with wallet i's lookup tag, and spends the marker of every fourth
// wallet's coin. Blocks 2 to 22 are empty except block 21, which appends a
// few leaves and spends a few markers after the snapshot. The snapshot is
// anchored at block 20 and the head is block 22.

const restoreHead = 22

func restoreTag(i int) ghosttree.LookupTag {
	var t ghosttree.LookupTag
	copy(t[:], crypto.Keccak256([]byte("restore-tag"), binary.BigEndian.AppendUint64(nil, uint64(i))))
	return t
}

func restoreLeaf(i int) common.Hash {
	return crypto.Keccak256Hash([]byte("restore-leaf"), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

func restoreMarker(i int) common.Hash {
	return crypto.Keccak256Hash([]byte("restore-marker"), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

// restoreSpent reports whether wallet i's coin was spent in block 1.
func restoreSpent(i int) bool { return i%4 == 0 }

type restoreFixture struct {
	client  *rpc.Client
	headers []*types.Header
	n       int
}

func newRestoreFixture(t *testing.T, n int, budget ghostpir.Budget) *restoreFixture {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	history := ghosttree.NewHistory(db)
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	appendLeaf := func(number uint64, i int) ghosttree.Record {
		res, err := ghosttree.AppendTagged(st, ghosttree.Coin, number, restoreLeaf(i), restoreTag(i))
		if err != nil {
			t.Fatal(err)
		}
		rec := ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: res.Leaf}
		copy(rec.Note[:], restoreLeaf(i).Bytes())
		return rec
	}
	spend := func(number uint64, i int) ghosttree.Record {
		// The reveal spending wallet i's coin appended wallet i+1's leaf.
		if err := ghosttree.MarkSpent(st, ghosttree.Coin, number, restoreMarker(i), uint64(i+1)); err != nil {
			t.Fatal(err)
		}
		return ghosttree.Record{Kind: ghosttree.CoinMarkers, Leaf: restoreMarker(i)}
	}
	var (
		f       = &restoreFixture{n: n}
		records = make(map[common.Hash][]ghosttree.Record)
		states  = make(map[common.Hash]*state.StateDB)
		parent  common.Hash
	)
	for number := uint64(0); number <= restoreHead; number++ {
		var recs []ghosttree.Record
		switch number {
		case 1:
			for i := 0; i < n; i++ {
				recs = append(recs, appendLeaf(number, i))
			}
			for i := 0; i < n; i += 4 {
				recs = append(recs, spend(number, i))
			}
		case 21:
			for i := n; i < n+3; i++ {
				recs = append(recs, appendLeaf(number, i))
			}
			recs = append(recs, spend(number, 1), spend(number, 5))
		}
		var fields *ghosttree.HeaderFields
		if number == 0 {
			fields = ghosttree.GenesisHeaderFields()
		} else if fields, err = ghosttree.ReadHeaderFields(st, number); err != nil {
			t.Fatal(err)
		}
		header := &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1)}
		fields.SetOn(header)
		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, header.Hash(), number)
		records[header.Hash()] = recs
		if number >= ghostpir.SnapshotInterval {
			states[header.Hash()] = st.Copy()
		}
		f.headers = append(f.headers, header)
		parent = header.Hash()
	}
	head := f.headers[restoreHead]
	if err := history.Sync(head, func(h *types.Header) ([]ghosttree.Record, error) { return records[h.Hash()], nil }); err != nil {
		t.Fatal(err)
	}
	server, err := ghostpir.NewBulkServer(db, history, budget, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.SetState(func(h *types.Header) (ghosttree.StateDB, error) {
		if s, ok := states[h.Hash()]; ok {
			return s, nil
		}
		return nil, fmt.Errorf("no state of block %d", h.Number)
	})
	if err := server.Update(head); err != nil {
		t.Fatal(err)
	}
	srv := rpc.NewServer()
	if err := srv.RegisterName("ghost", NewGhostRestoreAPI(server)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	f.client = rpc.DialInProc(srv)
	t.Cleanup(f.client.Close)
	return f
}

// restoreWallet is the wallet side of a restore: it reads the snapshot
// header, checks it against the anchor header of its own chain, and reads
// records by PIR, counting the queries and the bytes sent and received.
type restoreWallet struct {
	t       *testing.T
	f       *restoreFixture
	anchor  *types.Header
	header  ghostpir.SnapshotHeader
	queries int
	bytes   int
}

// searchProbes is the number of index records every search reads, padded:
// enough for a bucket of up to 255 leaves.
const searchProbes = 8

func (f *restoreFixture) wallet(t *testing.T) *restoreWallet {
	var rh RPCRestoreHeader
	if err := f.client.Call(&rh, "ghost_restoreHeader"); err != nil {
		t.Fatal(err)
	}
	w := &restoreWallet{t: t, f: f, anchor: f.headers[rh.Number]}
	if rh.Anchor != w.anchor.Hash() || uint64(rh.Number) != ghostpir.SnapshotNumber(restoreHead) {
		t.Fatalf("snapshot anchored at %d %x", rh.Number, rh.Anchor)
	}
	w.header = ghostpir.SnapshotHeader{Number: uint64(rh.Number), Anchor: rh.Anchor, CoinTreeRoot: rh.CoinTreeRoot, DataTreeRoot: rh.DataTreeRoot, DataMarkerRoot: rh.DataMarkerRoot}
	for _, e := range rh.Entries {
		var table ghostpir.Table
		for c := ghostpir.NoteTable; c <= ghostpir.IndexBucketTable; c++ {
			if c.String() == e.Table {
				table = c
			}
		}
		w.header.Entries = append(w.header.Entries, ghostpir.SnapshotEntry{
			Table: table, Kind: ghosttree.Kind(e.Kind), TreeIndex: uint64(e.TreeIndex),
			RecordSize: int(e.RecordSize), Records: int(e.Records), Root: e.Root, Digest: e.Digest,
		})
	}
	if !bytes.Equal(w.header.Encode(), rh.Encoded) || w.header.ID() != rh.ID {
		t.Fatal("the snapshot header's fields differ from its encoding")
	}
	// Every indexed tree is under the anchor header's root of it.
	for _, set := range ghosttree.IndexedSets {
		for _, table := range []ghostpir.Table{ghostpir.IndexTable, ghostpir.IndexBucketTable} {
			e := w.entry(table, ghostpir.IndexSetKind(set))
			if want := ghostpir.IndexHeaderRoot(w.anchor, set); want == nil || w.header.Entries[e].Root != *want {
				t.Fatalf("%v %v: root not the anchor header's", set, table)
			}
		}
	}
	return w
}

func (w *restoreWallet) entry(table ghostpir.Table, kind ghosttree.Kind) int {
	for i, e := range w.header.Entries {
		if e.Table == table && e.Kind == kind && e.TreeIndex == 0 {
			return i
		}
	}
	w.t.Fatalf("no %v database of %v", table, kind)
	return 0
}

// read fetches record index of database entry by PIR.
func (w *restoreWallet) read(entry, index int) []byte {
	w.t.Helper()
	shape, err := ghostpir.EntryShape(&w.header, entry)
	if err != nil {
		w.t.Fatal(err)
	}
	c, err := ghostpir.NewClient(shape)
	if err != nil {
		w.t.Fatal(err)
	}
	q, qs, err := c.Query(index, rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	var answer hexutil.Bytes
	if err := w.f.client.Call(&answer, "ghost_restoreQuery", hexutil.Uint64(entry), hexutil.Bytes(q)); err != nil {
		w.t.Fatal(err)
	}
	rec, err := c.Decode(qs, answer)
	if err != nil {
		w.t.Fatal(err)
	}
	w.queries++
	w.bytes += len(q) + len(answer)
	return rec
}

// low finds, in an indexed tree, the witness of the last leaf whose key is
// below q (or at q, with orEqual), in 1 + searchProbes queries whatever the
// tree, and checks every record it reads against the anchor header's root.
func (w *restoreWallet) low(set ghosttree.IndexedSet, q common.Hash, orEqual bool) []byte {
	w.t.Helper()
	kind := ghostpir.IndexSetKind(set)
	root := *ghostpir.IndexHeaderRoot(w.anchor, set)
	buckets, index := w.entry(ghostpir.IndexBucketTable, kind), w.entry(ghostpir.IndexTable, kind)
	b := bits.Len(uint(w.header.Entries[buckets].Records)) - 1
	start, end, err := ghostpir.DecodeIndexBucket(w.read(buckets, int(ghostpir.IndexBucketOf(b, q))))
	if err != nil {
		w.t.Fatal(err)
	}
	below := func(key common.Hash) bool {
		c := bytes.Compare(key[:], q[:])
		return c < 0 || (orEqual && c == 0)
	}
	lo, hi := int(start)-1, int(end)
	var found []byte
	for probe := 0; probe < searchProbes; probe++ {
		if hi-lo <= 1 {
			// Done: the padding reads the leaf found again, or the
			// sentinel, so the count of queries never depends on the tree.
			if found == nil {
				found = w.read(index, lo)
			} else {
				w.read(index, 0)
			}
			continue
		}
		mid := lo + (hi-lo)/2
		rec := w.read(index, mid)
		key, ok := ghosttree.VerifySetWitness(set, root, rec)
		if !ok {
			w.t.Fatalf("%v: rank %d does not verify against the anchor root", set, mid)
		}
		if below(key) {
			lo = mid
			if hi-lo <= 1 {
				found = rec
			}
		} else {
			hi = mid
		}
	}
	if hi-lo > 1 {
		w.t.Fatalf("%v: bucket of %d leaves needs more than %d probes", set, end-start, searchProbes)
	}
	if found == nil {
		found = w.read(index, lo)
	}
	if key, ok := ghosttree.VerifySetWitness(set, root, found); !ok || !below(key) {
		w.t.Fatalf("%v: the low leaf does not verify", set)
	}
	return found
}

// restoreCoin restores wallet i's coin: the first entry of its tag in the
// coin lookup index, its note and coin-tree witness, and the spent status of
// its marker, every item verified against the anchor header.
func (w *restoreWallet) restoreCoin(i int) (spent bool) {
	t := w.t
	t.Helper()
	tag := restoreTag(i)
	lw := w.low(ghosttree.CoinLookupSet, ghosttree.LookupQueryKey(tag), false)
	g := uint64(i)
	if !ghosttree.VerifyLookupFirst(ghosttree.Coin, *w.anchor.CoinLookupRoot, tag, g, lw) {
		t.Fatalf("wallet %d: no first-entry proof of its tag at %d", i, g)
	}
	pos := uint32(g) // tree 0
	note, err := ghostpir.DecodeNoteRecord(w.read(w.entry(ghostpir.NoteTable, ghosttree.Coin), int(pos)))
	if err != nil {
		t.Fatal(err)
	}
	sibs, err := ghostpir.DecodeWitnessRecord(w.read(w.entry(ghostpir.WitnessTable, ghosttree.Coin), int(pos)))
	if err != nil || len(sibs) != 32 {
		t.Fatalf("wallet %d: witness record %v", i, err)
	}
	if !ghosttree.VerifyMembership(w.anchor, ghosttree.Coin, pos, note.Leaf, [32]common.Hash(sibs)) || note.Leaf != restoreLeaf(i) {
		t.Fatalf("wallet %d: leaf not under the anchor's coin root", i)
	}
	marker := restoreMarker(i)
	mw := w.low(ghosttree.CoinMarkerSet, marker, true)
	root := *w.anchor.CoinMarkerRoot
	switch {
	case ghosttree.VerifyCoinMarker(root, marker, uint64(i+1), mw):
		return true
	case ghosttree.VerifyCoinMarkerAbsence(root, marker, mw):
		return false
	}
	t.Fatalf("wallet %d: no membership or absence proof of its marker", i)
	return false
}

// restoreBytes runs the restores of a few wallets and the bulk reads, and
// returns the queries and bytes of one coin restore.
func restoreBytes(t *testing.T, n int) (queries, size int) {
	f := newRestoreFixture(t, n, ghostpir.Budget{Window: time.Hour, PerClient: 1 << 20, Total: 1 << 20})
	w := f.wallet(t)

	// One restore, of a spent coin, measured; the others checked.
	if !w.restoreCoin(n - 4) {
		t.Fatal("spent coin restored as unspent")
	}
	queries, size = w.queries, w.bytes
	for _, i := range []int{1, n / 2, n - 1} {
		if spent := w.restoreCoin(i); spent != restoreSpent(i) {
			t.Fatalf("wallet %d restored as spent %v", i, spent)
		}
	}
	// A tag that was never used has an absence proof.
	absent := restoreTag(1 << 40)
	if !ghosttree.VerifyLookupAbsence(ghosttree.Coin, *w.anchor.CoinLookupRoot, absent, w.low(ghosttree.CoinLookupSet, ghosttree.LookupQueryKey(absent), false)) {
		t.Fatal("no absence proof of an unused tag")
	}

	// The blocks after the snapshot carry their lookup lists, which hash
	// to each header's lookupDigest; block 21's spend of wallet 1's marker
	// is there.
	var blocks []hexutil.Bytes
	if err := f.client.Call(&blocks, "ghost_restoreBlocks", hexutil.Uint64(0)); err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("%d blocks after the snapshot", len(blocks))
	}
	for k, enc := range blocks {
		header := f.headers[ghostpir.SnapshotInterval+1+k]
		lookup := blockLookupOf(t, enc)
		if binary.BigEndian.Uint64(enc[:8]) != header.Number.Uint64() {
			t.Fatalf("block %d out of order", k)
		}
		if ghosttree.K(ghosttree.TagBlockLookupDigest, lookup) != *header.LookupDigest {
			t.Fatalf("block %d: lookup lists do not hash to its lookupDigest", header.Number)
		}
		if k == 0 && !bytes.Contains(lookup, restoreMarker(1).Bytes()) {
			t.Fatal("block 21's lookup lists miss its spend")
		}
	}
	var tops []hexutil.Bytes
	if err := f.client.Call(&tops, "ghost_restoreTops"); err != nil || len(tops) == 0 {
		t.Fatalf("tops: %d, %v", len(tops), err)
	}
	return queries, size
}

// blockLookupOf returns the lookup-list encoding at the end of a block's
// wire encoding.
func blockLookupOf(t *testing.T, enc []byte) []byte {
	p := 8 + common.HashLength
	tags := int(binary.BigEndian.Uint32(enc[p:]))
	p += 4 + tags*ghostpir.TagEntryBytes
	markers := int(binary.BigEndian.Uint32(enc[p:]))
	p += 4 + markers*ghostpir.MarkerEntryBytes
	n := int(binary.BigEndian.Uint32(enc[p:]))
	p += 4
	if p+n != len(enc) || n == 0 {
		t.Fatalf("block encoding of %d bytes, lookup lists of %d at %d", len(enc), n, p)
	}
	return enc[p:]
}

// TestGhostRestoreOverRPC restores coins over RPC from a tree of 100,000
// coin leaves and from a small one: every answer verifies against the
// anchor header's roots (coin tree, coin lookup index, coin marker set), and
// a restore makes the same queries at both sizes. No request names the tag,
// position or marker it reads. A PIR answer grows with the square root of
// its database, so the bytes are reported, and checked to stay within it.
func TestGhostRestoreOverRPC(t *testing.T) {
	smallQ, smallB := restoreBytes(t, 64)
	largeQ, largeB := restoreBytes(t, 100_000)
	t.Logf("one coin restore: %d queries at 64 leaves, %d at 100,000; %d bytes at 64 leaves, %d at 100,000", smallQ, largeQ, smallB, largeB)
	if smallQ != largeQ {
		t.Errorf("a restore makes %d queries at 64 leaves and %d at 100,000", smallQ, largeQ)
	}
	if want := 2*(1+searchProbes) + 2; largeQ != want {
		t.Errorf("%d queries a restore, want %d", largeQ, want)
	}
	// Each answer is one of a grid of about sqrt(records) rows and columns:
	// with 1,563 times the leaves, at most about 40 times the bytes.
	if largeB > 40*smallB {
		t.Errorf("restore bytes grew from %d to %d", smallB, largeB)
	}
}

// TestGhostRestoreBudget checks that a request past the restore server's
// budget is refused with the limit code and does no work.
func TestGhostRestoreBudget(t *testing.T) {
	f := newRestoreFixture(t, 16, ghostpir.Budget{Window: time.Hour, PerClient: 3, Total: 3})
	var h RPCRestoreHeader
	for i := 0; i < 3; i++ {
		if err := f.client.Call(&h, "ghost_restoreHeader"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	var tops []hexutil.Bytes
	err := f.client.Call(&tops, "ghost_restoreTops")
	var rpcErr rpc.Error
	if !errors.As(err, &rpcErr) || rpcErr.ErrorCode() != -32005 {
		t.Fatalf("request past the budget: %v, want a refusal with code -32005", err)
	}
	var answer hexutil.Bytes
	if err := f.client.Call(&answer, "ghost_restoreQuery", hexutil.Uint64(0), hexutil.Bytes{1, 2, 3}); !errors.As(err, &rpcErr) || rpcErr.ErrorCode() != -32005 {
		t.Fatalf("query past the budget: %v", err)
	}
}

// TestGhostRestoreRefusesBadQueries checks that a query of the wrong shape,
// or to an entry that does not exist, is refused.
func TestGhostRestoreRefusesBadQueries(t *testing.T) {
	f := newRestoreFixture(t, 16, ghostpir.DefaultBudget)
	var answer hexutil.Bytes
	for name, args := range map[string][]interface{}{
		"short query":        {hexutil.Uint64(0), hexutil.Bytes{1, 2, 3}},
		"entry out of range": {hexutil.Uint64(1 << 20), hexutil.Bytes{1}},
		"entry beyond int":   {hexutil.Uint64(1 << 40), hexutil.Bytes{1}},
		"no query":           {hexutil.Uint64(0)},
	} {
		if err := f.client.Call(&answer, "ghost_restoreQuery", args...); err == nil {
			t.Errorf("%s: answered", name)
		}
	}
}

// TestGhostRestoreNamesNothing checks the restore surface: four reads, none
// of which takes a tag, a marker, a position or a note.
func TestGhostRestoreNamesNothing(t *testing.T) {
	typ := reflect.TypeOf(&GhostRestoreAPI{})
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	slices.Sort(names)
	if want := []string{"RestoreBlocks", "RestoreHeader", "RestoreQuery", "RestoreTops"}; !reflect.DeepEqual(names, want) {
		t.Errorf("restore methods %v, want %v", names, want)
	}
}
