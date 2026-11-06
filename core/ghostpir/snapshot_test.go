package ghostpir

import (
	"errors"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// blockSpec is the content of one block of a test branch.
type blockSpec struct {
	coin, data               []uint32
	coinMarkers, dataMarkers int
	skip                     uint64 // added to the leaf sequence before the block
}

// branchSpecs is the content of blocks from to to-1 of a branch: variant 0
// is the first branch, and another variant a branch whose leaves, counts and
// markers all differ from it.
func branchSpecs(from, to int, variant uint32) []blockSpec {
	var out []blockSpec
	for i := from; i < to; i++ {
		tags := func(n int, salt uint32) []uint32 {
			tt := make([]uint32, n)
			for k := range tt {
				tt[k] = (uint32(i)*131 + uint32(k)*7 + salt + variant*977) * 2654435761 >> 8
			}
			return tt
		}
		s := blockSpec{coin: tags(3+int(variant), 1), data: tags(2, 2), coinMarkers: 1, dataMarkers: 1 + int(variant)}
		if variant != 0 && i == from {
			s.skip = 1000 * uint64(variant)
		}
		out = append(out, s)
	}
	return out
}

// replay builds a branch from genesis in db and makes it the canonical
// chain: the headers of an earlier branch with the same blocks below the
// fork are the same headers.
func replay(t *testing.T, db ethdb.Database, h *ghosttree.History, specs []blockSpec) *restoreChain {
	t.Helper()
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &restoreChain{t: t, db: db, h: h, st: st}
	c.seal(nil)
	for _, s := range specs {
		c.seq += s.skip
		c.block(s.coin, s.data, s.coinMarkers, s.dataMarkers)
	}
	return c
}

// countLeaves is the number of records of a kind up to and including block
// number.
func countLeaves(c *restoreChain, kind ghosttree.Kind, number uint64) int {
	n := 0
	for _, recs := range c.records[:number+1] {
		for _, r := range recs {
			if r.Kind == kind {
				n++
			}
		}
	}
	return n
}

// entry finds an entry of a snapshot or fails.
func entry(t *testing.T, s *Snapshot, table Table, kind ghosttree.Kind) int {
	t.Helper()
	i, ok := s.Find(table, kind, 0)
	if !ok {
		t.Fatalf("snapshot has no %v of %v tree 0", table, kind)
	}
	return i
}

// checkSnapshotOf checks that a snapshot is that of the chain's block at
// number: its anchor and roots are the header's, its databases hold the
// chain's leaves and markers as of the block, and a coin witness read
// through PIR verifies against the header.
func checkSnapshotOf(t *testing.T, c *restoreChain, s *Snapshot, number uint64) {
	t.Helper()
	header := c.headers[number]
	hd := s.Header
	if hd.Number != number || hd.Anchor != header.Hash() {
		t.Fatalf("snapshot at block %d %x, want block %d %x", hd.Number, hd.Anchor, number, header.Hash())
	}
	if hd.CoinTreeRoot != *header.CoinTreeRoot || hd.DataTreeRoot != *header.DataTreeRoot || hd.DataMarkerRoot != *header.DataMarkerRoot {
		t.Fatalf("snapshot roots %x %x %x differ from block %d's", hd.CoinTreeRoot, hd.DataTreeRoot, hd.DataMarkerRoot, number)
	}
	if s.ID != hd.ID() {
		t.Fatal("snapshot identity is not its header's")
	}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		e := hd.Entries[entry(t, s, NoteTable, kind)]
		if e.Root != *ghosttree.HeaderRoot(header, kind) || e.Records != countLeaves(c, kind, number) {
			t.Fatalf("%v notes: %d records under %x, block %d has %d under %x", kind, e.Records, e.Root, number, countLeaves(c, kind, number), *ghosttree.HeaderRoot(header, kind))
		}
	}
	for _, kind := range []ghosttree.Kind{ghosttree.CoinMarkers, ghosttree.DataMarkers} {
		i := entry(t, s, MarkerTable, kind)
		want := c.markers(kind, number)
		recs := s.Records(i)
		if len(recs) != len(want) || hd.Entries[i].Root != listRoot(want) {
			t.Fatalf("%v: %d marker records, the chain spent %d by block %d", kind, len(recs), len(want), number)
		}
		for pos, rec := range recs {
			if m, _, err := DecodeLeafWitnessRecord(rec); err != nil || m != want[pos] {
				t.Fatalf("%v marker %d differs from the chain's", kind, pos)
			}
		}
	}
	hi := entry(t, s, HintBucketTable, ghosttree.Coin)
	if hd.Entries[hi].Records != len(s.Hints[0].Buckets) || hd.Entries[hi+1].Table != HintOverflowTable || hd.Entries[hi+1].Records != len(s.Hints[0].Overflow) {
		t.Fatalf("hint entries %+v and %+v for the coin hint table", hd.Entries[hi], hd.Entries[hi+1])
	}
	for i, e := range hd.Entries {
		if e.Digest != recordsDigest(s.Records(i)) || e.Records != len(s.Records(i)) {
			t.Fatalf("entry %d (%v of %v) digest or count does not match its records", i, e.Table, e.Kind)
		}
		if db := s.Database(i); (db == nil) != (e.Records == 0) || (db != nil && db.Shape().Seed != DatabaseSeed(s.ID, i)) {
			t.Fatalf("entry %d (%v of %v) PIR database missing or under another seed", i, e.Table, e.Kind)
		}
	}

	// The last coin leaf's witness, read through the snapshot's database,
	// verifies against the anchor header.
	ni, wi := entry(t, s, NoteTable, ghosttree.Coin), entry(t, s, WitnessTable, ghosttree.Coin)
	last := hd.Entries[wi].Records - 1
	srv := NewServer(s.Database(wi), log.NewLogger(new(recordingHandler)))
	cl, err := NewClient(srv.Shape())
	if err != nil {
		t.Fatal(err)
	}
	got, _, _ := fetch(t, srv, cl, last, nil)
	if !slices.Equal(got, s.Records(wi)[last]) {
		t.Fatal("coin witness read through PIR differs from the snapshot's record")
	}
	sib, err := DecodeWitnessRecord(got)
	if err != nil {
		t.Fatal(err)
	}
	note, err := DecodeNoteRecord(s.Records(ni)[last])
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.VerifyMembership(header, ghosttree.Coin, uint32(last), note.Leaf, siblingArray(t, sib)) {
		t.Fatalf("coin witness %d from the snapshot does not verify against block %d", last, number)
	}
}

func TestSnapshotRebuildAfterReorg(t *testing.T) {
	t.Run("anchors and identity", testSnapshotAnchors)
	t.Run("reorganisation", testSnapshotReorg)
}

func testSnapshotReorg(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	h := ghosttree.NewHistory(db)
	quiet := log.NewLogger(new(recordingHandler))

	// Branch A runs to block 25; its snapshot is anchored at block 20.
	specA := branchSpecs(1, 26, 0)
	a := replay(t, db, h, specA)
	a.sync()
	snapper := NewSnapshotter(db, h, quiet)
	if snapper.Current() != nil {
		t.Fatal("a snapshot before the first update")
	}
	s19, rebuilt, err := snapper.Update(a.headers[19])
	if err != nil || !rebuilt || s19.Header.Number != 0 {
		t.Fatalf("head 19: snapshot at %v, rebuilt %v (%v)", s19, rebuilt, err)
	}
	sA, rebuilt, err := snapper.Update(a.headers[20])
	if err != nil || !rebuilt {
		t.Fatalf("head 20: rebuilt %v (%v)", rebuilt, err)
	}
	checkSnapshotOf(t, a, sA, 20)
	for _, n := range []int{21, 25} {
		s, rebuilt, err := snapper.Update(a.headers[n])
		if err != nil || rebuilt || s != sA || snapper.Current() != sA {
			t.Fatalf("head %d: rebuilt %v (%v) inside the interval", n, rebuilt, err)
		}
	}
	if snapper.Rebuilds() != 2 {
		t.Fatalf("%d rebuilds over blocks 19 to 25, want 2", snapper.Rebuilds())
	}

	// Branch B forks after block 12 and runs to block 27: the reorganisation
	// replaces block 20, so the snapshot is rebuilt on B's block 20.
	specB := append(slices.Clone(specA[:12]), branchSpecs(13, 28, 1)...)
	b := replay(t, db, h, specB)
	if b.headers[12].Hash() != a.headers[12].Hash() || b.headers[13].Hash() == a.headers[13].Hash() {
		t.Fatal("branch B does not fork from A after block 12")
	}
	if b.headers[20].Hash() == a.headers[20].Hash() || *b.headers[20].CoinTreeRoot == *a.headers[20].CoinTreeRoot {
		t.Fatal("branch B's block 20 has A's roots")
	}
	b.sync()
	sB, rebuilt, err := snapper.Update(b.headers[27])
	if err != nil || !rebuilt {
		t.Fatalf("after the reorganisation: rebuilt %v (%v)", rebuilt, err)
	}
	if sB.ID == sA.ID || sB.Header.Anchor == sA.Header.Anchor || snapper.Current() != sB {
		t.Fatal("snapshot after the reorganisation keeps the old branch's identity")
	}
	checkSnapshotOf(t, b, sB, 20)
	if sB.Header.CoinTreeRoot == sA.Header.CoinTreeRoot || sB.Header.DataTreeRoot == sA.Header.DataTreeRoot {
		t.Fatal("rebuilt snapshot keeps the old branch's roots")
	}
	// The old branch's anchor is no longer served from.
	if _, err := BuildSnapshot(h, a.headers[20]); err == nil {
		t.Fatal("built a snapshot on the replaced block 20")
	}

	// A reorganisation above the anchor (branch C forks after block 22)
	// keeps the snapshot.
	specC := append(slices.Clone(specB[:22]), branchSpecs(23, 31, 2)...)
	cc := replay(t, db, h, specC)
	if cc.headers[22].Hash() != b.headers[22].Hash() || cc.headers[23].Hash() == b.headers[23].Hash() {
		t.Fatal("branch C does not fork from B after block 22")
	}
	cc.sync()
	s, rebuilt, err := snapper.Update(cc.headers[30])
	if err != nil || rebuilt || s != sB {
		t.Fatalf("reorganisation above the anchor: rebuilt %v (%v)", rebuilt, err)
	}

	// A node that only ever saw the new canonical chain builds the same
	// snapshot, byte for byte.
	db2 := rawdb.NewMemoryDatabase()
	fresh := replay(t, db2, ghosttree.NewHistory(db2), specC)
	fresh.sync()
	if fresh.headers[20].Hash() != b.headers[20].Hash() {
		t.Fatal("the fresh node's block 20 differs")
	}
	other, err := BuildSnapshot(fresh.h, fresh.headers[20])
	if err != nil {
		t.Fatal(err)
	}
	if other.ID != sB.ID || !slices.Equal(other.Header.Encode(), sB.Header.Encode()) {
		t.Fatal("the rebuilt snapshot differs from the one built on the new chain alone")
	}

	// The next interval rebuilds: block 40 on branch C.
	for _, sp := range branchSpecs(31, 41, 2) {
		cc.block(sp.coin, sp.data, sp.coinMarkers, sp.dataMarkers)
	}
	cc.sync()
	s40, rebuilt, err := snapper.Update(cc.headers[40])
	if err != nil || !rebuilt || s40.ID == sB.ID {
		t.Fatalf("head 40: rebuilt %v (%v)", rebuilt, err)
	}
	checkSnapshotOf(t, cc, s40, 40)
}

// testSnapshotAnchors checks where a snapshot may sit and that its identity
// commits to its whole header.
func testSnapshotAnchors(t *testing.T) {
	for head, want := range map[uint64]uint64{0: 0, 1: 0, 19: 0, 20: 20, 21: 20, 39: 20, 40: 40, 1_000_019: 1_000_000} {
		if got := SnapshotNumber(head); got != want {
			t.Fatalf("SnapshotNumber(%d) = %d, want %d", head, got, want)
		}
	}
	c := newRestoreChain(t)
	for range 21 {
		c.block([]uint32{1, 2}, []uint32{3}, 1, 1)
	}
	c.sync()
	if _, err := BuildSnapshot(c.h, c.headers[19]); !errors.Is(err, ErrSnapshotAnchor) {
		t.Fatalf("snapshot on block 19: %v, want %v", err, ErrSnapshotAnchor)
	}
	noRoots := types.CopyHeader(c.headers[20])
	noRoots.CoinTreeRoot = nil
	if _, err := BuildSnapshot(c.h, noRoots); !errors.Is(err, ErrSnapshotAnchor) {
		t.Fatalf("snapshot on a header without roots: %v, want %v", err, ErrSnapshotAnchor)
	}
	s, err := BuildSnapshot(c.h, c.headers[20])
	if err != nil {
		t.Fatal(err)
	}
	// The identity commits to every field of the header.
	id := s.Header.ID()
	for name, damage := range map[string]func(h *SnapshotHeader){
		"number":      func(h *SnapshotHeader) { h.Number++ },
		"anchor":      func(h *SnapshotHeader) { h.Anchor[0] ^= 1 },
		"coin root":   func(h *SnapshotHeader) { h.CoinTreeRoot[0] ^= 1 },
		"data root":   func(h *SnapshotHeader) { h.DataTreeRoot[0] ^= 1 },
		"marker root": func(h *SnapshotHeader) { h.DataMarkerRoot[0] ^= 1 },
		"digest":      func(h *SnapshotHeader) { h.Entries[0].Digest[0] ^= 1 },
		"records":     func(h *SnapshotHeader) { h.Entries[1].Records++ },
		"entries":     func(h *SnapshotHeader) { h.Entries = h.Entries[1:] },
	} {
		hd := s.Header
		hd.Entries = slices.Clone(s.Header.Entries)
		damage(&hd)
		if hd.ID() == id {
			t.Fatalf("identity unchanged by a damaged %s", name)
		}
	}
	if DatabaseSeed(id, 0) == DatabaseSeed(id, 1) || DatabaseSeed(id, 0) == DatabaseSeed(common.Hash{}, 0) {
		t.Fatal("database seeds repeat")
	}
}
