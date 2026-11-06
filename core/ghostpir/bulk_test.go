package ghostpir

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/log"
)

// bulkTestTags is the tag of the coin leaf at every position of the bulk
// test chain: distinct, all in the one bucket of a tree below 8,192 leaves.
func bulkTestTags(n int) []uint32 {
	tags := make([]uint32, n)
	for i := range tags {
		tags[i] = uint32(i*104729+17) % (1 << 24)
	}
	return tags
}

// bulkTestChain is a chain of 23 blocks: block 1 appends 40 coin leaves,
// blocks 2 to 23 one or two each, and every block spends markers. Its
// snapshot is anchored at block 20, with 59 coin leaves in one hint bucket.
func bulkTestChain(t *testing.T) (*restoreChain, []uint32) {
	t.Helper()
	tags := bulkTestTags(200)
	c := newRestoreChain(t)
	next := 0
	take := func(n int) []uint32 {
		out := tags[next : next+n]
		next += n
		return out
	}
	c.block(take(40), []uint32{0x100, 0x200, 0x300}, 1, 1)
	for n := 2; n <= 23; n++ {
		k := 1
		if n > 20 {
			k = 2
		}
		c.block(take(k), []uint32{uint32(0x1000 + n)}, 1, n%2)
	}
	c.sync()
	return c, tags[:next]
}

func newTestBulkServer(t *testing.T, c *restoreChain, b Budget) (*BulkServer, *recordingHandler) {
	t.Helper()
	h := new(recordingHandler)
	srv, err := NewBulkServer(c.db, c.h, b, log.NewLogger(h))
	if err != nil {
		t.Fatal(err)
	}
	return srv, h
}

// pirRead reads record index of entry through the server's PIR, as a wallet
// does: the shape from the snapshot header alone, then a query and its
// answer.
func pirRead(t *testing.T, srv *BulkServer, client string, hd *SnapshotHeader, entry, index int) ([]byte, error) {
	t.Helper()
	shape, err := EntryShape(hd, entry)
	if err != nil {
		t.Fatalf("shape of entry %d: %v", entry, err)
	}
	cl, err := NewClient(shape)
	if err != nil {
		t.Fatal(err)
	}
	q, st, err := cl.Query(index, nil)
	if err != nil {
		t.Fatalf("query for %d of entry %d: %v", index, entry, err)
	}
	ans, err := srv.Query(client, entry, q)
	if err != nil {
		return nil, err
	}
	rec, err := cl.Decode(st, ans)
	if err != nil {
		t.Fatalf("decode %d of entry %d: %v", index, entry, err)
	}
	return rec, nil
}

func headerEntry(t *testing.T, hd *SnapshotHeader, table Table, kind ghosttree.Kind) int {
	t.Helper()
	for i, e := range hd.Entries {
		if e.Table == table && e.Kind == kind && e.TreeIndex == 0 {
			return i
		}
	}
	t.Fatalf("snapshot header has no %v of %v tree 0", table, kind)
	return 0
}

func countMessages(records []string, msg string) int {
	n := 0
	for _, r := range records {
		if strings.Contains(r, msg) {
			n++
		}
	}
	return n
}

func TestBulkServerEnforcesPerClientBudget(t *testing.T) {
	c, _ := bulkTestChain(t)

	if _, err := NewBulkServer(c.db, c.h, Budget{Window: time.Minute, PerClient: 0, Total: 5}, nil); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget of 0 per client: %v, want %v", err, ErrBudget)
	}
	if _, err := NewBulkServer(c.db, c.h, Budget{Window: time.Minute, PerClient: 6, Total: 5}, nil); !errors.Is(err, ErrBudget) {
		t.Fatalf("total below the per-client budget: %v, want %v", err, ErrBudget)
	}

	srv, logs := newTestBulkServer(t, c, Budget{Window: time.Minute, PerClient: 3, Total: 5})
	clock := time.Unix(1_800_000_000, 0)
	srv.budget.now = func() time.Time { return clock }

	// Before the first update nothing is served, and the request still
	// counts.
	if _, err := srv.Tops("early"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("tops before an update: %v, want %v", err, ErrNoSnapshot)
	}
	if err := srv.Update(c.headers[23]); err != nil {
		t.Fatal(err)
	}
	if a, all := srv.budget.used("early"); a != 1 || all != 1 {
		t.Fatalf("request before the update charged %d, %d in all, want 1, 1", a, all)
	}
	clock = clock.Add(time.Minute)

	// Client a spends its three requests: the header, the tops and a PIR
	// query that reads its hint bucket.
	hd, err := srv.Header("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Tops("a"); err != nil {
		t.Fatal(err)
	}
	bi := headerEntry(t, hd, HintBucketTable, ghosttree.Coin)
	rec, err := pirRead(t, srv, "a", hd, bi, 0)
	if err != nil {
		t.Fatalf("third request of a: %v", err)
	}
	if !slices.Equal(rec, srv.Snapshot().Records(bi)[0]) {
		t.Fatal("bucket read through the server differs from the snapshot's")
	}
	logs.take()

	// Its fourth request of any kind is refused, before any work.
	if _, err := pirRead(t, srv, "a", hd, bi, 0); !errors.Is(err, ErrClientBudget) {
		t.Fatalf("fourth request of a, a query: %v, want %v", err, ErrClientBudget)
	}
	if got, err := srv.Blocks("a", 0); !errors.Is(err, ErrClientBudget) || got != nil {
		t.Fatalf("fourth request of a, blocks: %d blocks (%v), want %v", len(got), err, ErrClientBudget)
	}
	if got, err := srv.Header("a"); !errors.Is(err, ErrClientBudget) || got != nil {
		t.Fatalf("fourth request of a, header: %v, want %v", err, ErrClientBudget)
	}
	recs := logs.take()
	if countMessages(recs, "Answered PIR query") != 0 || countMessages(recs, "Refused PIR restore request") != 3 {
		t.Fatalf("refused requests logged %q", recs)
	}
	// A refusal is not charged.
	if a, all := srv.budget.used("a"); a != 3 || all != 3 {
		t.Fatalf("a charged %d, %d in all, want 3, 3", a, all)
	}

	// Another client has its own budget, until the total is spent.
	if _, err := srv.Blocks("b", 0); err != nil {
		t.Fatalf("first request of b: %v", err)
	}
	if _, err := pirRead(t, srv, "b", hd, bi, 0); err != nil {
		t.Fatalf("second request of b: %v", err)
	}
	if _, err := srv.Tops("b"); !errors.Is(err, ErrTotalBudget) {
		t.Fatalf("third request of b past the total: %v, want %v", err, ErrTotalBudget)
	}
	if _, err := srv.Header("c"); !errors.Is(err, ErrTotalBudget) {
		t.Fatalf("first request of c past the total: %v, want %v", err, ErrTotalBudget)
	}
	if b, all := srv.budget.used("b"); b != 2 || all != 5 {
		t.Fatalf("b charged %d, %d in all, want 2, 5", b, all)
	}

	// The budgets refill with the next window, not before.
	clock = clock.Add(time.Minute - time.Second)
	if _, err := srv.Tops("a"); !errors.Is(err, ErrClientBudget) {
		t.Fatalf("a inside the window: %v, want %v", err, ErrClientBudget)
	}
	clock = clock.Add(time.Second)
	if _, err := pirRead(t, srv, "a", hd, bi, 0); err != nil {
		t.Fatalf("a in the next window: %v", err)
	}
	if a, all := srv.budget.used("a"); a != 1 || all != 1 {
		t.Fatalf("next window charged a %d, %d in all, want 1, 1", a, all)
	}
}

func TestBulkServerReturnsOverflowPastSixteenSlots(t *testing.T) {
	c, tags := bulkTestChain(t)
	srv, _ := newTestBulkServer(t, c, Budget{Window: time.Minute, PerClient: 1000, Total: 1000})
	if err := srv.Update(c.headers[23]); err != nil {
		t.Fatal(err)
	}
	hd, err := srv.Header("wallet")
	if err != nil {
		t.Fatal(err)
	}
	if hd.Number != 20 {
		t.Fatalf("snapshot at block %d, want 20", hd.Number)
	}
	count := countLeaves(c, ghosttree.Coin, 20)
	if count != 59 {
		t.Fatalf("%d coin leaves at block 20, want 59", count)
	}
	bi := headerEntry(t, hd, HintBucketTable, ghosttree.Coin)
	oi := headerEntry(t, hd, HintOverflowTable, ghosttree.Coin)
	if hd.Entries[bi].Records != 1 || hd.Entries[oi].Records != count-HintSlots {
		t.Fatalf("%d buckets and %d overflow entries, want 1 and %d", hd.Entries[bi].Records, hd.Entries[oi].Records, count-HintSlots)
	}

	// The wallet reads the bucket of its tag (the only bucket of a tree this
	// small) through PIR: sixteen slots, and the run of the rest in the
	// overflow table.
	rec, err := pirRead(t, srv, "wallet", hd, bi, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeHintBucket(rec)
	if err != nil {
		t.Fatal(err)
	}
	if b.Total != uint64(count) || len(b.Slots) != HintSlots || b.Overflow != 0 {
		t.Fatalf("bucket of %d entries, %d slots, overflow at %d", b.Total, len(b.Slots), b.Overflow)
	}
	for i, e := range b.Slots {
		if e.Position != uint32(i) || e.Tag != tagBytes(tags[i]) {
			t.Fatalf("slot %d is position %d tag %x, want position %d tag %#x", i, e.Position, e.Tag, i, tags[i])
		}
	}
	// Every entry past the sixteen slots comes back from the overflow
	// database at its public index, in position order.
	for k := 0; k < int(b.Total)-HintSlots; k++ {
		rec, err := pirRead(t, srv, "wallet", hd, oi, int(b.Overflow)+k)
		if err != nil {
			t.Fatal(err)
		}
		e, err := DecodeHintOverflow(rec)
		if err != nil {
			t.Fatal(err)
		}
		want := HintSlots + k
		if e.Position != uint32(want) || e.Tag != tagBytes(tags[want]) {
			t.Fatalf("overflow entry %d is position %d tag %x, want position %d tag %#x", k, e.Position, e.Tag, want, tags[want])
		}
	}
	// The overflow run ends where the bucket says: there is no record past it.
	if _, err := EntryShape(hd, oi); err != nil {
		t.Fatal(err)
	}
	shape, _ := EntryShape(hd, oi)
	if _, _, err := shape.Locate(int(b.Overflow + b.Total - HintSlots)); !errors.Is(err, ErrIndex) {
		t.Fatalf("a record past the overflow run: %v, want %v", err, ErrIndex)
	}
	// A query to an entry without a database is refused.
	if _, err := srv.Query("wallet", len(hd.Entries), nil); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("query past the entries: %v, want %v", err, ErrNoDatabase)
	}
}

// wantBlock is the bulk data of block n of the chain, from the records the
// chain applied: tags of its coin and data leaves, then its markers with
// their positions in their lists.
func wantBlock(c *restoreChain, n uint64) BlockTags {
	b := BlockTags{Number: n, Hash: c.headers[n].Hash(), Tags: []TagEntry{}, Markers: []MarkerEntry{}}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		for _, r := range c.records[n] {
			if r.Kind == kind {
				e := TagEntry{Kind: kind, TreeIndex: r.TreeIndex, Position: r.Position}
				copy(e.Tag[:], r.Note[:ghosttree.TagBytes])
				b.Tags = append(b.Tags, e)
			}
		}
	}
	for _, kind := range []ghosttree.Kind{ghosttree.CoinMarkers, ghosttree.DataMarkers} {
		pos := uint64(len(c.markers(kind, n-1)))
		for _, r := range c.records[n] {
			if r.Kind == kind {
				b.Markers = append(b.Markers, MarkerEntry{Kind: kind, Position: pos, Marker: r.Leaf})
				pos++
			}
		}
	}
	return b
}

func checkBlocks(t *testing.T, c *restoreChain, got []BlockTags, from, to uint64) {
	t.Helper()
	if len(got) != int(to-from+1) {
		t.Fatalf("%d blocks, want blocks %d to %d", len(got), from, to)
	}
	for i, b := range got {
		want := wantBlock(c, from+uint64(i))
		if b.Number != want.Number || b.Hash != want.Hash || !slices.Equal(b.Tags, want.Tags) || !slices.Equal(b.Markers, want.Markers) {
			t.Fatalf("block %d served as %+v, the chain has %+v", want.Number, b, want)
		}
		if len(want.Tags) == 0 || len(want.Markers) == 0 {
			t.Fatalf("block %d of the test chain has no leaf or no marker", want.Number)
		}
	}
}

func TestBulkServerServesTopsAndBlocksAfterSnapshot(t *testing.T) {
	c, _ := bulkTestChain(t)
	srv, _ := newTestBulkServer(t, c, Budget{Window: time.Minute, PerClient: 1000, Total: 1000})
	if err := srv.Update(c.headers[23]); err != nil {
		t.Fatal(err)
	}
	anchor := c.headers[20]

	// The tops of every tree fold to the anchor header's root.
	tops, err := srv.Tops("wallet")
	if err != nil {
		t.Fatal(err)
	}
	if len(tops) != 2 || tops[0].Kind != ghosttree.Coin || tops[1].Kind != ghosttree.Data {
		t.Fatalf("%d tree tops, want coin tree 0 and data tree 0", len(tops))
	}
	for _, tt := range tops {
		if tt.Level != min(TopLevel, ghosttree.Release.Depth) || tt.Count != uint64(countLeaves(c, tt.Kind, 20)) || len(tt.Nodes) != 1 {
			t.Fatalf("%v tops at level %d over %d leaves, %d nodes", tt.Kind, tt.Level, tt.Count, len(tt.Nodes))
		}
		if tt.Root() != *ghosttree.HeaderRoot(anchor, tt.Kind) {
			t.Fatalf("%v tops fold to %x, block 20 has %x", tt.Kind, tt.Root(), *ghosttree.HeaderRoot(anchor, tt.Kind))
		}
		damaged := tt
		damaged.Nodes = []common.Hash{{1}}
		if damaged.Root() == tt.Root() {
			t.Fatalf("%v tops: a damaged node folds to the same root", tt.Kind)
		}
		if len(tt.Encode()) != 1+8+1+8+4+len(tt.Nodes)*common.HashLength {
			t.Fatalf("%v tops encode to %d bytes", tt.Kind, len(tt.Encode()))
		}
	}

	// The blocks after the snapshot: 21 to 23, each with its leaves' tags and
	// its markers.
	blocks, err := srv.Blocks("wallet", 0)
	if err != nil {
		t.Fatal(err)
	}
	checkBlocks(t, c, blocks, 21, 23)
	blocks, err = srv.Blocks("wallet", 22)
	if err != nil {
		t.Fatal(err)
	}
	checkBlocks(t, c, blocks, 23, 23)
	if blocks, err = srv.Blocks("wallet", 23); err != nil || len(blocks) != 0 {
		t.Fatalf("blocks after the head: %d (%v)", len(blocks), err)
	}
	old, err := srv.Header("wallet")
	if err != nil {
		t.Fatal(err)
	}

	// The chain moves on to block 41: the snapshot is rebuilt at block 40,
	// and the bulk data starts after it.
	for n := 24; n <= 41; n++ {
		c.block([]uint32{uint32(0x2000 + n)}, []uint32{uint32(0x3000 + n)}, 1, 1)
	}
	c.sync()
	if err := srv.Update(c.headers[41]); err != nil {
		t.Fatal(err)
	}
	hd, err := srv.Header("wallet")
	if err != nil {
		t.Fatal(err)
	}
	if hd.Number != 40 || hd.Anchor != c.headers[40].Hash() {
		t.Fatalf("snapshot at block %d after head 41, want 40", hd.Number)
	}
	blocks, err = srv.Blocks("wallet", 0)
	if err != nil {
		t.Fatal(err)
	}
	checkBlocks(t, c, blocks, 41, 41)
	tops, err = srv.Tops("wallet")
	if err != nil {
		t.Fatal(err)
	}
	if tops[0].Root() != *c.headers[40].CoinTreeRoot || tops[1].Root() != *c.headers[40].DataTreeRoot {
		t.Fatal("tops after the rebuild do not fold to block 40's roots")
	}
	// A query made under the old snapshot is refused.
	bi := headerEntry(t, old, HintBucketTable, ghosttree.Coin)
	if _, err := pirRead(t, srv, "wallet", old, bi, 0); !errors.Is(err, ErrStaleSnapshot) {
		t.Fatalf("query under the replaced snapshot: %v, want %v", err, ErrStaleSnapshot)
	}
}
