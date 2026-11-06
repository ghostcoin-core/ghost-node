package ghostpir

import (
	"encoding/binary"
	"math/big"
	"reflect"
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

// restoreChain is a canonical header chain in a database with the tree
// history of its records. Leaves are appended to real tree state, so the
// header roots are those core/ghosttree computes.
type restoreChain struct {
	t       *testing.T
	db      ethdb.Database
	h       *ghosttree.History
	st      *state.StateDB
	headers []*types.Header
	records [][]ghosttree.Record
	seq     uint64
}

func newRestoreChain(t *testing.T) *restoreChain {
	t.Helper()
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	db := rawdb.NewMemoryDatabase()
	c := &restoreChain{t: t, db: db, h: ghosttree.NewHistory(db), st: st}
	c.seal(nil)
	return c
}

func seqBytes(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b[:]
}

// setNoteTag writes tag, big-endian, over the first TagBytes bytes of note.
func setNoteTag(note *[ghosttree.NoteBytes]byte, tag uint32) {
	for i := ghosttree.TagBytes - 1; i >= 0; i-- {
		note[i] = byte(tag)
		tag >>= 8
	}
}

func tagBytes(tag uint32) (out [ghosttree.TagBytes]byte) {
	for i := ghosttree.TagBytes - 1; i >= 0; i-- {
		out[i] = byte(tag)
		tag >>= 8
	}
	return out
}

// block adds a canonical block whose coin and data leaves have notes with
// the given tags, and which spends the given numbers of coin and data
// markers. Every third leaf is a salted commit.
func (c *restoreChain) block(coinTags, dataTags []uint32, coinMarkers, dataMarkers int) {
	c.t.Helper()
	number := uint64(len(c.headers))
	var recs []ghosttree.Record
	for _, k := range []struct {
		kind ghosttree.Kind
		tags []uint32
	}{{ghosttree.Coin, coinTags}, {ghosttree.Data, dataTags}} {
		for _, tag := range k.tags {
			c.seq++
			leaf := ghosttree.K("ghost/pir-test-leaf", seqBytes(c.seq))
			res, err := ghosttree.Append(c.st, k.kind, number, leaf)
			if err != nil {
				c.t.Fatal(err)
			}
			var note [ghosttree.NoteBytes]byte
			for i := 0; i < len(note); i += common.HashLength {
				copy(note[i:], leaf[:])
			}
			setNoteTag(&note, tag)
			rec := ghosttree.Record{Kind: res.Kind, TreeIndex: res.TreeIndex, Position: res.Position, Leaf: leaf, Note: note}
			if c.seq%3 == 0 {
				salt := new([ghosttree.SaltBytes]byte)
				copy(salt[:], ghosttree.K("ghost/pir-test-salt", seqBytes(c.seq)).Bytes())
				rec.Salt = salt
			}
			recs = append(recs, rec)
		}
	}
	for _, k := range []struct {
		kind ghosttree.Kind
		n    int
	}{{ghosttree.CoinMarkers, coinMarkers}, {ghosttree.DataMarkers, dataMarkers}} {
		for i := 0; i < k.n; i++ {
			c.seq++
			recs = append(recs, ghosttree.Record{Kind: k.kind, Leaf: ghosttree.K("ghost/pir-test-marker", seqBytes(c.seq))})
		}
	}
	c.seal(recs)
}

// seal writes the header of the next block over the current tree state.
func (c *restoreChain) seal(recs []ghosttree.Record) {
	c.t.Helper()
	coin, err := ghosttree.Root(c.st, ghosttree.Coin)
	if err != nil {
		c.t.Fatal(err)
	}
	data, err := ghosttree.Root(c.st, ghosttree.Data)
	if err != nil {
		c.t.Fatal(err)
	}
	marker, err := ghosttree.DataMarkerRoot(c.st)
	if err != nil {
		c.t.Fatal(err)
	}
	number := uint64(len(c.headers))
	header := &types.Header{Number: new(big.Int).SetUint64(number), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1), CoinTreeRoot: &coin, DataTreeRoot: &data, DataMarkerRoot: &marker}
	if number > 0 {
		header.ParentHash = c.headers[number-1].Hash()
	}
	rawdb.WriteHeader(c.db, header)
	rawdb.WriteCanonicalHash(c.db, header.Hash(), number)
	c.headers = append(c.headers, header)
	c.records = append(c.records, recs)
}

// sync makes the history hold the chain up to its head.
func (c *restoreChain) sync() {
	c.t.Helper()
	head := c.headers[len(c.headers)-1]
	if err := c.h.Sync(head, func(h *types.Header) ([]ghosttree.Record, error) {
		return c.records[h.Number.Uint64()], nil
	}); err != nil {
		c.t.Fatalf("sync: %v", err)
	}
}

// markers returns the markers of a kind spent up to and including block
// number, in order.
func (c *restoreChain) markers(kind ghosttree.Kind, number uint64) []common.Hash {
	var out []common.Hash
	for _, recs := range c.records[:number+1] {
		for _, r := range recs {
			if r.Kind == kind {
				out = append(out, r.Leaf)
			}
		}
	}
	return out
}

// served returns every entry of tree 0 of a kind as the history serves it
// as of anchor, page by page, and its page-root list.
func served(t *testing.T, h *ghosttree.History, kind ghosttree.Kind, anchor common.Hash) ([]ghosttree.PageEntry, []common.Hash) {
	t.Helper()
	roots, err := h.PageRoots(kind, 0, anchor)
	if err != nil {
		t.Fatal(err)
	}
	var out []ghosttree.PageEntry
	for p := range roots {
		page, err := h.Page(kind, 0, uint32(p), anchor)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, page.Entries...)
	}
	return out, roots
}

func findTable(t *testing.T, tables []*HintTable, kind ghosttree.Kind, index uint64) *HintTable {
	t.Helper()
	for _, tb := range tables {
		if tb.Kind == kind && tb.TreeIndex == index {
			return tb
		}
	}
	t.Fatalf("no hint table for %v tree %d", kind, index)
	return nil
}

// overflowRun is the entries of bucket k in the overflow table.
func overflowRun(tb *HintTable, k int) []HintEntry {
	b := tb.Buckets[k]
	return tb.Overflow[b.Overflow : b.Overflow+b.overflowCount()]
}

func positionsOf(entries []HintEntry) []uint32 {
	out := make([]uint32, len(entries))
	for i, e := range entries {
		out[i] = e.Position
	}
	return out
}

// readBack fetches records of a set through a PIR database, server and
// client, and checks each against the set's own record.
func readBack(t *testing.T, label string, size int, records [][]byte, indexes ...int) [][]byte {
	t.Helper()
	db, err := NewDatabase(testSeed(label), size, records)
	if err != nil {
		t.Fatalf("%s: NewDatabase: %v", label, err)
	}
	srv := NewServer(db, log.NewLogger(new(recordingHandler)))
	c, err := NewClient(srv.Shape())
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, i := range indexes {
		got, _, _ := fetch(t, srv, c, i, nil)
		if !slices.Equal(got, records[i]) {
			t.Fatalf("%s: record %d read back differs from the built record", label, i)
		}
		out = append(out, got)
	}
	return out
}

func TestHintTableFindsTagInBucket(t *testing.T) {
	c := newRestoreChain(t)
	n := 2*ghosttree.MinBucketNotes + 40 // one prefix bit
	coinTags := make([]uint32, n)
	var high []uint32 // the positions whose tag starts with a 1 bit
	for i := range coinTags {
		coinTags[i] = uint32(i*7919) % (1 << 23)
		if i%600 == 5 {
			coinTags[i] |= 1 << 23
			high = append(high, uint32(i))
		}
	}
	coinTags[300] = coinTags[100] // two notes with one tag
	dataTags := []uint32{0xabcdef, 0x000001, 0x7fffff}
	c.block(coinTags[:5000], nil, 0, 0)
	c.block(coinTags[5000:], dataTags, 0, 0)
	c.sync()
	anchor := c.headers[2].Hash()

	tables, err := BuildHintTables(c.h, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 2 {
		t.Fatalf("%d hint tables, want one per tree of each kind", len(tables))
	}
	coin := findTable(t, tables, ghosttree.Coin, 0)
	if coin.Count != uint64(n) || coin.Bits != 1 || ghosttree.BucketBits(uint64(n)) != 1 || len(coin.Buckets) != 2 {
		t.Fatalf("coin table of %d leaves, %d bits, %d buckets", coin.Count, coin.Bits, len(coin.Buckets))
	}
	// Every tag finds its bucket from the tag and the leaf count alone, and
	// the bucket (or its overflow run) gives the tag's position.
	for i, tag := range coinTags {
		tb := tagBytes(tag)
		if got, want := HintBucketOf(uint64(n), tb), tag>>23; got != want {
			t.Fatalf("position %d: tag %#x in bucket %d, want %d", i, tag, got, want)
		}
		if !slices.Contains(coin.Lookup(tb), uint32(i)) {
			t.Fatalf("position %d: tag %#x not found, lookup gives %v", i, tag, coin.Lookup(tb))
		}
	}
	if got := coin.Lookup(tagBytes(coinTags[100])); !slices.Equal(got, []uint32{100, 300}) {
		t.Fatalf("shared tag gives positions %v, want [100 300]", got)
	}
	var absent uint32 = 1 << 23
	for slices.Contains(coinTags, absent) {
		absent++
	}
	if got := coin.Lookup(tagBytes(absent)); len(got) != 0 {
		t.Fatalf("absent tag %#x gives positions %v", absent, got)
	}
	// The bucket of the 1 bit holds its entries in its slots alone.
	b1 := coin.Buckets[1]
	if b1.Total != uint64(len(high)) || !slices.Equal(positionsOf(b1.Slots), high) || len(overflowRun(coin, 1)) != 0 {
		t.Fatalf("bucket 1: total %d, slots %v, want %v in the slots", b1.Total, positionsOf(b1.Slots), high)
	}
	for _, e := range b1.Slots {
		if e.Tag != tagBytes(coinTags[e.Position]) {
			t.Fatalf("bucket 1: position %d under tag %x", e.Position, e.Tag)
		}
	}
	// A bucket is the history's own note bucket under the same prefix rule.
	for k := range coin.Buckets {
		nb, err := ghosttree.ReadNoteBucket(c.h, ghosttree.Coin, 0, coin.Bits, uint32(k), anchor)
		if err != nil {
			t.Fatal(err)
		}
		var want []uint32
		for _, e := range nb.Entries {
			want = append(want, e.Position)
		}
		got := append(positionsOf(coin.Buckets[k].Slots), positionsOf(overflowRun(coin, k))...)
		if !slices.Equal(got, want) {
			t.Fatalf("bucket %d: %d positions, the history's note bucket has %d", k, len(got), len(want))
		}
	}
	data := findTable(t, tables, ghosttree.Data, 0)
	if data.Count != 3 || data.Bits != 0 || len(data.Buckets) != 1 {
		t.Fatalf("data table of %d leaves, %d bits", data.Count, data.Bits)
	}
	for i, tag := range dataTags {
		if got := data.Lookup(tagBytes(tag)); !slices.Equal(got, []uint32{uint32(i)}) {
			t.Fatalf("data tag %#x gives %v, want [%d]", tag, got, i)
		}
	}
	// A wallet reads its bucket through the PIR database at the bucket's
	// index and gets the table's bucket.
	recs := readBack(t, "hint buckets", HintBucketRecordSize, coin.BucketRecords(), 1, 0)
	for i, k := range []int{1, 0} {
		got, err := DecodeHintBucket(recs[i])
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, coin.Buckets[k]) {
			t.Fatalf("bucket %d read back as %+v", k, got)
		}
	}
}

func TestHintOverflowHoldsEntriesPastSixteenSlots(t *testing.T) {
	t.Run("from the tree history", func(t *testing.T) {
		c := newRestoreChain(t)
		tags := make([]uint32, 40)
		for i := range tags {
			tags[i] = uint32(i*104729+17) % (1 << 24)
		}
		dataTags := []uint32{5, 6, 7, 8, 9, 10, 11, 12, 13}
		c.block(tags[:10], dataTags, 0, 0)
		c.block(tags[10:25], nil, 0, 0)
		c.block(tags[25:], nil, 0, 0)
		c.sync()

		for _, tc := range []struct {
			anchor int
			count  int
		}{{3, 40}, {2, 25}, {1, 10}} {
			tables, err := BuildHintTables(c.h, c.headers[tc.anchor].Hash())
			if err != nil {
				t.Fatal(err)
			}
			coin := findTable(t, tables, ghosttree.Coin, 0)
			if coin.Count != uint64(tc.count) || len(coin.Buckets) != 1 {
				t.Fatalf("anchor %d: %d leaves in %d buckets", tc.anchor, coin.Count, len(coin.Buckets))
			}
			b := coin.Buckets[0]
			slots := min(tc.count, HintSlots)
			if b.Total != uint64(tc.count) || len(b.Slots) != slots || b.Overflow != 0 {
				t.Fatalf("anchor %d: bucket total %d, %d slots, overflow at %d", tc.anchor, b.Total, len(b.Slots), b.Overflow)
			}
			for i, e := range append(slices.Clone(b.Slots), coin.Overflow...) {
				if e.Position != uint32(i) || e.Tag != tagBytes(tags[i]) {
					t.Fatalf("anchor %d: entry %d is position %d tag %x, want position %d tag %#x", tc.anchor, i, e.Position, e.Tag, i, tags[i])
				}
			}
			if len(coin.Overflow) != tc.count-slots {
				t.Fatalf("anchor %d: %d overflow entries, want %d", tc.anchor, len(coin.Overflow), tc.count-slots)
			}
			for i := range tc.count {
				if got := coin.Lookup(tagBytes(tags[i])); !slices.Equal(got, []uint32{uint32(i)}) {
					t.Fatalf("anchor %d: tag of position %d gives %v", tc.anchor, i, got)
				}
			}
			data := findTable(t, tables, ghosttree.Data, 0)
			if data.Buckets[0].Total != 9 || len(data.Buckets[0].Slots) != 9 || len(data.Overflow) != 0 {
				t.Fatalf("anchor %d: data bucket of 9 notes spilled", tc.anchor)
			}
		}
	})

	t.Run("a bucket past its slots among others", func(t *testing.T) {
		n := 2 * ghosttree.MinBucketNotes // one prefix bit
		tags := make([][ghosttree.TagBytes]byte, n)
		var high []uint32
		for i := range tags {
			tag := uint32(i*31) % (1 << 23)
			if i%271 == 3 && len(high) < 30 {
				tag |= 1 << 23
				high = append(high, uint32(i))
			}
			tags[i] = tagBytes(tag)
		}
		tb, err := NewHintTable(ghosttree.Coin, 0, tags)
		if err != nil {
			t.Fatal(err)
		}
		if tb.Bits != 1 || len(high) != 30 {
			t.Fatalf("%d bits, %d entries in bucket 1", tb.Bits, len(high))
		}
		b0, b1 := tb.Buckets[0], tb.Buckets[1]
		if b1.Total != 30 || !slices.Equal(positionsOf(b1.Slots), high[:HintSlots]) {
			t.Fatalf("bucket 1: total %d, slots %v", b1.Total, positionsOf(b1.Slots))
		}
		// The overflow table runs bucket after bucket; each run is the
		// bucket's entries past its slots, in position order.
		if b0.Overflow != 0 || b1.Overflow != b0.Total-HintSlots || len(tb.Overflow) != n-2*HintSlots {
			t.Fatalf("overflow runs at %d and %d of %d entries", b0.Overflow, b1.Overflow, len(tb.Overflow))
		}
		if got := positionsOf(overflowRun(tb, 1)); !slices.Equal(got, high[HintSlots:]) {
			t.Fatalf("bucket 1 overflow %v, want %v", got, high[HintSlots:])
		}
		run0 := positionsOf(overflowRun(tb, 0))
		if !slices.IsSorted(run0) || slices.Contains(run0, high[0]) {
			t.Fatalf("bucket 0 overflow not in position order or holds another bucket's entry")
		}
		// Nothing is lost: every position is in exactly one slot or overflow
		// entry, under its own tag.
		seen := make([]int, n)
		for _, b := range tb.Buckets {
			for _, e := range b.Slots {
				seen[e.Position]++
				if e.Tag != tags[e.Position] {
					t.Fatalf("position %d under another tag", e.Position)
				}
			}
		}
		for _, e := range tb.Overflow {
			seen[e.Position]++
			if e.Tag != tags[e.Position] {
				t.Fatalf("overflow position %d under another tag", e.Position)
			}
		}
		for pos, k := range seen {
			if k != 1 {
				t.Fatalf("position %d held %d times", pos, k)
			}
		}
		for _, pos := range high[HintSlots:] {
			if got := tb.Lookup(tags[pos]); !slices.Contains(got, pos) {
				t.Fatalf("overflowed position %d not found: %v", pos, got)
			}
		}
		// The records decode to the table.
		for k, rec := range tb.BucketRecords() {
			got, err := DecodeHintBucket(rec)
			if err != nil || !reflect.DeepEqual(got, tb.Buckets[k]) {
				t.Fatalf("bucket record %d decodes to %+v (%v)", k, got, err)
			}
		}
		orecs := tb.OverflowRecords()
		if len(orecs) != len(tb.Overflow) {
			t.Fatalf("%d overflow records for %d entries", len(orecs), len(tb.Overflow))
		}
		for i, rec := range orecs {
			if got, err := DecodeHintOverflow(rec); err != nil || got != tb.Overflow[i] {
				t.Fatalf("overflow record %d decodes to %+v (%v)", i, got, err)
			}
		}
		// A wallet reads an overflow entry of its bucket at its public index.
		at := int(b1.Overflow) + 2
		got := readBack(t, "hint overflow", HintOverflowRecordSize, orecs, at)
		if e, err := DecodeHintOverflow(got[0]); err != nil || e.Position != high[HintSlots+2] {
			t.Fatalf("overflow entry %d read back as %+v (%v)", at, e, err)
		}
	})
}

// listRoot folds a whole marker list up the list tree in one pass.
func listRoot(markers []common.Hash) common.Hash {
	z := ghosttree.EmptyLeaf
	cur := slices.Clone(markers)
	for l := 0; l < ghosttree.Release.Depth; l++ {
		var next []common.Hash
		for i := 0; i < len(cur); i += 2 {
			right := z
			if i+1 < len(cur) {
				right = cur[i+1]
			}
			next = append(next, ghosttree.K(MarkerListTag, []byte{byte(l)}, cur[i][:], right[:]))
		}
		z = ghosttree.K(MarkerListTag, []byte{byte(l)}, z[:], z[:])
		cur = next
	}
	if len(cur) == 0 {
		return z
	}
	return cur[0]
}

func siblingArray(t *testing.T, s []common.Hash) (out [32]common.Hash) {
	t.Helper()
	if len(s) != ghosttree.Release.Depth {
		t.Fatalf("%d siblings, want %d", len(s), ghosttree.Release.Depth)
	}
	copy(out[:], s)
	return out
}

func pageLeaves(entries []ghosttree.PageEntry, page int) []common.Hash {
	end := min(len(entries), (page+1)*ghosttree.PageLeaves)
	var out []common.Hash
	for _, e := range entries[page*ghosttree.PageLeaves : end] {
		out = append(out, e.Leaf)
	}
	return out
}

// checkTree checks the notes and witness records of tree 0 of a kind
// against the history's own pages, page roots and witnesses, and every
// witness against the header's root.
func checkTree(t *testing.T, h *ghosttree.History, header *types.Header, kind ghosttree.Kind, notes, wits *RecordSet) {
	t.Helper()
	anchor := header.Hash()
	entries, roots := served(t, h, kind, anchor)
	if len(notes.Records) != len(entries) || len(wits.Records) != len(entries) {
		t.Fatalf("%v: %d notes and %d witnesses for %d leaves", kind, len(notes.Records), len(wits.Records), len(entries))
	}
	if notes.Root != *ghosttree.HeaderRoot(header, kind) || wits.Root != notes.Root {
		t.Fatalf("%v: records under root %x, header %x", kind, wits.Root, *ghosttree.HeaderRoot(header, kind))
	}
	last := len(entries) - 1
	samples := []int{0, 1, ghosttree.PageLeaves - 1, ghosttree.PageLeaves, last}
	for pos, rec := range notes.Records {
		if len(rec) != NoteRecordSize {
			t.Fatalf("%v note %d of %d bytes", kind, pos, len(rec))
		}
		got, err := DecodeNoteRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, entries[pos]) {
			t.Fatalf("%v note %d differs from the history's", kind, pos)
		}
	}
	for pos, rec := range wits.Records {
		var (
			leaf = entries[pos].Leaf
			sib  []common.Hash
			err  error
		)
		if kind == ghosttree.Data {
			var got common.Hash
			got, sib, err = DecodeLeafWitnessRecord(rec)
			if err == nil && got != leaf {
				t.Fatalf("lookup %d holds leaf %x, the history %x", pos, got, leaf)
			}
		} else {
			sib, err = DecodeWitnessRecord(rec)
		}
		if err != nil {
			t.Fatal(err)
		}
		arr := siblingArray(t, sib)
		if !ghosttree.VerifyMembership(header, kind, uint32(pos), leaf, arr) {
			t.Fatalf("%v witness %d does not verify against the header root", kind, pos)
		}
		if slices.Contains(samples, pos) {
			page := pos / ghosttree.PageLeaves
			want, err := ghosttree.Witness(kind, uint32(pos), pageLeaves(entries, page), roots)
			if err != nil {
				t.Fatal(err)
			}
			if arr != want {
				t.Fatalf("%v witness %d differs from the history's own", kind, pos)
			}
			arr[3][0] ^= 1
			if ghosttree.VerifyMembership(header, kind, uint32(pos), leaf, arr) {
				t.Fatalf("%v witness %d verifies with a damaged sibling", kind, pos)
			}
		}
	}
}

func TestDatabasesMatchTreeHistory(t *testing.T) {
	c := newRestoreChain(t)
	tags := func(n int) []uint32 {
		out := make([]uint32, n)
		for i := range out {
			out[i] = uint32(c.seq+uint64(i)) * 2654435761 >> 8
		}
		return out
	}
	// The data tree passes eight pages, so it is read in more than one page
	// set; the coin tree and the data marker list span two pages.
	c.block(tags(3000), tags(20000), 7, 3000)
	c.block(tags(1200), tags(16900), 0, 1500)
	c.block(tags(5), tags(3), 2, 0)
	c.sync()
	head := c.headers[3]

	dbs, err := BuildDatabases(c.h, head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs.Notes) != 2 || len(dbs.CoinWitnesses) != 1 || len(dbs.Lookups) != 1 || len(dbs.Markers) != 2 {
		t.Fatalf("%d note, %d witness, %d lookup and %d marker databases", len(dbs.Notes), len(dbs.CoinWitnesses), len(dbs.Lookups), len(dbs.Markers))
	}
	if n := len(dbs.Lookups[0].Records); n != 36903 || n <= ghosttree.PageSetPages*ghosttree.PageLeaves {
		t.Fatalf("data tree of %d leaves", n)
	}
	checkTree(t, c.h, head, ghosttree.Coin, dbs.Notes[0], dbs.CoinWitnesses[0])
	checkTree(t, c.h, head, ghosttree.Data, dbs.Notes[1], dbs.Lookups[0])

	for i, kind := range []ghosttree.Kind{ghosttree.CoinMarkers, ghosttree.DataMarkers} {
		set := dbs.Markers[i]
		want := c.markers(kind, 3)
		if set.Kind != kind || set.TreeIndex != 0 || len(set.Records) != len(want) {
			t.Fatalf("%v: %d marker records, want %d", kind, len(set.Records), len(want))
		}
		if set.Root != listRoot(want) {
			t.Fatalf("%v: list root %x, the list folds to %x", kind, set.Root, listRoot(want))
		}
		for pos, rec := range set.Records {
			marker, sib, err := DecodeLeafWitnessRecord(rec)
			if err != nil {
				t.Fatal(err)
			}
			if marker != want[pos] {
				t.Fatalf("%v marker %d differs from the chain's", kind, pos)
			}
			if !VerifyMarkerWitness(set.Root, uint64(pos), marker, sib) {
				t.Fatalf("%v marker %d does not verify against the list root", kind, pos)
			}
			if VerifyMarkerWitness(set.Root, uint64(pos)^1, marker, sib) {
				t.Fatalf("%v marker %d verifies at another position", kind, pos)
			}
		}
		page, err := c.h.MarkerPage(kind, 0, 0, head.Hash())
		if err != nil {
			t.Fatal(err)
		}
		for pos, m := range page.Markers {
			if got, _, _ := DecodeLeafWitnessRecord(set.Records[pos]); got != m {
				t.Fatalf("%v marker %d differs from the history's marker page", kind, pos)
			}
		}
	}

	// Every database reads back through PIR at the record's index.
	for _, set := range append(append(append(slices.Clone(dbs.Notes), dbs.CoinWitnesses...), dbs.Lookups...), dbs.Markers...) {
		last := len(set.Records) - 1
		db, err := set.Database(testSeed(set.Kind.String()))
		if err != nil {
			t.Fatal(err)
		}
		if db.Shape().RecordSize != set.RecordSize {
			t.Fatalf("%v database of %d-byte records, set of %d", set.Kind, db.Shape().RecordSize, set.RecordSize)
		}
		readBack(t, set.Kind.String()+" read back", set.RecordSize, set.Records, 0, last/2, last)
	}

	// The same history and anchor build byte-identical tables and databases.
	again, err := BuildDatabases(c.h, head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dbs, again) {
		t.Fatal("two builds of the databases differ")
	}
	t1, err := BuildHintTables(c.h, head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	t2, err := BuildHintTables(c.h, head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(t1, t2) {
		t.Fatal("two builds of the hint tables differ")
	}
	for i := range t1 {
		if !reflect.DeepEqual(t1[i].BucketRecords(), t2[i].BucketRecords()) || !reflect.DeepEqual(t1[i].OverflowRecords(), t2[i].OverflowRecords()) {
			t.Fatalf("hint table %d records differ between builds", i)
		}
	}
	seed := testSeed("identical")
	d1, err := dbs.CoinWitnesses[0].Database(seed)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := again.CoinWitnesses[0].Database(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d1, d2) {
		t.Fatal("two PIR databases of the same records differ")
	}

	// The databases are as of the anchor: an earlier anchor builds the
	// trees and lists as they were at it.
	early := c.headers[1]
	old, err := BuildDatabases(c.h, early.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Notes[0].Records) != 3000 || len(old.Lookups[0].Records) != 20000 || len(old.Markers[0].Records) != 7 || len(old.Markers[1].Records) != 3000 {
		t.Fatalf("as of block 1: %d coin notes, %d lookups, %d and %d markers", len(old.Notes[0].Records), len(old.Lookups[0].Records), len(old.Markers[0].Records), len(old.Markers[1].Records))
	}
	if old.CoinWitnesses[0].Root != *early.CoinTreeRoot || old.Markers[1].Root != listRoot(c.markers(ghosttree.DataMarkers, 1)) {
		t.Fatal("as of block 1: roots differ from the chain's at block 1")
	}
	sib, err := DecodeWitnessRecord(old.CoinWitnesses[0].Records[2999])
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := DecodeNoteRecord(old.Notes[0].Records[2999])
	if !ghosttree.VerifyMembership(early, ghosttree.Coin, 2999, leaf.Leaf, siblingArray(t, sib)) {
		t.Fatal("as of block 1: the last coin witness does not verify against block 1")
	}
}
