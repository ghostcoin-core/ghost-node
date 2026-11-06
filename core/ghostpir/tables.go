package ghostpir

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// The hint table of a tree maps the tag of every note (the first
// ghosttree.TagBytes bytes of the note) to the leaf position of the note, so
// that a wallet that knows its tags learns its positions without a scan.
//
// The table is a list of buckets of HintSlots slots. The bucket of a tag is
// its first ghosttree.BucketBits(count) bits, count the leaves of the tree at
// the anchor: the prefix rule of ghosttree.ReadNoteBucket. A wallet finds the
// bucket of a tag from public data alone (the tag and the leaf count) and so
// the index of its record in the bucket database.
//
// A bucket keeps its first HintSlots entries, in position order, in its
// slots. The entries past them go to the overflow table, bucket after
// bucket, each bucket's in position order, and the bucket records where its
// run starts and how many entries it has in all, so nothing is lost and the
// overflow records of a bucket sit at public indexes.

// HintSlots is the number of slots of a hint bucket.
const HintSlots = 16

const (
	// HintEntryBytes is one entry on the wire: the tag, then the position
	// as 4 big-endian bytes.
	HintEntryBytes = ghosttree.TagBytes + 4

	// hintBucketHeader is the start of a bucket record: the number of its
	// entries and the index of its first overflow entry, 8 big-endian bytes
	// each.
	hintBucketHeader = 8 + 8

	// HintBucketRecordSize is the record of a bucket: its header, then
	// HintSlots entries, the unused ones zero.
	HintBucketRecordSize = hintBucketHeader + HintSlots*HintEntryBytes

	// HintOverflowRecordSize is the record of one overflow entry.
	HintOverflowRecordSize = HintEntryBytes
)

var (
	// ErrHintRecord is returned for a hint record that does not decode.
	ErrHintRecord = errors.New("ghostpir: malformed hint record")

	// ErrHintTree is returned for a tree that no hint table can hold.
	ErrHintTree = errors.New("ghostpir: tree beyond a hint table")
)

// HintEntry is one note of a tree: its tag and its leaf position.
type HintEntry struct {
	Tag      [ghosttree.TagBytes]byte
	Position uint32
}

// HintBucket is one bucket of a hint table.
type HintBucket struct {
	Total    uint64      // entries of the bucket, slots and overflow
	Overflow uint64      // index in the overflow table of its first entry past the slots
	Slots    []HintEntry // its first min(Total, HintSlots) entries, in position order
}

// overflowCount is the number of the bucket's entries in the overflow table.
func (b HintBucket) overflowCount() uint64 { return b.Total - uint64(len(b.Slots)) }

// HintTable is the hint table of one tree as of an anchor.
type HintTable struct {
	Kind      ghosttree.Kind
	TreeIndex uint64
	Count     uint64       // leaves of the tree at the anchor
	Bits      uint32       // ghosttree.BucketBits(Count)
	Buckets   []HintBucket // 2^Bits buckets, by prefix
	Overflow  []HintEntry  // the entries past the slots, by bucket, then position
}

// tagNumber is a tag as a big-endian number.
func tagNumber(tag [ghosttree.TagBytes]byte) uint32 {
	var n uint32
	for _, b := range tag {
		n = n<<8 | uint32(b)
	}
	return n
}

// HintBucketOf is the bucket of a tag in the hint table of a tree of count
// leaves: the first ghosttree.BucketBits(count) bits of the tag.
func HintBucketOf(count uint64, tag [ghosttree.TagBytes]byte) uint32 {
	return tagNumber(tag) >> (ghosttree.MaxBucketBits - ghosttree.BucketBits(count))
}

// NewHintTable builds the hint table of tree treeIndex of a kind whose leaf
// at position i has a note starting with tags[i].
func NewHintTable(kind ghosttree.Kind, treeIndex uint64, tags [][ghosttree.TagBytes]byte) (*HintTable, error) {
	count := uint64(len(tags))
	if count > uint64(1)<<32 {
		return nil, fmt.Errorf("%w: %d leaves", ErrHintTree, count)
	}
	bits := ghosttree.BucketBits(count)
	t := &HintTable{Kind: kind, TreeIndex: treeIndex, Count: count, Bits: bits, Buckets: make([]HintBucket, 1<<bits)}
	// The entries past the slots of each bucket, in position order.
	var spill [][]HintEntry
	for pos, tag := range tags {
		k := HintBucketOf(count, tag)
		b := &t.Buckets[k]
		e := HintEntry{Tag: tag, Position: uint32(pos)}
		b.Total++
		if len(b.Slots) < HintSlots {
			b.Slots = append(b.Slots, e)
			continue
		}
		if spill == nil {
			spill = make([][]HintEntry, len(t.Buckets))
		}
		spill[k] = append(spill[k], e)
	}
	t.Overflow = []HintEntry{}
	for k := range t.Buckets {
		t.Buckets[k].Overflow = uint64(len(t.Overflow))
		if spill != nil {
			t.Overflow = append(t.Overflow, spill[k]...)
		}
	}
	return t, nil
}

// Lookup returns the positions of the notes of the table's tree whose tag is
// tag, in position order: those in the slots of the tag's bucket, then those
// of its run of the overflow table.
func (t *HintTable) Lookup(tag [ghosttree.TagBytes]byte) []uint32 {
	b := t.Buckets[HintBucketOf(t.Count, tag)]
	var out []uint32
	for _, e := range b.Slots {
		if e.Tag == tag {
			out = append(out, e.Position)
		}
	}
	for _, e := range t.Overflow[b.Overflow : b.Overflow+b.overflowCount()] {
		if e.Tag == tag {
			out = append(out, e.Position)
		}
	}
	return out
}

func putHintEntry(dst []byte, e HintEntry) {
	copy(dst, e.Tag[:])
	binary.BigEndian.PutUint32(dst[ghosttree.TagBytes:], e.Position)
}

func readHintEntry(src []byte) HintEntry {
	var e HintEntry
	copy(e.Tag[:], src)
	e.Position = binary.BigEndian.Uint32(src[ghosttree.TagBytes:])
	return e
}

// BucketRecords returns the record of every bucket, by prefix, each
// HintBucketRecordSize bytes: the records of the bucket database.
func (t *HintTable) BucketRecords() [][]byte {
	slab := make([]byte, len(t.Buckets)*HintBucketRecordSize)
	out := make([][]byte, len(t.Buckets))
	for k, b := range t.Buckets {
		rec := slab[k*HintBucketRecordSize : (k+1)*HintBucketRecordSize : (k+1)*HintBucketRecordSize]
		binary.BigEndian.PutUint64(rec, b.Total)
		binary.BigEndian.PutUint64(rec[8:], b.Overflow)
		for i, e := range b.Slots {
			putHintEntry(rec[hintBucketHeader+i*HintEntryBytes:], e)
		}
		out[k] = rec
	}
	return out
}

// OverflowRecords returns the record of every overflow entry, in the order
// of the overflow table, each HintOverflowRecordSize bytes: the records of
// the overflow database.
func (t *HintTable) OverflowRecords() [][]byte {
	slab := make([]byte, len(t.Overflow)*HintOverflowRecordSize)
	out := make([][]byte, len(t.Overflow))
	for i, e := range t.Overflow {
		rec := slab[i*HintOverflowRecordSize : (i+1)*HintOverflowRecordSize : (i+1)*HintOverflowRecordSize]
		putHintEntry(rec, e)
		out[i] = rec
	}
	return out
}

// DecodeHintBucket decodes a bucket record.
func DecodeHintBucket(rec []byte) (HintBucket, error) {
	if len(rec) != HintBucketRecordSize {
		return HintBucket{}, fmt.Errorf("%w: bucket of %d bytes", ErrHintRecord, len(rec))
	}
	b := HintBucket{Total: binary.BigEndian.Uint64(rec), Overflow: binary.BigEndian.Uint64(rec[8:])}
	n := int(min(b.Total, HintSlots))
	b.Slots = make([]HintEntry, n)
	for i := range b.Slots {
		b.Slots[i] = readHintEntry(rec[hintBucketHeader+i*HintEntryBytes:])
	}
	for _, c := range rec[hintBucketHeader+n*HintEntryBytes:] {
		if c != 0 {
			return HintBucket{}, fmt.Errorf("%w: unused slot not zero", ErrHintRecord)
		}
	}
	return b, nil
}

// DecodeHintOverflow decodes an overflow record.
func DecodeHintOverflow(rec []byte) (HintEntry, error) {
	if len(rec) != HintOverflowRecordSize {
		return HintEntry{}, fmt.Errorf("%w: overflow entry of %d bytes", ErrHintRecord, len(rec))
	}
	return readHintEntry(rec), nil
}

// BuildHintTables builds the hint table of every tree of both kinds (Coin,
// then Data, each by tree index) as of the anchor block, from the pages of
// the tree history alone. The anchor must be canonical and applied to the
// history.
func BuildHintTables(h *ghosttree.History, anchor common.Hash) ([]*HintTable, error) {
	if h == nil {
		return nil, errNoHistory
	}
	var out []*HintTable
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		trees, err := readTrees(h, kind, anchor)
		if err != nil {
			return nil, err
		}
		for _, tr := range trees {
			tags := make([][ghosttree.TagBytes]byte, 0, tr.count)
			for _, page := range tr.pages {
				for i := range page {
					var tag [ghosttree.TagBytes]byte
					copy(tag[:], page[i].Note[:ghosttree.TagBytes])
					tags = append(tags, tag)
				}
			}
			t, err := NewHintTable(kind, tr.index, tags)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
		}
	}
	return out, nil
}
