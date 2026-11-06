package ghostpir

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// SnapshotInterval is the number of blocks between two snapshots: a
// snapshot is anchored at a block whose number is a multiple of it, and a
// restore server rebuilds its snapshot when the head reaches the next one.
const SnapshotInterval = 20

// The domain labels of the snapshot's hashes.
const (
	snapshotIDLabel   = "ghost/pir-snapshot/v1"
	snapshotSeedLabel = "ghost/pir-snapshot-database/v1"
	snapshotDataLabel = "ghost/pir-snapshot-records/v1"
)

var (
	// ErrSnapshotAnchor is returned for an anchor a snapshot cannot sit on:
	// one whose number is not a multiple of SnapshotInterval, or one whose
	// header lacks a tree root.
	ErrSnapshotAnchor = errors.New("ghostpir: not a snapshot anchor")

	// ErrSnapshotRoots is returned when the records built from the tree
	// history do not fold to the roots of the anchor header.
	ErrSnapshotRoots = errors.New("ghostpir: snapshot records differ from the anchor header's roots")

	// ErrSnapshotChain is returned when the ancestry of a head cannot be
	// walked down to its snapshot anchor.
	ErrSnapshotChain = errors.New("ghostpir: snapshot anchor not in the head's ancestry")
)

// SnapshotNumber is the number of the anchor of the snapshot a head at block
// head is served from: the last multiple of SnapshotInterval at or below it.
func SnapshotNumber(head uint64) uint64 { return head - head%SnapshotInterval }

// Table names the kind of a database of a snapshot.
type Table uint8

const (
	NoteTable         Table = iota + 1 // the notes of a coin or data tree
	WitnessTable                       // the coin-tree witness records
	LookupTable                        // the lookup leaves of a data tree
	MarkerTable                        // the leaves of a marker list
	HintBucketTable                    // the buckets of a tree's hint table
	HintOverflowTable                  // the overflow entries of a tree's hint table
)

func (t Table) String() string {
	switch t {
	case NoteTable:
		return "notes"
	case WitnessTable:
		return "witnesses"
	case LookupTable:
		return "lookups"
	case MarkerTable:
		return "markers"
	case HintBucketTable:
		return "hint-buckets"
	case HintOverflowTable:
		return "hint-overflow"
	}
	return fmt.Sprintf("table-%d", uint8(t))
}

// SnapshotEntry is one database of a snapshot as its header lists it.
type SnapshotEntry struct {
	Table      Table
	Kind       ghosttree.Kind // the tree's or marker list's kind
	TreeIndex  uint64         // the tree's or marker list's index
	RecordSize int
	Records    int
	Root       common.Hash // the tree or list root the records are under; zero for a hint table
	Digest     common.Hash // SHA-256 of the domain label and the records, in order
}

// SnapshotHeader is the public description of a snapshot: its anchor block,
// the anchor's tree and marker roots, and every database. Any node with the
// same chain builds the same header, byte for byte, and so the same
// identity.
type SnapshotHeader struct {
	Number         uint64
	Anchor         common.Hash // hash of the anchor block
	CoinTreeRoot   common.Hash
	DataTreeRoot   common.Hash
	DataMarkerRoot common.Hash // zero when the anchor header has none
	Entries        []SnapshotEntry
}

// snapshotEntryBytes is one entry in the header's encoding.
const snapshotEntryBytes = 1 + 1 + 8 + 4 + 8 + 2*common.HashLength

// Encode is the header's canonical encoding: the number, the anchor hash and
// the three roots, the count of entries as 4 bytes, then every entry (table,
// kind, tree index, record size, record count, root, digest), integers
// big-endian.
func (h *SnapshotHeader) Encode() []byte {
	out := make([]byte, 0, 8+4*common.HashLength+4+len(h.Entries)*snapshotEntryBytes)
	out = binary.BigEndian.AppendUint64(out, h.Number)
	out = append(out, h.Anchor[:]...)
	out = append(out, h.CoinTreeRoot[:]...)
	out = append(out, h.DataTreeRoot[:]...)
	out = append(out, h.DataMarkerRoot[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(h.Entries)))
	for _, e := range h.Entries {
		out = append(out, byte(e.Table), byte(e.Kind))
		out = binary.BigEndian.AppendUint64(out, e.TreeIndex)
		out = binary.BigEndian.AppendUint32(out, uint32(e.RecordSize))
		out = binary.BigEndian.AppendUint64(out, uint64(e.Records))
		out = append(out, e.Root[:]...)
		out = append(out, e.Digest[:]...)
	}
	return out
}

// ID is the snapshot's identity: SHA-256 of a domain label and the header's
// encoding.
func (h *SnapshotHeader) ID() common.Hash {
	d := sha256.New()
	d.Write([]byte(snapshotIDLabel))
	d.Write(h.Encode())
	return common.BytesToHash(d.Sum(nil))
}

// DatabaseSeed is the public seed of the database at entry i of the
// snapshot whose identity is id: SHA-256 of a domain label, the identity and
// i as 4 big-endian bytes. Every database of a snapshot has its own a_j, and
// a new snapshot new ones.
func DatabaseSeed(id common.Hash, i int) [32]byte {
	d := sha256.New()
	d.Write([]byte(snapshotSeedLabel))
	d.Write(id[:])
	d.Write(binary.BigEndian.AppendUint32(nil, uint32(i)))
	var seed [32]byte
	copy(seed[:], d.Sum(nil))
	return seed
}

// recordsDigest hashes records in order.
func recordsDigest(records [][]byte) common.Hash {
	d := sha256.New()
	d.Write([]byte(snapshotDataLabel))
	for _, r := range records {
		d.Write(r)
	}
	return common.BytesToHash(d.Sum(nil))
}

// Snapshot is everything a restore server answers from as of one anchor:
// the record sets and hint tables built from the tree history, and the PIR
// database of every one of them, preprocessed.
type Snapshot struct {
	Header    SnapshotHeader
	ID        common.Hash
	Databases *Databases
	Hints     []*HintTable // Coin trees, then Data trees, each by tree index

	records [][][]byte  // the records of every entry
	dbs     []*Database // the PIR database of every entry, nil for one without records
	elapsed time.Duration
}

// Database is the PIR database of entry i, nil for an entry without
// records (no query can be made to it).
func (s *Snapshot) Database(i int) *Database {
	if i < 0 || i >= len(s.dbs) {
		return nil
	}
	return s.dbs[i]
}

// Records is the records of entry i, nil out of range.
func (s *Snapshot) Records(i int) [][]byte {
	if i < 0 || i >= len(s.records) {
		return nil
	}
	return s.records[i]
}

// Find is the index of the entry of a table for one tree or marker list.
func (s *Snapshot) Find(table Table, kind ghosttree.Kind, treeIndex uint64) (int, bool) {
	for i, e := range s.Header.Entries {
		if e.Table == table && e.Kind == kind && e.TreeIndex == treeIndex {
			return i, true
		}
	}
	return 0, false
}

// Elapsed is the time the snapshot took to build, preprocessing included.
func (s *Snapshot) Elapsed() time.Duration { return s.elapsed }

// BuildSnapshot builds the snapshot anchored at a block from the tree
// history: every record set and hint table as of the anchor, and the PIR
// database of each under its seed, preprocessed. The anchor's number must be
// a multiple of SnapshotInterval and the anchor canonical and applied to the
// history. The root of the last tree of each kind must be the anchor
// header's root of that kind, or the build fails with ErrSnapshotRoots.
func BuildSnapshot(h *ghosttree.History, anchor *types.Header) (*Snapshot, error) {
	start := time.Now()
	if anchor == nil || anchor.Number == nil || !anchor.Number.IsUint64() {
		return nil, fmt.Errorf("%w: no anchor header", ErrSnapshotAnchor)
	}
	number := anchor.Number.Uint64()
	if number%SnapshotInterval != 0 {
		return nil, fmt.Errorf("%w: block %d", ErrSnapshotAnchor, number)
	}
	if anchor.CoinTreeRoot == nil || anchor.DataTreeRoot == nil {
		return nil, fmt.Errorf("%w: block %d has no tree roots", ErrSnapshotAnchor, number)
	}
	hash := anchor.Hash()
	dbs, err := BuildDatabases(h, hash)
	if err != nil {
		return nil, err
	}
	hints, err := BuildHintTables(h, hash)
	if err != nil {
		return nil, err
	}
	header := SnapshotHeader{Number: number, Anchor: hash, CoinTreeRoot: *anchor.CoinTreeRoot, DataTreeRoot: *anchor.DataTreeRoot}
	if anchor.DataMarkerRoot != nil {
		header.DataMarkerRoot = *anchor.DataMarkerRoot
	}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		var last *RecordSet
		for _, set := range dbs.Notes {
			if set.Kind == kind {
				last = set
			}
		}
		want := *ghosttree.HeaderRoot(anchor, kind)
		if last == nil || last.Root != want {
			got := common.Hash{}
			if last != nil {
				got = last.Root
			}
			return nil, fmt.Errorf("%w: %v tree root %x at block %d, header %x", ErrSnapshotRoots, kind, got, number, want)
		}
	}

	snap := &Snapshot{Databases: dbs, Hints: hints}
	add := func(table Table, kind ghosttree.Kind, index uint64, size int, root common.Hash, records [][]byte) {
		header.Entries = append(header.Entries, SnapshotEntry{
			Table: table, Kind: kind, TreeIndex: index, RecordSize: size,
			Records: len(records), Root: root, Digest: recordsDigest(records),
		})
		snap.records = append(snap.records, records)
	}
	for _, set := range dbs.Notes {
		add(NoteTable, set.Kind, set.TreeIndex, set.RecordSize, set.Root, set.Records)
	}
	for _, set := range dbs.CoinWitnesses {
		add(WitnessTable, set.Kind, set.TreeIndex, set.RecordSize, set.Root, set.Records)
	}
	for _, set := range dbs.Lookups {
		add(LookupTable, set.Kind, set.TreeIndex, set.RecordSize, set.Root, set.Records)
	}
	for _, set := range dbs.Markers {
		add(MarkerTable, set.Kind, set.TreeIndex, set.RecordSize, set.Root, set.Records)
	}
	for _, t := range hints {
		add(HintBucketTable, t.Kind, t.TreeIndex, HintBucketRecordSize, common.Hash{}, t.BucketRecords())
		add(HintOverflowTable, t.Kind, t.TreeIndex, HintOverflowRecordSize, common.Hash{}, t.OverflowRecords())
	}
	snap.Header = header
	snap.ID = header.ID()

	// The preprocessing of the rebuild: every database under its seed.
	snap.dbs = make([]*Database, len(header.Entries))
	for i, e := range header.Entries {
		if e.Records == 0 {
			continue
		}
		db, err := NewDatabase(DatabaseSeed(snap.ID, i), e.RecordSize, snap.records[i])
		if err != nil {
			return nil, fmt.Errorf("%v of %v tree %d: %w", e.Table, e.Kind, e.TreeIndex, err)
		}
		snap.dbs[i] = db
	}
	snap.elapsed = time.Since(start)
	return snap, nil
}

// Snapshotter keeps the snapshot of a node's canonical head: it rebuilds it
// when the head passes into a new interval of SnapshotInterval blocks, and
// when a reorganisation replaces the anchor block, so that the snapshot it
// holds is always that of the head's own chain.
type Snapshotter struct {
	db  ethdb.Reader
	h   *ghosttree.History
	log log.Logger

	mu       sync.Mutex // serialises Update
	cur      atomic.Pointer[Snapshot]
	rebuilds atomic.Uint64
}

// NewSnapshotter keeps snapshots built from the tree history h, reading
// headers from db (the database the history reads its headers from) and
// logging to logger (the root logger when nil).
func NewSnapshotter(db ethdb.Reader, h *ghosttree.History, logger log.Logger) *Snapshotter {
	if logger == nil {
		logger = log.Root()
	}
	return &Snapshotter{db: db, h: h, log: logger}
}

// Current is the snapshot held, nil before the first successful Update.
func (s *Snapshotter) Current() *Snapshot { return s.cur.Load() }

// Rebuilds is the number of snapshots built so far.
func (s *Snapshotter) Rebuilds() uint64 { return s.rebuilds.Load() }

// Update brings the snapshot to the head: the anchor is the head's ancestor
// at SnapshotNumber of the head's number. If the snapshot held is anchored
// at that block it stays, and Update reports no rebuild; otherwise the
// snapshot is built again. The history must hold the head's chain. If the
// build fails, the snapshot held stays only if its anchor is still in the
// head's ancestry, and the error is returned.
func (s *Snapshotter) Update(head *types.Header) (*Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if head == nil || head.Number == nil || !head.Number.IsUint64() {
		return nil, false, fmt.Errorf("%w: no head header", ErrSnapshotChain)
	}
	anchor, err := s.ancestor(head, SnapshotNumber(head.Number.Uint64()))
	if err != nil {
		return nil, false, err
	}
	old := s.cur.Load()
	if old != nil && old.Header.Anchor == anchor.Hash() {
		return old, false, nil
	}
	snap, err := BuildSnapshot(s.h, anchor)
	if err != nil {
		if old != nil {
			if a, aerr := s.ancestor(anchor, old.Header.Number); aerr != nil || a.Hash() != old.Header.Anchor {
				s.cur.Store(nil)
			}
		}
		s.log.Warn("Failed to rebuild PIR snapshot", "number", anchor.Number, "anchor", anchor.Hash(), "err", err)
		return nil, false, err
	}
	s.cur.Store(snap)
	s.rebuilds.Add(1)
	s.log.Info("Rebuilt PIR snapshot", "number", snap.Header.Number, "anchor", snap.Header.Anchor,
		"id", snap.ID, "databases", len(snap.Header.Entries), "elapsed", common.PrettyDuration(snap.elapsed))
	return snap, true, nil
}

// ancestor walks from header down its parents to the block at number.
func (s *Snapshotter) ancestor(header *types.Header, number uint64) (*types.Header, error) {
	cur := header
	if cur.Number.Uint64() < number {
		return nil, fmt.Errorf("%w: block %d below %d", ErrSnapshotChain, cur.Number.Uint64(), number)
	}
	for cur.Number.Uint64() > number {
		n := cur.Number.Uint64() - 1
		parent := rawdb.ReadHeader(s.db, cur.ParentHash, n)
		if parent == nil {
			return nil, fmt.Errorf("%w: header %d %x missing", ErrSnapshotChain, n, cur.ParentHash)
		}
		cur = parent
	}
	return cur, nil
}
