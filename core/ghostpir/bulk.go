package ghostpir

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// The bulk data of a restore server is what every wallet reads whole, so
// reading it says nothing about the wallet:
//
//   - the tree tops: for every coin and data tree of the snapshot, its nodes
//     at level TopLevel, left to right, up to the last one over a leaf. With
//     them a wallet holds the part of every witness above that level and
//     checks them against the anchor header's root;
//   - the blocks after the snapshot: for every block from the one after the
//     anchor up to the head, the lookup tag (the first ghosttree.TagBytes
//     bytes of the note) and position of every coin and data leaf it
//     appended, and every coin and data marker it spent, with its position
//     in its marker list. The snapshot's databases do not hold these yet; a
//     wallet scans them for its tags and markers instead.
//
// The rest is read through PIR over the snapshot's databases (see
// BulkServer.Query).

// TopLevel is the level of the tree tops a restore server serves in bulk: a
// node at level 20 is the root of 2^20 leaves, so a tree of the release depth
// has at most 4,096 tops (128 KiB). A tree shallower than TopLevel is served
// at its root.
const TopLevel = 20

var (
	// ErrNoSnapshot is returned by a restore server that holds no snapshot:
	// before its first update, and after an update that failed.
	ErrNoSnapshot = errors.New("ghostpir: no snapshot served")

	// ErrNoDatabase is returned for a query to an entry of the snapshot that
	// has no PIR database: one out of range, or one without records.
	ErrNoDatabase = errors.New("ghostpir: no database at the snapshot entry")
)

// topLevel is the level tree tops are served at for the release depth.
func topLevel() int { return min(TopLevel, ghosttree.Release.Depth) }

// TreeTops is the nodes of one tree at Level as of the snapshot's anchor.
type TreeTops struct {
	Kind      ghosttree.Kind // Coin or Data
	TreeIndex uint64
	Level     int
	Count     uint64        // leaves of the tree at the anchor
	Nodes     []common.Hash // node i is the root of leaves i * 2^Level to (i+1) * 2^Level - 1
}

// Root folds the tops up to the root of the tree, the unused subtrees empty.
func (t *TreeTops) Root() common.Hash {
	depth := ghosttree.Release.Depth
	if t.Level < 0 || t.Level > depth {
		return common.Hash{}
	}
	m := treeMerkle(t.Kind, depth)
	return m.top(t.Level, m.levels(t.Level, depth-t.Level, t.Nodes))
}

// Encode is the tops on the wire: the kind (1 byte), tree index (8), level
// (1), leaf count (8) and node count (4), integers big-endian, then the
// nodes.
func (t *TreeTops) Encode() []byte {
	out := make([]byte, 0, 1+8+1+8+4+len(t.Nodes)*common.HashLength)
	out = append(out, byte(t.Kind))
	out = binary.BigEndian.AppendUint64(out, t.TreeIndex)
	out = append(out, byte(t.Level))
	out = binary.BigEndian.AppendUint64(out, t.Count)
	out = binary.BigEndian.AppendUint32(out, uint32(len(t.Nodes)))
	for _, n := range t.Nodes {
		out = append(out, n[:]...)
	}
	return out
}

// TagEntry is one leaf appended after the snapshot: its tree, its position
// and the lookup tag of its note.
type TagEntry struct {
	Kind      ghosttree.Kind // Coin or Data
	TreeIndex uint64
	Position  uint32
	Tag       [ghosttree.TagBytes]byte
}

// TagEntryBytes is one tag entry on the wire.
const TagEntryBytes = 1 + 8 + 4 + ghosttree.TagBytes

// MarkerEntry is one marker spent after the snapshot: its list, its position
// in the list and the marker.
type MarkerEntry struct {
	Kind     ghosttree.Kind // CoinMarkers or DataMarkers
	Index    uint64
	Position uint64
	Marker   common.Hash
}

// MarkerEntryBytes is one marker entry on the wire.
const MarkerEntryBytes = 1 + 8 + 8 + common.HashLength

// BlockTags is the bulk data of one block after the snapshot.
type BlockTags struct {
	Number  uint64
	Hash    common.Hash
	Tags    []TagEntry    // coin leaves, then data leaves, each in position order
	Markers []MarkerEntry // coin markers, then data markers, each in the order spent
}

// Encode is the block on the wire: its number (8 bytes) and hash, the tag
// count (4) and the tags (kind, tree index, position, tag), the marker count
// (4) and the markers (kind, list index, position, marker), integers
// big-endian.
func (b *BlockTags) Encode() []byte {
	out := make([]byte, 0, 8+common.HashLength+4+len(b.Tags)*TagEntryBytes+4+len(b.Markers)*MarkerEntryBytes)
	out = binary.BigEndian.AppendUint64(out, b.Number)
	out = append(out, b.Hash[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.Tags)))
	for _, e := range b.Tags {
		out = append(out, byte(e.Kind))
		out = binary.BigEndian.AppendUint64(out, e.TreeIndex)
		out = binary.BigEndian.AppendUint32(out, e.Position)
		out = append(out, e.Tag[:]...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.Markers)))
	for _, e := range b.Markers {
		out = append(out, byte(e.Kind))
		out = binary.BigEndian.AppendUint64(out, e.Index)
		out = binary.BigEndian.AppendUint64(out, e.Position)
		out = append(out, e.Marker[:]...)
	}
	return out
}

// bulkState is everything a restore server answers from as of one head.
type bulkState struct {
	snap    *Snapshot
	servers []*Server // the PIR server of every entry, nil for one without records
	tops    []TreeTops
	head    *types.Header
	blocks  []BlockTags // the blocks after the anchor up to the head, in order
}

// BulkServer is a restore server: it keeps the snapshot of a node's head
// (see Snapshotter), serves the bulk data of it and of the blocks after it,
// and answers PIR queries to its databases, every request within a Budget.
// Like Server it holds no key and asks for no permission; a client is an
// opaque label of the requester (its address, say) used for its budget and
// the log only.
type BulkServer struct {
	db     ethdb.Reader
	h      *ghosttree.History
	snaps  *Snapshotter
	budget *budgeter
	log    log.Logger

	mu  sync.Mutex // serialises Update
	cur atomic.Pointer[bulkState]
}

// NewBulkServer serves the snapshots of the tree history h, reading headers
// from db (the database the history reads its headers from), within budget,
// logging to logger (the root logger when nil). It serves nothing before its
// first Update.
func NewBulkServer(db ethdb.Reader, h *ghosttree.History, budget Budget, logger log.Logger) (*BulkServer, error) {
	g, err := newBudgeter(budget)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.Root()
	}
	return &BulkServer{db: db, h: h, snaps: NewSnapshotter(db, h, logger), budget: g, log: logger}, nil
}

// Snapshot is the snapshot served, nil when there is none. It is for the
// node itself; a client reads the snapshot's header with Header.
func (s *BulkServer) Snapshot() *Snapshot {
	if st := s.cur.Load(); st != nil {
		return st.snap
	}
	return nil
}

// Update brings what the server serves to the head: the snapshot of the
// head (rebuilt when the head enters a new interval or a reorganisation
// replaces the anchor) and the bulk data of the blocks after the anchor up
// to the head. The history must hold the head's chain, canonical. If the
// update fails the server serves nothing until an update succeeds: it never
// answers from a chain the node has left.
func (s *BulkServer) Update(head *types.Header) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.update(head)
	if err != nil {
		s.cur.Store(nil)
		s.log.Warn("Failed to update PIR restore server", "err", err)
		return err
	}
	s.cur.Store(st)
	s.log.Debug("Updated PIR restore server", "head", st.head.Number, "snapshot", st.snap.Header.Number,
		"id", st.snap.ID, "blocks", len(st.blocks))
	return nil
}

func (s *BulkServer) update(head *types.Header) (*bulkState, error) {
	snap, _, err := s.snaps.Update(head)
	if err != nil {
		return nil, err
	}
	st := &bulkState{snap: snap, head: head}
	if old := s.cur.Load(); old != nil && old.snap == snap {
		st.servers, st.tops = old.servers, old.tops
	} else {
		st.servers = make([]*Server, len(snap.Header.Entries))
		for i := range st.servers {
			if db := snap.Database(i); db != nil {
				st.servers[i] = NewServer(db, s.log)
			}
		}
		if st.tops, err = s.treeTops(snap); err != nil {
			return nil, err
		}
	}
	if st.blocks, err = s.blocksAfter(snap, head); err != nil {
		return nil, err
	}
	return st, nil
}

// treeTops builds the tops of every tree of the snapshot from the page-root
// lists of the history and checks that each folds to its tree's root.
func (s *BulkServer) treeTops(snap *Snapshot) ([]TreeTops, error) {
	depth := ghosttree.Release.Depth
	level := topLevel()
	var out []TreeTops
	for _, e := range snap.Header.Entries {
		if e.Table != NoteTable {
			continue
		}
		roots, err := s.h.PageRoots(e.Kind, e.TreeIndex, snap.Header.Anchor)
		if err != nil {
			return nil, err
		}
		m := treeMerkle(e.Kind, depth)
		rows := m.levels(ghosttree.PageLevels, level-ghosttree.PageLevels, roots)
		t := TreeTops{Kind: e.Kind, TreeIndex: e.TreeIndex, Level: level, Count: uint64(e.Records), Nodes: rows[len(rows)-1]}
		if got := t.Root(); got != e.Root {
			return nil, fmt.Errorf("%w: %v tree %d tops fold to %x, the snapshot has %x", ErrTreeHistory, e.Kind, e.TreeIndex, got, e.Root)
		}
		out = append(out, t)
	}
	return out, nil
}

// cursor is the next position of a tree or marker list: the index of the
// last one that has started and its count.
type cursor struct {
	index, count uint64
}

// snapshotCursor is where the snapshot ends for one kind: the last tree or
// marker list of the kind in a table and its record count, moved on to the
// next index when it is full.
func snapshotCursor(h *SnapshotHeader, table Table, kind ghosttree.Kind) cursor {
	var c cursor
	for _, e := range h.Entries {
		if e.Table == table && e.Kind == kind && e.TreeIndex >= c.index {
			c = cursor{e.TreeIndex, uint64(e.Records)}
		}
	}
	if c.count == uint64(1)<<ghosttree.Release.Depth {
		c = cursor{c.index + 1, 0}
	}
	return c
}

// blocksAfter reads the bulk data of every block after the snapshot's anchor
// up to the head, on the head's own chain, from the history as of each
// block: the leaves and markers past the counts of the block before.
func (s *BulkServer) blocksAfter(snap *Snapshot, head *types.Header) ([]BlockTags, error) {
	anchor := snap.Header.Number
	var headers []*types.Header
	for cur := head; cur.Number.Uint64() > anchor; {
		headers = append(headers, cur)
		n := cur.Number.Uint64() - 1
		parent := rawdb.ReadHeader(s.db, cur.ParentHash, n)
		if parent == nil {
			return nil, fmt.Errorf("%w: header %d %x missing", ErrSnapshotChain, n, cur.ParentHash)
		}
		cur = parent
		if n == anchor && cur.Hash() != snap.Header.Anchor {
			return nil, fmt.Errorf("%w: block %d is not the snapshot's anchor", ErrSnapshotChain, n)
		}
	}
	slices.Reverse(headers)

	trees := map[ghosttree.Kind]*cursor{}
	lists := map[ghosttree.Kind]*cursor{}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		c := snapshotCursor(&snap.Header, NoteTable, kind)
		trees[kind] = &c
	}
	for _, kind := range []ghosttree.Kind{ghosttree.CoinMarkers, ghosttree.DataMarkers} {
		c := snapshotCursor(&snap.Header, MarkerTable, kind)
		lists[kind] = &c
	}
	out := make([]BlockTags, 0, len(headers))
	for _, header := range headers {
		hash := header.Hash()
		b := BlockTags{Number: header.Number.Uint64(), Hash: hash, Tags: []TagEntry{}, Markers: []MarkerEntry{}}
		for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
			if err := s.readTags(&b, kind, trees[kind], hash); err != nil {
				return nil, fmt.Errorf("block %d: %w", b.Number, err)
			}
		}
		for _, kind := range []ghosttree.Kind{ghosttree.CoinMarkers, ghosttree.DataMarkers} {
			if err := s.readMarkers(&b, kind, lists[kind], hash); err != nil {
				return nil, fmt.Errorf("block %d: %w", b.Number, err)
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// readTags appends to b the tag of every leaf of a kind past the cursor as
// of block hash, and moves the cursor past them.
func (s *BulkServer) readTags(b *BlockTags, kind ghosttree.Kind, c *cursor, hash common.Hash) error {
	capacity := uint64(1) << ghosttree.Release.Depth
	for {
		if c.count == capacity {
			*c = cursor{c.index + 1, 0}
		}
		page := c.count / ghosttree.PageLeaves
		p, err := s.h.Page(kind, c.index, uint32(page), hash)
		if err != nil {
			if c.index > 0 && c.count == 0 && errors.Is(err, ghosttree.ErrNoTree) {
				return nil
			}
			return err
		}
		off := c.count % ghosttree.PageLeaves
		if uint64(len(p.Entries)) < off {
			return fmt.Errorf("%w: %v tree %d has %d leaves, fewer than before", ErrTreeHistory, kind, c.index, page*ghosttree.PageLeaves+uint64(len(p.Entries)))
		}
		for i := off; i < uint64(len(p.Entries)); i++ {
			e := TagEntry{Kind: kind, TreeIndex: c.index, Position: uint32(page*ghosttree.PageLeaves + i)}
			copy(e.Tag[:], p.Entries[i].Note[:ghosttree.TagBytes])
			b.Tags = append(b.Tags, e)
		}
		c.count = page*ghosttree.PageLeaves + uint64(len(p.Entries))
		if len(p.Entries) < ghosttree.PageLeaves {
			return nil
		}
	}
}

// readMarkers appends to b every marker of a kind past the cursor as of
// block hash, and moves the cursor past them.
func (s *BulkServer) readMarkers(b *BlockTags, kind ghosttree.Kind, c *cursor, hash common.Hash) error {
	capacity := uint64(1) << ghosttree.Release.Depth
	for {
		if c.count == capacity {
			*c = cursor{c.index + 1, 0}
		}
		page := c.count / ghosttree.PageLeaves
		p, err := s.h.MarkerPage(kind, c.index, uint32(page), hash)
		if err != nil {
			if c.index > 0 && c.count == 0 && errors.Is(err, ghosttree.ErrNoTree) {
				return nil
			}
			return err
		}
		off := c.count % ghosttree.PageLeaves
		if uint64(len(p.Markers)) < off {
			return fmt.Errorf("%w: %v list %d has %d markers, fewer than before", ErrTreeHistory, kind, c.index, page*ghosttree.PageLeaves+uint64(len(p.Markers)))
		}
		for i := off; i < uint64(len(p.Markers)); i++ {
			b.Markers = append(b.Markers, MarkerEntry{Kind: kind, Index: c.index, Position: page*ghosttree.PageLeaves + i, Marker: p.Markers[i]})
		}
		c.count = page*ghosttree.PageLeaves + uint64(len(p.Markers))
		if len(p.Markers) < ghosttree.PageLeaves {
			return nil
		}
	}
}

// charge charges one request of client to the budget, logging a refusal.
func (s *BulkServer) charge(client, request string) error {
	if err := s.budget.charge(client); err != nil {
		s.log.Debug("Refused PIR restore request", "client", client, "request", request, "err", err)
		return err
	}
	return nil
}

// state is the state served, charging one request of client first.
func (s *BulkServer) state(client, request string) (*bulkState, error) {
	if err := s.charge(client, request); err != nil {
		return nil, err
	}
	st := s.cur.Load()
	if st == nil {
		return nil, ErrNoSnapshot
	}
	return st, nil
}

// Header returns the header of the snapshot served: its anchor, roots and
// databases, from which a client derives the shape of every database (see
// EntryShape). One request.
func (s *BulkServer) Header(client string) (*SnapshotHeader, error) {
	st, err := s.state(client, "header")
	if err != nil {
		return nil, err
	}
	h := st.snap.Header
	h.Entries = slices.Clone(h.Entries)
	return &h, nil
}

// Tops returns the tops of every coin and data tree of the snapshot, coin
// trees then data trees, each by tree index. One request.
func (s *BulkServer) Tops(client string) ([]TreeTops, error) {
	st, err := s.state(client, "tops")
	if err != nil {
		return nil, err
	}
	out := slices.Clone(st.tops)
	for i := range out {
		out[i].Nodes = slices.Clone(out[i].Nodes)
	}
	return out, nil
}

// Blocks returns the bulk data of the blocks after the snapshot's anchor up
// to the head, those numbered above after only, in order. A wallet that has
// read up to the anchor asks with after at or below it and gets every
// block. One request.
func (s *BulkServer) Blocks(client string, after uint64) ([]BlockTags, error) {
	st, err := s.state(client, "blocks")
	if err != nil {
		return nil, err
	}
	var out []BlockTags
	for _, b := range st.blocks {
		if b.Number > after {
			b.Tags, b.Markers = slices.Clone(b.Tags), slices.Clone(b.Markers)
			out = append(out, b)
		}
	}
	return out, nil
}
