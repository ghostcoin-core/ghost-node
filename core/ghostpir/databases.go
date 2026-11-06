package ghostpir

import (
	"errors"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// The databases a restore server answers from, each the records of one tree
// or marker list as of one anchor block, built from the pages of the tree
// history (History.PageRoots, History.PageSet and History.MarkerPage) and
// nothing else. Every record of a database has the same size, and record i
// is the leaf at position i of its tree or list, so the index a wallet asks
// for is public:
//
//   - the notes: every leaf of a coin or data tree with its note and salt;
//   - the coin-tree witness records: the sibling hashes of every coin leaf,
//     which with the leaf verify against the tree root of the header;
//   - the lookup leaves: every leaf of a data tree with its siblings, which
//     verify against the data tree root of the header;
//   - the marker leaves: every spent marker of a coin or data marker list,
//     in the order the chain spent them, with its siblings in the list tree
//     (see MarkerListTag), which verify against the list root.
//
// Any node with the same chain builds the same records, byte for byte.

// MarkerListTag is the hash tag of the inner nodes of the list tree over a
// marker list: a tree of the release depth whose leaf at position i is the
// i-th spent marker of the list and whose unused leaves are
// ghosttree.EmptyLeaf. No header carries its root; it binds the records of a
// marker database together, and every node derives the same root from the
// same chain.
const MarkerListTag = "ghost/pir-marker-list-node/v1"

var (
	// ErrTreeHistory is returned when the pages the tree history serves do
	// not hold together: a page of the wrong size or out of order, or leaves
	// that do not hash to their page root.
	ErrTreeHistory = errors.New("ghostpir: tree history pages do not hold together")

	errNoHistory = errors.New("ghostpir: no tree history")
)

// NoteRecordSize is the record of a note: the leaf, the note, a byte that is
// 1 for a salted commit and 0 otherwise, and the salt (zero without one).
const NoteRecordSize = common.HashLength + ghosttree.NoteBytes + 1 + ghosttree.SaltBytes

// WitnessRecordSize is the record of a coin-tree witness: the sibling at
// every level from the leaf up, ghosttree.Release.Depth hashes.
func WitnessRecordSize() int { return ghosttree.Release.Depth * common.HashLength }

// LeafWitnessRecordSize is the record of a lookup or marker leaf: the leaf,
// then its siblings as in a witness record.
func LeafWitnessRecordSize() int { return common.HashLength + WitnessRecordSize() }

// RecordSet is the records of one database: those of one tree or marker
// list, record i for position i.
type RecordSet struct {
	Kind       ghosttree.Kind // Coin or Data for a tree, CoinMarkers or DataMarkers for a list
	TreeIndex  uint64         // the index of the tree or list
	RecordSize int
	Records    [][]byte
	Root       common.Hash // root of the tree or list tree the leaves are under
}

// Database builds the PIR database of the records under a seed. A set
// without records has none (ErrShape).
func (s *RecordSet) Database(seed [32]byte) (*Database, error) {
	return NewDatabase(seed, s.RecordSize, s.Records)
}

// Databases is the records of every database as of one anchor.
type Databases struct {
	Anchor        common.Hash
	Notes         []*RecordSet // coin trees, then data trees, each by tree index
	CoinWitnesses []*RecordSet // coin trees by tree index
	Lookups       []*RecordSet // data trees by tree index
	Markers       []*RecordSet // coin marker lists, then data marker lists, each by index
}

// BuildDatabases builds the records of every database as of the anchor
// block. The anchor must be canonical and applied to the history, and the
// history's head canonical; anything else is the history's error.
func BuildDatabases(h *ghosttree.History, anchor common.Hash) (*Databases, error) {
	if h == nil {
		return nil, errNoHistory
	}
	depth := ghosttree.Release.Depth
	if depth < ghosttree.PageLevels {
		return nil, fmt.Errorf("%w: depth %d below a page", ghosttree.ErrDepth, depth)
	}
	out := &Databases{Anchor: anchor}
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		trees, err := readTrees(h, kind, anchor)
		if err != nil {
			return nil, err
		}
		m := treeMerkle(kind, depth)
		for _, tr := range trees {
			leaves := make([][]common.Hash, len(tr.pages))
			for p, page := range tr.pages {
				leaves[p] = make([]common.Hash, len(page))
				for i := range page {
					leaves[p][i] = page[i].Leaf
				}
			}
			withLeaf := kind == ghosttree.Data
			recs, root, err := m.witnessRecords(leaves, tr.roots, withLeaf)
			if err != nil {
				return nil, fmt.Errorf("%v tree %d: %w", kind, tr.index, err)
			}
			if want := ghosttree.RootFromPageRoots(kind, tr.roots); root != want {
				return nil, fmt.Errorf("%w: %v tree %d folds to %x, its page roots to %x", ErrTreeHistory, kind, tr.index, root, want)
			}
			out.Notes = append(out.Notes, &RecordSet{Kind: kind, TreeIndex: tr.index, RecordSize: NoteRecordSize, Records: noteRecords(tr), Root: root})
			set := &RecordSet{Kind: kind, TreeIndex: tr.index, RecordSize: WitnessRecordSize(), Records: recs, Root: root}
			if withLeaf {
				set.RecordSize = LeafWitnessRecordSize()
				out.Lookups = append(out.Lookups, set)
			} else {
				out.CoinWitnesses = append(out.CoinWitnesses, set)
			}
		}
	}
	m := markerMerkle(depth)
	for _, kind := range []ghosttree.Kind{ghosttree.CoinMarkers, ghosttree.DataMarkers} {
		lists, err := readMarkerLists(h, kind, anchor)
		if err != nil {
			return nil, err
		}
		for index, pages := range lists {
			recs, root, err := m.witnessRecords(pages, nil, true)
			if err != nil {
				return nil, fmt.Errorf("%v list %d: %w", kind, index, err)
			}
			out.Markers = append(out.Markers, &RecordSet{Kind: kind, TreeIndex: uint64(index), RecordSize: LeafWitnessRecordSize(), Records: recs, Root: root})
		}
	}
	return out, nil
}

// noteRecords returns the note record of every leaf of a tree.
func noteRecords(tr *treeRead) [][]byte {
	slab := make([]byte, int(tr.count)*NoteRecordSize)
	out := make([][]byte, 0, tr.count)
	for _, page := range tr.pages {
		for i := range page {
			rec := slab[:NoteRecordSize:NoteRecordSize]
			slab = slab[NoteRecordSize:]
			copy(rec, page[i].Leaf[:])
			copy(rec[common.HashLength:], page[i].Note[:])
			if salt := page[i].Salt; salt != nil {
				rec[common.HashLength+ghosttree.NoteBytes] = 1
				copy(rec[common.HashLength+ghosttree.NoteBytes+1:], salt[:])
			}
			out = append(out, rec)
		}
	}
	return out
}

// DecodeNoteRecord decodes a note record into the leaf, note and salt.
func DecodeNoteRecord(rec []byte) (ghosttree.PageEntry, error) {
	if len(rec) != NoteRecordSize {
		return ghosttree.PageEntry{}, fmt.Errorf("%w: note record of %d bytes", ErrRecordSize, len(rec))
	}
	var e ghosttree.PageEntry
	copy(e.Leaf[:], rec)
	copy(e.Note[:], rec[common.HashLength:])
	salt := rec[common.HashLength+ghosttree.NoteBytes+1:]
	switch rec[common.HashLength+ghosttree.NoteBytes] {
	case 0:
		for _, b := range salt {
			if b != 0 {
				return ghosttree.PageEntry{}, fmt.Errorf("%w: salt without its flag", ErrRecordSize)
			}
		}
	case 1:
		e.Salt = new([ghosttree.SaltBytes]byte)
		copy(e.Salt[:], salt)
	default:
		return ghosttree.PageEntry{}, fmt.Errorf("%w: salt flag %d", ErrRecordSize, rec[common.HashLength+ghosttree.NoteBytes])
	}
	return e, nil
}

// DecodeWitnessRecord decodes a coin-tree witness record into its siblings,
// the one at level 0 first.
func DecodeWitnessRecord(rec []byte) ([]common.Hash, error) {
	if len(rec) != WitnessRecordSize() {
		return nil, fmt.Errorf("%w: witness record of %d bytes", ErrRecordSize, len(rec))
	}
	return decodeHashes(rec), nil
}

// DecodeLeafWitnessRecord decodes a lookup or marker record into the leaf
// and its siblings.
func DecodeLeafWitnessRecord(rec []byte) (common.Hash, []common.Hash, error) {
	if len(rec) != LeafWitnessRecordSize() {
		return common.Hash{}, nil, fmt.Errorf("%w: leaf record of %d bytes", ErrRecordSize, len(rec))
	}
	return common.BytesToHash(rec[:common.HashLength]), decodeHashes(rec[common.HashLength:]), nil
}

func decodeHashes(b []byte) []common.Hash {
	out := make([]common.Hash, len(b)/common.HashLength)
	for i := range out {
		copy(out[i][:], b[i*common.HashLength:])
	}
	return out
}

// VerifyMarkerWitness reports whether marker sits at position of the marker
// list tree whose root is root, with siblings[l] the sibling at level l.
func VerifyMarkerWitness(root common.Hash, position uint64, marker common.Hash, siblings []common.Hash) bool {
	depth := ghosttree.Release.Depth
	if len(siblings) != depth || position>>depth != 0 {
		return false
	}
	return markerMerkle(depth).pathRoot(position, marker, siblings) == root
}

// merkle is the hashing of one kind of tree: its inner node and its empty
// subtrees Z_0 to Z_depth.
type merkle struct {
	tag   string
	depth int
	zeros []common.Hash
}

func newMerkle(tag string, depth int) merkle {
	m := merkle{tag: tag, depth: depth, zeros: make([]common.Hash, depth+1)}
	m.zeros[0] = ghosttree.EmptyLeaf
	for l := 0; l < depth; l++ {
		m.zeros[l+1] = m.node(l, m.zeros[l], m.zeros[l])
	}
	return m
}

// treeMerkle is the hashing of the consensus tree of a kind.
func treeMerkle(kind ghosttree.Kind, depth int) merkle {
	if kind == ghosttree.Data {
		return newMerkle(ghosttree.TagDataNode, depth)
	}
	return newMerkle(ghosttree.TagCoinNode, depth)
}

func markerMerkle(depth int) merkle { return newMerkle(MarkerListTag, depth) }

func (m merkle) node(level int, left, right common.Hash) common.Hash {
	return ghosttree.K(m.tag, []byte{byte(level)}, left[:], right[:])
}

// levels returns the rows of nodes from height from up by n levels over
// nodes, which sit at height from: row k at height from+k, a short row
// padded with the empty subtree of its height.
func (m merkle) levels(from, n int, nodes []common.Hash) [][]common.Hash {
	rows := make([][]common.Hash, n+1)
	rows[0] = nodes
	for k := 0; k < n; k++ {
		cur := rows[k]
		next := make([]common.Hash, (len(cur)+1)/2)
		for i := range next {
			right := m.zeros[from+k]
			if 2*i+1 < len(cur) {
				right = cur[2*i+1]
			}
			next[i] = m.node(from+k, cur[2*i], right)
		}
		rows[k+1] = next
	}
	return rows
}

// top is the single node of the last row of levels.
func (m merkle) top(from int, rows [][]common.Hash) common.Hash {
	if last := rows[len(rows)-1]; len(last) > 0 {
		return last[0]
	}
	return m.zeros[from+len(rows)-1]
}

// sibling is the sibling of node index in row k of levels.
func (m merkle) sibling(from int, rows [][]common.Hash, k int, index uint64) common.Hash {
	if s := index ^ 1; s < uint64(len(rows[k])) {
		return rows[k][s]
	}
	return m.zeros[from+k]
}

// pathRoot is the root over leaf at position with the given siblings.
func (m merkle) pathRoot(position uint64, leaf common.Hash, siblings []common.Hash) common.Hash {
	cur := leaf
	for l := 0; l < m.depth; l++ {
		if position>>l&1 == 1 {
			cur = m.node(l, siblings[l], cur)
		} else {
			cur = m.node(l, cur, siblings[l])
		}
	}
	return cur
}

// witnessRecords returns the witness record of every leaf of a tree whose
// leaves are pages, page by page, and the root of the tree. roots is the
// page-root list the pages must hash to; nil computes it from the pages.
// With withLeaf, every record starts with its leaf.
func (m merkle) witnessRecords(pages [][]common.Hash, roots []common.Hash, withLeaf bool) ([][]byte, common.Hash, error) {
	if uint64(len(pages)) > (uint64(1)<<m.depth)/ghosttree.PageLeaves {
		return nil, common.Hash{}, fmt.Errorf("%w: %d pages", ErrTreeHistory, len(pages))
	}
	lower := make([][][]common.Hash, len(pages))
	for p, leaves := range pages {
		if len(leaves) == 0 || len(leaves) > ghosttree.PageLeaves || (p < len(pages)-1 && len(leaves) != ghosttree.PageLeaves) {
			return nil, common.Hash{}, fmt.Errorf("%w: page %d of %d has %d leaves", ErrTreeHistory, p, len(pages), len(leaves))
		}
		lower[p] = m.levels(0, ghosttree.PageLevels, leaves)
	}
	if roots == nil {
		roots = make([]common.Hash, len(pages))
		for p := range pages {
			roots[p] = m.top(0, lower[p])
		}
	}
	if len(roots) != len(pages) {
		return nil, common.Hash{}, fmt.Errorf("%w: %d pages for %d page roots", ErrTreeHistory, len(pages), len(roots))
	}
	upper := m.levels(ghosttree.PageLevels, m.depth-ghosttree.PageLevels, roots)
	root := m.top(ghosttree.PageLevels, upper)

	size := m.depth * common.HashLength
	if withLeaf {
		size += common.HashLength
	}
	var out [][]byte
	for p, leaves := range pages {
		if m.top(0, lower[p]) != roots[p] {
			return nil, common.Hash{}, fmt.Errorf("%w: page %d does not hash to its page root", ErrTreeHistory, p)
		}
		slab := make([]byte, len(leaves)*size)
		for off, leaf := range leaves {
			rec := slab[off*size : off*size : (off+1)*size]
			if withLeaf {
				rec = append(rec, leaf[:]...)
			}
			for k := 0; k < ghosttree.PageLevels; k++ {
				s := m.sibling(0, lower[p], k, uint64(off)>>k)
				rec = append(rec, s[:]...)
			}
			for k := 0; k < m.depth-ghosttree.PageLevels; k++ {
				s := m.sibling(ghosttree.PageLevels, upper, k, uint64(p)>>k)
				rec = append(rec, s[:]...)
			}
			out = append(out, rec)
		}
	}
	return out, root, nil
}

// treeRead is one tree as of an anchor: its page-root list and the entries
// of every page.
type treeRead struct {
	index uint64
	roots []common.Hash
	pages [][]ghosttree.PageEntry
	count uint64
}

// readTrees reads every tree of a kind as of the anchor, by tree index: tree
// 0, and each next index while the one before it is full.
func readTrees(h *ghosttree.History, kind ghosttree.Kind, anchor common.Hash) ([]*treeRead, error) {
	capacity := uint64(1) << ghosttree.Release.Depth
	var out []*treeRead
	for index := uint64(0); ; index++ {
		tr, err := readTree(h, kind, index, anchor)
		if err != nil {
			if index > 0 && errors.Is(err, ghosttree.ErrNoTree) {
				return out, nil
			}
			return nil, err
		}
		out = append(out, tr)
		if tr.count < capacity || index == math.MaxUint64 {
			return out, nil
		}
	}
}

// readTree reads every page of one tree as of the anchor, in page sets: all
// of a tree of ghosttree.PageSetPages pages or fewer at once, and a larger
// one in runs of that many pages, the last run ending at the last page.
func readTree(h *ghosttree.History, kind ghosttree.Kind, index uint64, anchor common.Hash) (*treeRead, error) {
	roots, err := h.PageRoots(kind, index, anchor)
	if err != nil {
		return nil, err
	}
	n := len(roots)
	tr := &treeRead{index: index, roots: roots, pages: make([][]ghosttree.PageEntry, n)}
	for start := 0; start < n; start += ghosttree.PageSetPages {
		lo := start
		if n > ghosttree.PageSetPages {
			lo = min(start, n-ghosttree.PageSetPages)
		}
		hi := min(lo+ghosttree.PageSetPages, n)
		want := make([]uint32, 0, hi-lo)
		for p := lo; p < hi; p++ {
			want = append(want, uint32(p))
		}
		set, err := h.PageSet(kind, index, want, anchor)
		if err != nil {
			return nil, err
		}
		if len(set) != len(want) {
			return nil, fmt.Errorf("%w: %v tree %d: %d pages for %d asked", ErrTreeHistory, kind, index, len(set), len(want))
		}
		for i, page := range set {
			if page.Page != want[i] || page.Kind != kind || page.TreeIndex != index || int(page.Filled) != len(page.Entries) {
				return nil, fmt.Errorf("%w: %v tree %d: page %d served for %d", ErrTreeHistory, kind, index, page.Page, want[i])
			}
			tr.pages[want[i]] = page.Entries
		}
	}
	for _, page := range tr.pages {
		tr.count += uint64(len(page))
	}
	return tr, nil
}

// readMarkerLists reads every marker list of a kind as of the anchor, each
// as its pages of markers: list 0, and each next index while the one before
// it is full.
func readMarkerLists(h *ghosttree.History, kind ghosttree.Kind, anchor common.Hash) ([][][]common.Hash, error) {
	pagesPerList := (uint64(1) << ghosttree.Release.Depth) / ghosttree.PageLeaves
	var out [][][]common.Hash
	for index := uint64(0); ; index++ {
		var pages [][]common.Hash
		full := false
		for p := uint64(0); p < pagesPerList; p++ {
			mp, err := h.MarkerPage(kind, index, uint32(p), anchor)
			if err != nil {
				if index > 0 && p == 0 && errors.Is(err, ghosttree.ErrNoTree) {
					return out, nil
				}
				return nil, err
			}
			if mp.Kind != kind || mp.Index != index || uint64(mp.Page) != p || len(mp.Markers) > ghosttree.PageLeaves {
				return nil, fmt.Errorf("%w: %v list %d: page %d served for %d", ErrTreeHistory, kind, index, mp.Page, p)
			}
			if len(mp.Markers) > 0 {
				pages = append(pages, mp.Markers)
			}
			if len(mp.Markers) < ghosttree.PageLeaves {
				break
			}
			full = p == pagesPerList-1
		}
		out = append(out, pages)
		if !full || index == math.MaxUint64 {
			return out, nil
		}
	}
}
