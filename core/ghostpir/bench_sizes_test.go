package ghostpir

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// The two-size benchmark records what a restore server costs at the chain
// sizes of one and five years: the size of every database of a snapshot,
// the bytes of every query and answer, the server's core-seconds per query
// and the preprocessing of a rebuild, and the totals of one restore, beside
// the published figures of 187.7 MB / 404.4 MB downloaded and 479 / 2,394
// core-seconds a restore.
//
// The chain is a fixture, not a chain read from a network: a block every 30
// seconds (the public testnet's block time), 1,051,920 blocks a year, and
// per block on average two coin leaves (a reveal's remainder and a deposit),
// one coin marker (the reveal's), one data leaf and half a data marker. The
// databases are sized from it exactly as BuildSnapshot lays them out
// (NewShape), without building them whole: a five-year snapshot is tens of
// gigabytes in NTT form.
//
// The costs are measured on the machine the benchmark runs on, one core:
// the product of one row of a database at its full column count (the work
// of a query, and of the hint, is Rows such products), the NTT of one cell
// (the rest of the preprocessing is one per cell), and the expansion of the
// public a_j. A row is the same work whatever row it is, so the full figures
// are those measured costs times the rows and cells of each grid.

// blocksPerYear is the blocks of a year of 30-second blocks.
const blocksPerYear = 365.25 * 24 * 3600 / 30

// restoreSize is a fixture chain size and the published figures for it.
type restoreSize struct {
	name                 string
	years                float64
	publishedDownloadMB  float64 // total download of a restore, 10^6 bytes
	publishedCoreSeconds float64 // server core-seconds of a restore
}

var restoreSizes = []restoreSize{
	{name: "one-year", years: 1, publishedDownloadMB: 187.7, publishedCoreSeconds: 479},
	{name: "five-year", years: 5, publishedDownloadMB: 404.4, publishedCoreSeconds: 2394},
}

// The fixture's load per block.
const (
	coinLeavesPerBlock  = 2.0
	coinMarkersPerBlock = 1.0
	dataLeavesPerBlock  = 1.0
	dataMarkersPerBlock = 0.5
)

// The fixture's restore: a wallet of restoreCoinNotes coin notes and
// restoreDataNotes data notes reads, for each note, its hint bucket, the
// columns its bucket's overflow run spans (an answer carries the whole
// column), the note and its witness (a lookup record for a data note); and in
// bulk the snapshot header, the tops of every tree and the blocks of a whole
// interval after the snapshot.
const (
	restoreCoinNotes = 4
	restoreDataNotes = 1
)

// chainCounts is the leaves and markers of the fixture chain at an age.
type chainCounts struct {
	coinLeaves, dataLeaves, coinMarkers, dataMarkers uint64
}

func countsAt(years float64) chainCounts {
	blocks := blocksPerYear * years
	return chainCounts{
		coinLeaves:  uint64(math.Round(blocks * coinLeavesPerBlock)),
		dataLeaves:  uint64(math.Round(blocks * dataLeavesPerBlock)),
		coinMarkers: uint64(math.Round(blocks * coinMarkersPerBlock)),
		dataMarkers: uint64(math.Round(blocks * dataMarkersPerBlock)),
	}
}

// sizeDB is one database of a snapshot of the fixture chain.
type sizeDB struct {
	table      Table
	kind       ghosttree.Kind
	recordSize int
	records    uint64
	shape      Shape
}

func (d *sizeDB) name() string { return fmt.Sprintf("%v %v", d.kind, d.table) }

// hintCounts is the buckets of a tree of count leaves and the entries of its
// overflow table, every bucket holding at least its slots (true of a tree of
// uniform tags past one bucket, whose buckets average 4,096 to 8,192 notes).
func hintCounts(count uint64) (buckets, overflow uint64) {
	buckets = uint64(1) << ghosttree.BucketBits(count)
	if count <= buckets*HintSlots {
		return buckets, 0
	}
	return buckets, count - buckets*HintSlots
}

// fixtureDatabases lays out every database of a snapshot of the chain, in
// the order BuildSnapshot lists them, one tree and one list of each kind.
func fixtureDatabases(c chainCounts) ([]*sizeDB, error) {
	coinBuckets, coinOverflow := hintCounts(c.coinLeaves)
	dataBuckets, dataOverflow := hintCounts(c.dataLeaves)
	dbs := []*sizeDB{
		{table: NoteTable, kind: ghosttree.Coin, recordSize: NoteRecordSize, records: c.coinLeaves},
		{table: NoteTable, kind: ghosttree.Data, recordSize: NoteRecordSize, records: c.dataLeaves},
		{table: WitnessTable, kind: ghosttree.Coin, recordSize: WitnessRecordSize(), records: c.coinLeaves},
		{table: LookupTable, kind: ghosttree.Data, recordSize: LeafWitnessRecordSize(), records: c.dataLeaves},
		{table: MarkerTable, kind: ghosttree.CoinMarkers, recordSize: LeafWitnessRecordSize(), records: c.coinMarkers},
		{table: MarkerTable, kind: ghosttree.DataMarkers, recordSize: LeafWitnessRecordSize(), records: c.dataMarkers},
		{table: HintBucketTable, kind: ghosttree.Coin, recordSize: HintBucketRecordSize, records: coinBuckets},
		{table: HintOverflowTable, kind: ghosttree.Coin, recordSize: HintOverflowRecordSize, records: coinOverflow},
		{table: HintBucketTable, kind: ghosttree.Data, recordSize: HintBucketRecordSize, records: dataBuckets},
		{table: HintOverflowTable, kind: ghosttree.Data, recordSize: HintOverflowRecordSize, records: dataOverflow},
	}
	for i, d := range dbs {
		s, err := NewShape(DatabaseSeed(common.Hash{}, i), d.recordSize, int(d.records))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.name(), err)
		}
		d.shape = s
	}
	return dbs, nil
}

func findSizeDB(dbs []*sizeDB, table Table, kind ghosttree.Kind) *sizeDB {
	for _, d := range dbs {
		if d.table == table && d.kind == kind {
			return d
		}
	}
	panic(fmt.Sprintf("no %v of %v in the fixture", table, kind))
}

// costMeter times the server's work on this machine, one core, caching the
// row product by column count.
type costMeter struct {
	minTime time.Duration
	rows    map[int]time.Duration
	cell    time.Duration
}

func newCostMeter(minTime time.Duration) *costMeter {
	return &costMeter{minTime: minTime, rows: make(map[int]time.Duration)}
}

// timeOp is the mean time of f over runs filling at least least, after one
// run to warm it.
func timeOp(least time.Duration, f func()) time.Duration {
	f()
	start := time.Now()
	for n := 1; ; n++ {
		f()
		if el := time.Since(start); el >= least {
			return el / time.Duration(n)
		}
	}
}

// row is the time of the product of one row of cols cells with a query,
// in the database's own code (rowProduct), on random cells and query.
func (m *costMeter) row(cols int) time.Duration {
	if d, ok := m.rows[cols]; ok {
		return d
	}
	p := newPRNG(testSeed(fmt.Sprintf("row of %d", cols)))
	db := &Database{shape: Shape{Rows: 1, Cols: cols}, cells: make([]uint64, cols*N)}
	p.uniform(db.cells)
	v := make([][]uint64, cols)
	flat := make([]uint64, cols*N)
	p.uniform(flat)
	for j := range v {
		v[j] = flat[j*N : (j+1)*N : (j+1)*N]
	}
	acc := newAccumulator()
	dst := make([]uint32, N)
	d := timeOp(m.minTime, func() { db.rowProduct(acc, 0, v, dst) })
	m.rows[cols] = d
	return d
}

// cellNTT is the time to bring one cell's plaintext into NTT form, as
// NewDatabase does for every cell.
func (m *costMeter) cellNTT() time.Duration {
	if m.cell > 0 {
		return m.cell
	}
	plain := testRecords(7, 1, CellBytes)[0]
	dst := make([]uint64, N)
	m.cell = timeOp(m.minTime, func() {
		for k := range dst {
			dst[k] = signedMod(int64(int16(uint16(plain[2*k]) | uint16(plain[2*k+1])<<8)))
		}
		forwardNTT(dst)
	})
	return m.cell
}

// dbCost is the measured cost of one database.
type dbCost struct {
	db         *sizeDB
	query      time.Duration // core time of one answer: Rows row products
	preprocess time.Duration // core time of its preprocessing: the a_j, the NTT of every cell and the hint
}

func (m *costMeter) cost(d *sizeDB) dbCost {
	s := d.shape
	row := m.row(s.Cols)
	cells, _ := s.cellCount()
	expand := timeOp(m.minTime, func() { publicA(s.Seed, s.Cols) })
	return dbCost{
		db:         d,
		query:      time.Duration(s.Rows) * row,
		preprocess: expand + time.Duration(cells)*m.cellNTT() + time.Duration(s.Rows)*row,
	}
}

// restoreReport is the figures of one fixture size.
type restoreReport struct {
	size   restoreSize
	counts chainCounts
	costs  []dbCost

	databaseBytes   int64
	preprocess      time.Duration
	bulkBytes       int64
	queries         float64
	queryBytes      float64 // queries and answers of a restore
	restoreCoreTime time.Duration
}

func (r *restoreReport) downloadMB() float64 {
	return (float64(r.bulkBytes) + r.queryBytes) / 1e6
}

// bulkBytes is the bulk data a restore reads: the snapshot header, the tops
// of one coin and one data tree, and the blocks of an interval after the
// snapshot, at the fixture's load.
func bulkBytes(c chainCounts, entries int) int64 {
	header := 8 + 4*common.HashLength + 4 + entries*snapshotEntryBytes
	level := topLevel()
	var tops int
	for _, n := range []uint64{c.coinLeaves, c.dataLeaves} {
		nodes := (n + uint64(1)<<level - 1) >> level
		tops += len((&TreeTops{Nodes: make([]common.Hash, nodes)}).Encode())
	}
	blocks := SnapshotInterval - 1
	perBlock := 8 + common.HashLength + 4 + 4 +
		(coinLeavesPerBlock+dataLeavesPerBlock)*TagEntryBytes +
		(coinMarkersPerBlock+dataMarkersPerBlock)*MarkerEntryBytes
	return int64(header+tops) + int64(math.Ceil(float64(blocks)*perBlock))
}

// overflowColumns is the expected number of columns the overflow run of one
// bucket spans, its start uniform within a column.
func overflowColumns(d *sizeDB, run float64) float64 {
	if run <= 0 {
		return 0
	}
	perColumn := float64(d.shape.Rows * d.shape.RecordsPerCell)
	return math.Min(float64(d.shape.Cols), 1+(run-1)/perColumn)
}

func measureRestore(size restoreSize, m *costMeter) (*restoreReport, error) {
	c := countsAt(size.years)
	dbs, err := fixtureDatabases(c)
	if err != nil {
		return nil, err
	}
	r := &restoreReport{size: size, counts: c, bulkBytes: bulkBytes(c, len(dbs))}
	costs := make(map[*sizeDB]dbCost)
	for _, d := range dbs {
		dc := m.cost(d)
		costs[d] = dc
		r.costs = append(r.costs, dc)
		r.databaseBytes += int64(d.shape.DatabaseBytes())
		r.preprocess += dc.preprocess
	}
	read := func(d *sizeDB, n float64) {
		r.queries += n
		r.queryBytes += n * float64(d.shape.QueryBytes()+d.shape.AnswerBytes())
		r.restoreCoreTime += time.Duration(n * float64(costs[d].query))
	}
	for _, note := range []struct {
		kind    ghosttree.Kind
		witness Table
		count   float64
		leaves  uint64
	}{
		{ghosttree.Coin, WitnessTable, restoreCoinNotes, c.coinLeaves},
		{ghosttree.Data, LookupTable, restoreDataNotes, c.dataLeaves},
	} {
		buckets, _ := hintCounts(note.leaves)
		run := float64(note.leaves)/float64(buckets) - HintSlots
		read(findSizeDB(dbs, HintBucketTable, note.kind), note.count)
		overflow := findSizeDB(dbs, HintOverflowTable, note.kind)
		read(overflow, note.count*overflowColumns(overflow, run))
		read(findSizeDB(dbs, NoteTable, note.kind), note.count)
		read(findSizeDB(dbs, note.witness, note.kind), note.count)
	}
	return r, nil
}

// log writes the report: the machine, every database and the totals beside
// the published figures.
func (r *restoreReport) log(tb testing.TB, machine string) {
	c := r.counts
	var b strings.Builder
	fmt.Fprintf(&b, "%s chain (fixture): %d coin leaves, %d data leaves, %d coin markers, %d data markers\n",
		r.size.name, c.coinLeaves, c.dataLeaves, c.coinMarkers, c.dataMarkers)
	fmt.Fprintf(&b, "measured on %s, one core\n", machine)
	fmt.Fprintf(&b, "%-26s %12s %7s %11s %11s %11s %11s %13s %15s\n",
		"database", "records", "rec B", "grid", "db MB", "query B", "answer B", "core-s/query", "preprocess s")
	for _, dc := range r.costs {
		s := dc.db.shape
		fmt.Fprintf(&b, "%-26s %12d %7d %11s %11.1f %11d %11d %13.3f %15.2f\n",
			dc.db.name(), dc.db.records, dc.db.recordSize, fmt.Sprintf("%dx%d", s.Rows, s.Cols),
			float64(s.DatabaseBytes())/1e6, s.QueryBytes(), s.AnswerBytes(),
			dc.query.Seconds(), dc.preprocess.Seconds())
	}
	fmt.Fprintf(&b, "snapshot: %.1f MB of databases, %.1f core-seconds of preprocessing per rebuild (measured)\n",
		float64(r.databaseBytes)/1e6, r.preprocess.Seconds())
	fmt.Fprintf(&b, "restore of %d coin and %d data notes: %.1f PIR queries, %.1f MB bulk, %.1f MB total download, %.1f server core-seconds (measured)\n",
		restoreCoinNotes, restoreDataNotes, r.queries, float64(r.bulkBytes)/1e6, r.downloadMB(), r.restoreCoreTime.Seconds())
	fmt.Fprintf(&b, "published: %.1f MB total download (measured/published %.2f), %.0f core-seconds a restore (measured/published %.3f)",
		r.size.publishedDownloadMB, r.downloadMB()/r.size.publishedDownloadMB,
		r.size.publishedCoreSeconds, r.restoreCoreTime.Seconds()/r.size.publishedCoreSeconds)
	tb.Log(b.String())
}

// BenchmarkRestoreSizes records the restore server's figures at the
// one-year and five-year fixture chain sizes (see the top of this file).
// Its timed loop is the product of one row of the coin note database, the
// unit every query and every rebuild's hint is made of; the figures are
// logged and reported as metrics, labelled measured with the machine named.
func BenchmarkRestoreSizes(b *testing.B) {
	machine := benchMachine()
	for _, size := range restoreSizes {
		b.Run(size.name, func(b *testing.B) {
			m := newCostMeter(200 * time.Millisecond)
			r, err := measureRestore(size, m)
			if err != nil {
				b.Fatal(err)
			}
			notes := findSizeDB(fixtureDBs(r), NoteTable, ghosttree.Coin)
			cols := notes.shape.Cols
			p := newPRNG(testSeed("bench row"))
			db := &Database{shape: Shape{Rows: 1, Cols: cols}, cells: make([]uint64, cols*N)}
			p.uniform(db.cells)
			v := make([][]uint64, cols)
			for j := range v {
				v[j] = make([]uint64, N)
				p.uniform(v[j])
			}
			acc, dst := newAccumulator(), make([]uint32, N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				db.rowProduct(acc, 0, v, dst)
			}
			b.StopTimer()
			b.ReportMetric(float64(r.databaseBytes)/1e6, "db-MB")
			b.ReportMetric(r.preprocess.Seconds(), "preprocess-core-s/rebuild")
			b.ReportMetric(r.queries, "queries/restore")
			b.ReportMetric(r.downloadMB(), "download-MB/restore")
			b.ReportMetric(r.restoreCoreTime.Seconds(), "core-s/restore")
			b.ReportMetric(size.publishedDownloadMB, "published-download-MB")
			b.ReportMetric(size.publishedCoreSeconds, "published-core-s")
			r.log(b, machine)
		})
	}
}

func fixtureDBs(r *restoreReport) []*sizeDB {
	out := make([]*sizeDB, len(r.costs))
	for i, dc := range r.costs {
		out[i] = dc.db
	}
	return out
}

// TestRestoreSizeFixture checks the fixture the benchmark sizes from: both
// chain sizes lay out as valid grids, five years cost more than one in every
// figure, and the report is built from the costs it measured. It times each
// operation once, so its figures are not the benchmark's.
func TestRestoreSizeFixture(t *testing.T) {
	m := newCostMeter(0)
	var reports []*restoreReport
	for _, size := range restoreSizes {
		r, err := measureRestore(size, m)
		if err != nil {
			t.Fatal(err)
		}
		for _, dc := range r.costs {
			if err := dc.db.shape.Validate(); err != nil {
				t.Fatalf("%s %s: %v", size.name, dc.db.name(), err)
			}
			if dc.query <= 0 || dc.preprocess <= dc.query {
				t.Fatalf("%s %s: query %v, preprocessing %v", size.name, dc.db.name(), dc.query, dc.preprocess)
			}
		}
		if r.queries < 4*(restoreCoinNotes+restoreDataNotes) || r.bulkBytes <= 0 || r.restoreCoreTime <= 0 {
			t.Fatalf("%s restore: %.1f queries, %d bulk bytes, %v", size.name, r.queries, r.bulkBytes, r.restoreCoreTime)
		}
		reports = append(reports, r)
	}
	one, five := reports[0], reports[1]
	if five.counts.coinLeaves != 5*one.counts.coinLeaves || one.counts.coinLeaves != 2_103_840 {
		t.Fatalf("fixture coin leaves %d and %d", one.counts.coinLeaves, five.counts.coinLeaves)
	}
	if five.databaseBytes <= one.databaseBytes || five.queryBytes <= one.queryBytes || five.preprocess <= one.preprocess {
		t.Fatal("five years cost no more than one")
	}
	// A coin note's bucket has thousands of entries: most of the tree is in
	// the overflow table.
	notes := findSizeDB(fixtureDBs(one), NoteTable, ghosttree.Coin)
	overflow := findSizeDB(fixtureDBs(one), HintOverflowTable, ghosttree.Coin)
	if overflow.records*2 < notes.records {
		t.Fatalf("%d overflow entries for %d coin leaves", overflow.records, notes.records)
	}
	var b strings.Builder
	one.log(&logCapture{TB: t, out: &b}, benchMachine())
	for _, want := range []string{"measured on ", "published: 187.7 MB", "479 core-seconds", "coin notes"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("report lacks %q:\n%s", want, b.String())
		}
	}
}

// logCapture keeps what is logged to it.
type logCapture struct {
	testing.TB
	out *strings.Builder
}

func (l *logCapture) Log(args ...any) { fmt.Fprint(l.out, args...) }
