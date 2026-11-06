package ghostpir

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/exp/slog"
)

// testRecords returns n deterministic pseudo-random records of size bytes.
func testRecords(seed uint64, n, size int) [][]byte {
	r := rand.New(rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8)}))
	recs := make([][]byte, n)
	for i := range recs {
		recs[i] = make([]byte, size)
		for k := range recs[i] {
			recs[i][k] = byte(r.Uint32())
		}
	}
	return recs
}

func testSeed(label string) [32]byte { return sha256.Sum256([]byte("ghostpir test snapshot " + label)) }

// recordingHandler keeps every log record the server writes.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// take returns and forgets the records so far, each as its level, message
// and attributes, without the elapsed time (the one field that varies).
func (h *recordingHandler) take() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %q", r.Level, r.Message)
		r.Attrs(func(a slog.Attr) bool {
			if a.Key != "elapsed" {
				fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
			}
			return true
		})
		out = append(out, b.String())
	}
	h.records = nil
	return out
}

// newTestServer builds a database and a server logging to a recorder.
func newTestServer(t *testing.T, label string, size, n int) (*Server, *Client, [][]byte, *recordingHandler) {
	t.Helper()
	recs := testRecords(uint64(size*7+n), n, size)
	db, err := NewDatabase(testSeed(label), size, recs)
	if err != nil {
		t.Fatalf("NewDatabase: %v", err)
	}
	h := new(recordingHandler)
	srv := NewServer(db, log.NewLogger(h))
	c, err := NewClient(srv.Shape())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, c, recs, h
}

// fetch runs one query for index through the server and decodes it, with
// the client's randomness from rnd (crypto/rand when nil).
func fetch(t *testing.T, srv *Server, c *Client, index int, rnd io.Reader) (record, query, answer []byte) {
	t.Helper()
	query, st, err := c.Query(index, rnd)
	if err != nil {
		t.Fatalf("Query(%d): %v", index, err)
	}
	answer, err = srv.Answer("restore-client", query)
	if err != nil {
		t.Fatalf("Answer for %d: %v", index, err)
	}
	record, err = c.Decode(st, answer)
	if err != nil {
		t.Fatalf("Decode(%d): %v", index, err)
	}
	return record, query, answer
}

// centred maps x mod m to (-m/2, m/2].
func centred(x, m uint64) int64 {
	if x > m/2 {
		return -int64(m - x)
	}
	return int64(x)
}

// queryCoefficients parses a query as the server receives it and returns
// every column in coefficient form.
func queryCoefficients(t *testing.T, s Shape, query []byte) [][]uint64 {
	t.Helper()
	b, err := decodeQuery(s, query)
	if err != nil {
		t.Fatalf("server-side parse: %v", err)
	}
	for _, v := range b {
		inverseNTT(v)
	}
	return b
}

// cellPlain is the public plaintext of grid cell (row, col), as centred
// 16-bit coefficients: what any full node knows of the database.
func cellPlain(s Shape, recs [][]byte, row, col int) []int64 {
	out := make([]int64, N)
	c := col*s.Rows + row
	total, _ := s.cellCount()
	if c >= total {
		return out
	}
	plain := make([]byte, CellBytes)
	s.fillCell(plain, c, recs)
	for k := range out {
		out[k] = int64(int16(uint16(plain[2*k]) | uint16(plain[2*k+1])<<8))
	}
	return out
}

// The distinguishers below play the server: they see only the query bytes,
// the answer bytes and the public database, and guess which of two indices
// was asked for. Each returns true for a guess of index 1.

// guessFromQuery looks for the encoding of Delta * 1 in the constant
// coefficient of each candidate column, which a query without the a_j * s
// mask shows openly.
func guessFromQuery(cols [][]uint64, col0, col1 int) bool {
	d0 := math.Abs(float64(centred(subMod(cols[col0][0], Delta), Q)))
	d1 := math.Abs(float64(centred(subMod(cols[col1][0], Delta), Q)))
	return d1 < d0
}

// guessFromAnswer compares the answer for the record's row with Delta' times
// the public cell each candidate would select.
func guessFromAnswer(answer []byte, s Shape, plain0, plain1 []int64, row0, row1 int) bool {
	dist := func(row int, plain []int64) float64 {
		x := answerRow(answer, s.Rows, 1, row)
		var d float64
		for k := range x {
			want := uint64(plain[k]<<(AnswerBits-PBits)) & answerMask
			d += math.Abs(float64(centred((x[k]-want)&answerMask, 1<<AnswerBits)))
		}
		return d
	}
	return dist(row1, plain1) < dist(row0, plain0)
}

// uniformityChi2 is the chi-square statistic of the top 4 bits of every
// coefficient of every column, against uniform mod Q.
func uniformityChi2(counts *[16]float64) float64 {
	var n float64
	for _, c := range counts {
		n += c
	}
	var chi2 float64
	for _, c := range counts {
		e := n / 16
		chi2 += (c - e) * (c - e) / e
	}
	return chi2
}

func TestRingLWEPIR_AnswersCorrectlyAndHidesIndex(t *testing.T) {
	t.Run("every note-sized record", func(t *testing.T) {
		srv, c, recs, _ := newTestServer(t, "notes", 380, 300)
		s := srv.Shape()
		if s.RecordsPerCell != 10 || s.CellsPerRecord != 1 || s.Rows*s.Cols < 30 {
			t.Fatalf("unexpected shape %+v", s)
		}
		for i := range recs {
			got, _, _ := fetch(t, srv, c, i, nil)
			if !slices.Equal(got, recs[i]) {
				t.Fatalf("record %d decoded wrong", i)
			}
		}
	})
	t.Run("every record spanning two cells", func(t *testing.T) {
		srv, c, recs, _ := newTestServer(t, "witnesses", CellBytes+904, 30)
		s := srv.Shape()
		if s.CellsPerRecord != 2 || s.Rows%2 != 0 {
			t.Fatalf("unexpected shape %+v", s)
		}
		for i := range recs {
			got, _, _ := fetch(t, srv, c, i, nil)
			if !slices.Equal(got, recs[i]) {
				t.Fatalf("record %d decoded wrong", i)
			}
		}
	})
	t.Run("server view does not reveal the index", func(t *testing.T) {
		srv, c, recs, logs := newTestServer(t, "notes", 380, 300)
		s := srv.Shape()
		idx := [2]int{0, len(recs) - 1}
		var col, row [2]int
		var plain [2][]int64
		for b, i := range idx {
			var err error
			if col[b], row[b], err = s.Locate(i); err != nil {
				t.Fatal(err)
			}
			plain[b] = cellPlain(s, recs, row[b], col[b])
		}
		if col[0] == col[1] || row[0] == row[1] {
			t.Fatalf("indices %v share a column or row: %v %v", idx, col, row)
		}

		// The choice of index and the client's randomness come from fixed
		// seeds, so the statistics below are the same on every run.
		const trials = 256
		bitsRand := rand.New(rand.NewPCG(11, 12))
		clientRand := rand.NewChaCha8([32]byte{'c', 'l', 'i', 'e', 'n', 't'})
		var queryWins, answerWins int
		var counts [16]float64
		var wantLog []string
		seen := make(map[[32]byte]bool)
		for trial := 0; trial < trials; trial++ {
			b := bitsRand.IntN(2)
			got, query, answer := fetch(t, srv, c, idx[b], clientRand)
			if !slices.Equal(got, recs[idx[b]]) {
				t.Fatalf("trial %d: record %d decoded wrong", trial, idx[b])
			}
			// Sizes are fixed by the shape.
			if len(query) != s.QueryBytes() || len(answer) != s.AnswerBytes() {
				t.Fatalf("trial %d: query %d answer %d bytes, want %d and %d",
					trial, len(query), len(answer), s.QueryBytes(), s.AnswerBytes())
			}
			// Every query is fresh: none repeats.
			if h := sha256.Sum256(query); seen[h] {
				t.Fatalf("trial %d: a query repeated", trial)
			} else {
				seen[h] = true
			}
			// The log is the same for every index.
			lines := logs.take()
			if len(lines) != 1 {
				t.Fatalf("trial %d: %d log records, want 1", trial, len(lines))
			}
			if wantLog == nil {
				wantLog = lines
			} else if lines[0] != wantLog[0] {
				t.Fatalf("trial %d: log differs by index:\n%s\n%s", trial, lines[0], wantLog[0])
			}
			cols := queryCoefficients(t, s, query)
			if guessFromQuery(cols, col[0], col[1]) == (b == 1) {
				queryWins++
			}
			if guessFromAnswer(answer, s, plain[0], plain[1], row[0], row[1]) == (b == 1) {
				answerWins++
			}
			for _, v := range cols {
				for _, x := range v {
					counts[x>>(QBits-4)]++
				}
			}
		}
		// Each distinguisher must do no better than a coin: within four
		// standard deviations of trials / 2.
		limit := 4 * math.Sqrt(trials) / 2
		t.Logf("of %d trials the query distinguisher guessed %d, the answer distinguisher %d; uniformity chi-square %.1f",
			trials, queryWins, answerWins, uniformityChi2(&counts))
		for name, wins := range map[string]int{"query": queryWins, "answer": answerWins} {
			if math.Abs(float64(wins)-trials/2) > limit {
				t.Errorf("%s distinguisher guessed %d of %d, coin bound %.0f", name, wins, trials, limit)
			}
		}
		// 15 degrees of freedom: 60 is past a 1e-6 tail.
		if chi2 := uniformityChi2(&counts); chi2 > 60 {
			t.Errorf("query coefficients are not uniform: chi-square %.1f", chi2)
		}
		if !strings.Contains(wantLog[0], "query=") || strings.Contains(wantLog[0], fmt.Sprint(idx[1])) {
			t.Errorf("unexpected log record %s", wantLog[0])
		}

		// Control: the same distinguishers on queries without the a_j * s
		// mask (a zero secret) must win, or they could not catch a leak.
		var ctlQuery, ctlAnswer int
		var ctlCounts [16]float64
		zero := make([]int8, N)
		for trial := 0; trial < 64; trial++ {
			b := trial & 1
			query := c.encrypt(idx[b], zero, newPRNG([32]byte{byte(trial), 0xc7}))
			answer, err := srv.Answer("control", query)
			if err != nil {
				t.Fatal(err)
			}
			cols := queryCoefficients(t, s, query)
			if guessFromQuery(cols, col[0], col[1]) == (b == 1) {
				ctlQuery++
			}
			if guessFromAnswer(answer, s, plain[0], plain[1], row[0], row[1]) == (b == 1) {
				ctlAnswer++
			}
			for _, v := range cols {
				for _, x := range v {
					ctlCounts[x>>(QBits-4)]++
				}
			}
		}
		if ctlQuery < 62 || ctlAnswer < 62 {
			t.Errorf("distinguishers too weak on unmasked queries: query %d, answer %d of 64", ctlQuery, ctlAnswer)
		}
		if chi2 := uniformityChi2(&ctlCounts); chi2 < 1000 {
			t.Errorf("uniformity test passed unmasked queries: chi-square %.1f", chi2)
		}
	})
}

// TestServerRefusesForeignQueries checks a query of another snapshot, size,
// magic or with a coefficient not below Q is refused, and logged without
// an answer.
func TestServerRefusesForeignQueries(t *testing.T) {
	srv, c, _, logs := newTestServer(t, "notes", 380, 300)
	query, _, err := c.Query(5, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewShape(testSeed("another snapshot"), 380, 300)
	if err != nil {
		t.Fatal(err)
	}
	oc, err := NewClient(other)
	if err != nil {
		t.Fatal(err)
	}
	stale, _, err := oc.Query(5, nil)
	if err != nil {
		t.Fatal(err)
	}
	badMagic := slices.Clone(query)
	badMagic[3] = '2'
	badCoef := slices.Clone(query)
	for k := 0; k < 7; k++ { // the first coefficient: all 50 bits set
		badCoef[headerBytes+k] = 0xff
	}
	for name, tc := range map[string]struct {
		q    []byte
		want error
	}{
		"stale snapshot": {stale, ErrStaleSnapshot},
		"short":          {query[:len(query)-1], ErrQueryShape},
		"long":           {append(slices.Clone(query), 0), ErrQueryShape},
		"magic":          {badMagic, ErrQueryShape},
		"coefficient":    {badCoef, ErrQueryCoefficient},
	} {
		if ans, err := srv.Answer("x", tc.q); !errors.Is(err, tc.want) || ans != nil {
			t.Errorf("%s: answer %d bytes, err %v, want %v", name, len(ans), err, tc.want)
		}
	}
	for _, l := range logs.take() {
		if !strings.Contains(l, "Refused PIR query") {
			t.Errorf("unexpected log %s", l)
		}
	}
	if _, _, err := c.Query(300, nil); !errors.Is(err, ErrIndex) {
		t.Errorf("Query past the end: %v", err)
	}
	if _, _, err := c.Query(-1, nil); !errors.Is(err, ErrIndex) {
		t.Errorf("Query below zero: %v", err)
	}
}

// TestShapes checks the grid layout: square-ish, bounded columns, records
// never straddling a column, and the sizes that follow.
func TestShapes(t *testing.T) {
	seed := testSeed("shapes")
	for _, tc := range []struct{ size, n int }{
		{380, 1}, {380, 10}, {380, 11}, {380, 1 << 20}, {1, 1}, {CellBytes, 7},
		{CellBytes + 1, 5}, {3*CellBytes + 1, 1000}, {1024, MaxCols * 40},
	} {
		s, err := NewShape(seed, tc.size, tc.n)
		if err != nil {
			t.Fatalf("%d records of %d: %v", tc.n, tc.size, err)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		if s.Cols > MaxCols || s.Rows%s.CellsPerRecord != 0 {
			t.Fatalf("%+v breaks the grid bounds", s)
		}
		for _, i := range []int{0, tc.n / 2, tc.n - 1} {
			col, row, err := s.Locate(i)
			if err != nil || col >= s.Cols || row+s.CellsPerRecord > s.Rows {
				t.Fatalf("%+v: record %d at col %d row %d (%v)", s, i, col, row, err)
			}
		}
		if s.QueryBytes() != 40+s.Cols*12800 || s.AnswerBytes() != 40+s.Rows*14336 {
			t.Fatalf("%+v: query %d answer %d bytes", s, s.QueryBytes(), s.AnswerBytes())
		}
	}
	if _, err := NewShape(seed, 380, 0); !errors.Is(err, ErrShape) {
		t.Errorf("empty database: %v", err)
	}
	if _, err := NewShape(seed, CellBytes, MaxRows*MaxCols+1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized database: %v", err)
	}
	s, _ := NewShape(seed, 380, 300)
	s.Scheme = "another scheme"
	if _, err := NewClient(s); !errors.Is(err, ErrScheme) {
		t.Errorf("client for another scheme: %v", err)
	}
	if _, err := NewDatabase(seed, 380, [][]byte{make([]byte, 379)}); !errors.Is(err, ErrRecordSize) {
		t.Errorf("short record: %v", err)
	}
}
