package ghostpir

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
)

var (
	// ErrScheme is returned for a shape that names another scheme.
	ErrScheme = errors.New("ghostpir: shape names another scheme")
	// ErrShape is returned for a shape that is not the grid of its records.
	ErrShape = errors.New("ghostpir: inconsistent database shape")
	// ErrRecordSize is returned for a record of another size than the database's.
	ErrRecordSize = errors.New("ghostpir: record of the wrong size")
	// ErrTooLarge is returned for a database past MaxRows * MaxCols cells.
	ErrTooLarge = errors.New("ghostpir: database too large")
	// ErrIndex is returned for a record index outside the database.
	ErrIndex = errors.New("ghostpir: record index out of range")
)

// Shape is the public description of a snapshot's database: everything a
// client needs, besides the seed's expansion, to query it.
type Shape struct {
	Scheme string   // SchemeName
	Seed   [32]byte // the snapshot's identity, from which the a_j expand

	RecordSize int // bytes in every record
	Records    int // number of records

	RecordsPerCell int // records packed into one cell (1 for a record past a cell)
	CellsPerRecord int // cells one record spans (1 for a record of a cell or less)

	Rows int // rows of the grid; a multiple of CellsPerRecord
	Cols int // columns of the grid; the number of ring elements in a query
}

// NewShape lays out records of recordSize bytes on a grid of cells, as near
// square as MaxCols and the record's span allow.
func NewShape(seed [32]byte, recordSize, records int) (Shape, error) {
	if recordSize <= 0 || records <= 0 {
		return Shape{}, fmt.Errorf("%w: %d records of %d bytes", ErrShape, records, recordSize)
	}
	s := Shape{Scheme: SchemeName, Seed: seed, RecordSize: recordSize, Records: records, RecordsPerCell: 1, CellsPerRecord: 1}
	if recordSize <= CellBytes {
		s.RecordsPerCell = CellBytes / recordSize
	} else {
		s.CellsPerRecord = (recordSize + CellBytes - 1) / CellBytes
	}
	cells, ok := s.cellCount()
	if !ok || cells > MaxRows*MaxCols {
		return Shape{}, fmt.Errorf("%w: %d records of %d bytes", ErrTooLarge, records, recordSize)
	}
	cpr := s.CellsPerRecord
	rows := int(math.Ceil(math.Sqrt(float64(cells))))
	// Rows are a multiple of the record's span, so no record straddles two
	// columns. With MaxRows = MaxCols, a grid of at most MaxRows * MaxCols
	// cells then has at most MaxCols columns.
	rows = (rows + cpr - 1) / cpr * cpr
	s.Rows = rows
	s.Cols = (cells + rows - 1) / rows
	if err := s.Validate(); err != nil {
		return Shape{}, fmt.Errorf("%w: %d records of %d bytes", ErrTooLarge, records, recordSize)
	}
	return s, nil
}

// cellCount is the number of cells the records fill.
func (s Shape) cellCount() (int, bool) {
	if s.RecordsPerCell > 1 {
		return (s.Records + s.RecordsPerCell - 1) / s.RecordsPerCell, true
	}
	if s.Records > MaxRows*MaxCols/s.CellsPerRecord {
		return 0, false
	}
	return s.Records * s.CellsPerRecord, true
}

// Validate checks that the shape is one NewShape can produce for its own
// record size and count, within the bounds of the scheme.
func (s Shape) Validate() error {
	if s.Scheme != SchemeName {
		return fmt.Errorf("%w: %q", ErrScheme, s.Scheme)
	}
	if s.RecordSize <= 0 || s.Records <= 0 || s.RecordsPerCell <= 0 || s.CellsPerRecord <= 0 {
		return ErrShape
	}
	if s.RecordSize <= CellBytes {
		if s.CellsPerRecord != 1 || s.RecordsPerCell != CellBytes/s.RecordSize {
			return ErrShape
		}
	} else if s.RecordsPerCell != 1 || s.CellsPerRecord != (s.RecordSize+CellBytes-1)/CellBytes {
		return ErrShape
	}
	if s.Rows <= 0 || s.Cols <= 0 || s.Rows > MaxRows || s.Cols > MaxCols || s.Rows%s.CellsPerRecord != 0 {
		return ErrShape
	}
	cells, ok := s.cellCount()
	if !ok || cells > s.Rows*s.Cols || cells <= s.Rows*(s.Cols-1) {
		return ErrShape
	}
	return nil
}

// cellOf is the first cell of record i and the byte offset of the record
// in it. Cells run down a column, then on to the next one.
func (s Shape) cellOf(i int) (cell, offset int) {
	if s.CellsPerRecord > 1 {
		return i * s.CellsPerRecord, 0
	}
	return i / s.RecordsPerCell, (i % s.RecordsPerCell) * s.RecordSize
}

// Locate is the column a query for record i selects and the first row of
// the record in it. The column is all a query depends on.
func (s Shape) Locate(i int) (col, row int, err error) {
	if i < 0 || i >= s.Records {
		return 0, 0, fmt.Errorf("%w: %d of %d", ErrIndex, i, s.Records)
	}
	cell, _ := s.cellOf(i)
	return cell / s.Rows, cell % s.Rows, nil
}

// QueryBytes is the size of every query to this shape.
func (s Shape) QueryBytes() int { return headerBytes + s.Cols*N*QBits/8 }

// AnswerBytes is the size of every answer from this shape.
func (s Shape) AnswerBytes() int { return headerBytes + 2*s.Rows*N*AnswerBits/8 }

// DatabaseBytes is the plaintext size of the grid, padding included.
func (s Shape) DatabaseBytes() int { return s.Rows * s.Cols * CellBytes }

// publicA expands the public ring elements a_j of a shape's seed, one per
// column, in NTT form.
func publicA(seed [32]byte, cols int) [][]uint64 {
	h := sha256.New()
	h.Write([]byte(SchemeName + "/public-a/v1"))
	h.Write(seed[:])
	var key [32]byte
	copy(key[:], h.Sum(nil))
	p := newPRNG(key)
	flat := make([]uint64, cols*N)
	p.uniform(flat)
	a := make([][]uint64, cols)
	for j := range a {
		a[j] = flat[j*N : (j+1)*N : (j+1)*N]
	}
	return a
}

// Database is a snapshot's database, preprocessed for answering: every cell
// in NTT form and the hint of every row.
type Database struct {
	shape Shape
	cells []uint64 // Rows * Cols cells of N values, row by row, in NTT form
	hint  []uint32 // Rows ring elements mod 2^AnswerBits, coefficient form
}

// NewDatabase builds and preprocesses the database of records under a
// snapshot seed. Every record must be recordSize bytes. The work is the
// preprocessing of a rebuild: one NTT per cell and the hint of every row.
func NewDatabase(seed [32]byte, recordSize int, records [][]byte) (*Database, error) {
	shape, err := NewShape(seed, recordSize, len(records))
	if err != nil {
		return nil, err
	}
	for i, r := range records {
		if len(r) != recordSize {
			return nil, fmt.Errorf("%w: record %d has %d bytes, want %d", ErrRecordSize, i, len(r), recordSize)
		}
	}
	db := &Database{shape: shape, cells: make([]uint64, shape.Rows*shape.Cols*N)}
	total, _ := shape.cellCount()
	parallel(total, func(lo, hi int) {
		plain := make([]byte, CellBytes)
		for c := lo; c < hi; c++ {
			clear(plain)
			shape.fillCell(plain, c, records)
			row, col := c%shape.Rows, c/shape.Rows
			dst := db.cells[(row*shape.Cols+col)*N : (row*shape.Cols+col+1)*N]
			for k := range dst {
				dst[k] = signedMod(int64(int16(uint16(plain[2*k]) | uint16(plain[2*k+1])<<8)))
			}
			forwardNTT(dst)
		}
	})
	a := publicA(seed, shape.Cols)
	db.hint = make([]uint32, shape.Rows*N)
	parallel(shape.Rows, func(lo, hi int) {
		acc := newAccumulator()
		for r := lo; r < hi; r++ {
			db.rowProduct(acc, r, a, db.hint[r*N:(r+1)*N])
		}
	})
	return db, nil
}

// fillCell writes the plaintext bytes of cell c.
func (s Shape) fillCell(dst []byte, c int, records [][]byte) {
	if s.CellsPerRecord > 1 {
		rec, part := c/s.CellsPerRecord, c%s.CellsPerRecord
		start := part * CellBytes
		end := min(start+CellBytes, s.RecordSize)
		copy(dst, records[rec][start:end])
		return
	}
	for k := 0; k < s.RecordsPerCell; k++ {
		i := c*s.RecordsPerCell + k
		if i >= s.Records {
			return
		}
		copy(dst[k*s.RecordSize:], records[i])
	}
}

// Shape is the public description of the database.
func (db *Database) Shape() Shape { return db.shape }

// accumulator holds 128-bit sums of products, one per coefficient.
type accumulator struct {
	hi, lo [N]uint64
	out    [N]uint64
}

func newAccumulator() *accumulator { return new(accumulator) }

// rowProduct computes sum_j D[r][j] * v_j for the NTT-form vectors v (one
// per column), switched to mod 2^AnswerBits in coefficient form, into dst.
// Products are summed in 128 bits and reduced once: a product is below
// 2^100 and there are at most MaxCols of them.
func (db *Database) rowProduct(acc *accumulator, r int, v [][]uint64, dst []uint32) {
	clear(acc.hi[:])
	clear(acc.lo[:])
	cols := db.shape.Cols
	for j := 0; j < cols; j++ {
		d := db.cells[(r*cols+j)*N : (r*cols+j+1)*N]
		x := v[j][:N]
		for k := 0; k < N; k++ {
			h, l := bits64Mul(d[k], x[k])
			var c uint64
			acc.lo[k], c = bits64Add(acc.lo[k], l)
			acc.hi[k] += h + c
		}
	}
	for k := 0; k < N; k++ {
		acc.out[k] = reduce128(acc.hi[k], acc.lo[k])
	}
	inverseNTT(acc.out[:])
	for k := 0; k < N; k++ {
		dst[k] = switchModulus(acc.out[k])
	}
}

// parallel runs f over [0, n) split into contiguous ranges, one per CPU.
func parallel(n int, f func(lo, hi int)) {
	workers := min(runtime.GOMAXPROCS(0), n)
	if workers <= 1 {
		f(0, n)
		return
	}
	var wg sync.WaitGroup
	step := (n + workers - 1) / workers
	for lo := 0; lo < n; lo += step {
		hi := min(lo+step, n)
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(lo, hi)
		}()
	}
	wg.Wait()
}
