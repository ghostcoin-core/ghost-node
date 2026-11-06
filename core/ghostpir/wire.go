package ghostpir

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire format. A query and an answer both start with a 40-byte header:
//
//	magic (4 bytes: "GPQ1" for a query, "GPA1" for an answer)
//	snapshot seed (32 bytes)
//	count (4 bytes, big endian): the columns of a query, the rows of an answer
//
// then the ring elements, their coefficients packed least significant bit
// first: a query is Cols elements in NTT form, QBits bits a coefficient,
// every one below Q; an answer is Rows hint elements then Rows answer
// elements in coefficient form, AnswerBits bits a coefficient. Both sizes
// are fixed by the shape and every coefficient row fills whole bytes, so an
// encoding has no padding and no other valid form.

const headerBytes = 4 + 32 + 4

var (
	queryMagic  = [4]byte{'G', 'P', 'Q', '1'}
	answerMagic = [4]byte{'G', 'P', 'A', '1'}
)

var (
	// ErrQueryShape is returned for a query that is not the shape of the
	// snapshot's database: another length, magic or column count.
	ErrQueryShape = errors.New("ghostpir: query does not fit the database shape")
	// ErrStaleSnapshot is returned for a query or answer of another snapshot.
	ErrStaleSnapshot = errors.New("ghostpir: query or answer for another snapshot")
	// ErrQueryCoefficient is returned for a query coefficient not below Q.
	ErrQueryCoefficient = errors.New("ghostpir: query coefficient out of range")
	// ErrAnswerShape is returned for an answer that is not the shape the
	// client expects.
	ErrAnswerShape = errors.New("ghostpir: answer does not fit the database shape")
)

func putHeader(dst []byte, magic [4]byte, seed [32]byte, count int) {
	copy(dst[0:4], magic[:])
	copy(dst[4:36], seed[:])
	binary.BigEndian.PutUint32(dst[36:40], uint32(count))
}

// checkHeader checks a message's length, magic, seed and count against what
// the shape fixes for it.
func checkHeader(msg []byte, magic [4]byte, seed [32]byte, count, size int, shapeErr error) error {
	if len(msg) != size {
		return fmt.Errorf("%w: %d bytes, want %d", shapeErr, len(msg), size)
	}
	if [4]byte(msg[0:4]) != magic {
		return fmt.Errorf("%w: bad magic", shapeErr)
	}
	if [32]byte(msg[4:36]) != seed {
		return fmt.Errorf("%w: seed %x, serving %x", ErrStaleSnapshot, msg[4:12], seed[:8])
	}
	if got := binary.BigEndian.Uint32(msg[36:40]); got != uint32(count) {
		return fmt.Errorf("%w: count %d, want %d", shapeErr, got, count)
	}
	return nil
}

// packBits writes vals at width bits each, least significant bit first.
// len(vals) * width must be a multiple of 8 and dst exactly that long.
func packBits(dst []byte, vals []uint64, width uint) {
	var acc uint64
	var n uint
	o := 0
	for _, v := range vals {
		acc |= v << n
		n += width
		for n >= 8 {
			dst[o] = byte(acc)
			o++
			acc >>= 8
			n -= 8
		}
	}
}

// unpackBits reads len(dst) values of width bits each from src.
func unpackBits(dst []uint64, src []byte, width uint) {
	var acc uint64
	var n uint
	o := 0
	mask := uint64(1)<<width - 1
	for i := range dst {
		for n < width {
			acc |= uint64(src[o]) << n
			o++
			n += 8
		}
		dst[i] = acc & mask
		acc >>= width
		n -= width
	}
}

// encodeQuery serialises the NTT-form query elements.
func encodeQuery(seed [32]byte, b [][]uint64) []byte {
	out := make([]byte, headerBytes+len(b)*N*QBits/8)
	putHeader(out, queryMagic, seed, len(b))
	for j, v := range b {
		off := headerBytes + j*N*QBits/8
		packBits(out[off:off+N*QBits/8], v, QBits)
	}
	return out
}

// decodeQuery parses a query to shape s, refusing any coefficient not
// below Q.
func decodeQuery(s Shape, msg []byte) ([][]uint64, error) {
	if err := checkHeader(msg, queryMagic, s.Seed, s.Cols, s.QueryBytes(), ErrQueryShape); err != nil {
		return nil, err
	}
	flat := make([]uint64, s.Cols*N)
	b := make([][]uint64, s.Cols)
	for j := range b {
		b[j] = flat[j*N : (j+1)*N : (j+1)*N]
		off := headerBytes + j*N*QBits/8
		unpackBits(b[j], msg[off:off+N*QBits/8], QBits)
		for _, v := range b[j] {
			if v >= Q {
				return nil, ErrQueryCoefficient
			}
		}
	}
	return b, nil
}

// encodeAnswer serialises the hint rows and answer rows (Rows * N values
// each, mod 2^AnswerBits).
func encodeAnswer(seed [32]byte, rows int, hint, ans []uint32) []byte {
	out := make([]byte, headerBytes+2*rows*N*AnswerBits/8)
	putHeader(out, answerMagic, seed, rows)
	row := make([]uint64, N)
	const rowBytes = N * AnswerBits / 8
	for part, src := range [2][]uint32{hint, ans} {
		for r := 0; r < rows; r++ {
			for k := range row {
				row[k] = uint64(src[r*N+k])
			}
			off := headerBytes + (part*rows+r)*rowBytes
			packBits(out[off:off+rowBytes], row, AnswerBits)
		}
	}
	return out
}

// answerRow reads row r of the hint (part 0) or of the answer (part 1).
func answerRow(msg []byte, rows, part, r int) []uint64 {
	const rowBytes = N * AnswerBits / 8
	row := make([]uint64, N)
	off := headerBytes + (part*rows+r)*rowBytes
	unpackBits(row, msg[off:off+rowBytes], AnswerBits)
	return row
}
