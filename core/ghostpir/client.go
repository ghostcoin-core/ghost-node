package ghostpir

import (
	"crypto/rand"
	"fmt"
	"io"
)

// Client queries one snapshot's database. It holds only public data: the
// shape and the a_j expanded from the shape's seed.
type Client struct {
	shape Shape
	a     [][]uint64
}

// NewClient prepares queries to a database of the given shape.
func NewClient(shape Shape) (*Client, error) {
	if err := shape.Validate(); err != nil {
		return nil, err
	}
	return &Client{shape: shape, a: publicA(shape.Seed, shape.Cols)}, nil
}

// QueryState is the client's secret for one query: the record asked for and
// the ternary secret s. It never leaves the client.
type QueryState struct {
	index int
	s     []int8
}

// Query encodes a query for record index, drawing the secret and errors from
// rnd (crypto/rand when nil). Every query has a fresh secret.
func (c *Client) Query(index int, rnd io.Reader) ([]byte, *QueryState, error) {
	if _, _, err := c.shape.Locate(index); err != nil {
		return nil, nil, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	var key [32]byte
	if _, err := io.ReadFull(rnd, key[:]); err != nil {
		return nil, nil, fmt.Errorf("ghostpir: query randomness: %w", err)
	}
	p := newPRNG(key)
	s := make([]int8, N)
	p.ternary(s)
	return c.encrypt(index, s, p), &QueryState{index: index, s: s}, nil
}

// encrypt builds b_j = a_j * s + e_j + Delta * [j == col] for every column,
// in NTT form, with the errors drawn from p.
func (c *Client) encrypt(index int, s []int8, p *prng) []byte {
	col, _, _ := c.shape.Locate(index)
	sHat := make([]uint64, N)
	for k, v := range s {
		sHat[k] = signedMod(int64(v))
	}
	forwardNTT(sHat)
	b := make([][]uint64, c.shape.Cols)
	e := make([]uint64, N)
	for j := range b {
		p.centredBinomial(e)
		if j == col {
			e[0] = addMod(e[0], Delta)
		}
		forwardNTT(e)
		bj := make([]uint64, N)
		aj := c.a[j]
		for k := range bj {
			bj[k] = addMod(mulMod(aj[k], sHat[k]), e[k])
		}
		b[j] = bj
	}
	return encodeQuery(c.shape.Seed, b)
}

// Decode recovers the record of a query from the server's answer.
func (c *Client) Decode(st *QueryState, answer []byte) ([]byte, error) {
	s := c.shape
	if st == nil || len(st.s) != N {
		return nil, fmt.Errorf("ghostpir: decode without a query state")
	}
	if err := checkHeader(answer, answerMagic, s.Seed, s.Rows, s.AnswerBytes(), ErrAnswerShape); err != nil {
		return nil, err
	}
	_, row, err := s.Locate(st.index)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 0, s.CellsPerRecord*CellBytes)
	for r := row; r < row+s.CellsPerRecord; r++ {
		h := answerRow(answer, s.Rows, 0, r)
		x := answerRow(answer, s.Rows, 1, r)
		hs := mulTernary(h, st.s)
		for k := 0; k < N; k++ {
			v := (x[k] - hs[k]) & answerMask
			m := ((v + 1<<(AnswerBits-PBits-1)) >> (AnswerBits - PBits)) & (1<<PBits - 1)
			plain = append(plain, byte(m), byte(m>>8))
		}
	}
	_, offset := s.cellOf(st.index)
	return plain[offset : offset+s.RecordSize : offset+s.RecordSize], nil
}

// mulTernary returns h * s in Z_{2^AnswerBits}[X]/(X^N + 1) for a ternary s.
func mulTernary(h []uint64, s []int8) []uint64 {
	out := make([]uint64, N)
	for i, si := range s {
		if si == 0 {
			continue
		}
		for k := 0; k < N; k++ {
			v := h[k]
			idx := i + k
			neg := si < 0
			if idx >= N {
				idx -= N
				neg = !neg
			}
			if neg {
				out[idx] -= v
			} else {
				out[idx] += v
			}
		}
	}
	for k := range out {
		out[k] &= answerMask
	}
	return out
}
