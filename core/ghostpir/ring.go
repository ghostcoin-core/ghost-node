package ghostpir

import (
	"crypto/aes"
	"crypto/cipher"
	"math/bits"
)

// Arithmetic mod Q. Every input is below Q, and so is every output.

func addMod(a, b uint64) uint64 {
	s := a + b
	if s >= Q {
		s -= Q
	}
	return s
}

func subMod(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + Q - b
}

func mulMod(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, r := bits.Div64(hi, lo, Q)
	return r
}

func powMod(a, e uint64) uint64 {
	r := uint64(1)
	for ; e > 0; e >>= 1 {
		if e&1 == 1 {
			r = mulMod(r, a)
		}
		a = mulMod(a, a)
	}
	return r
}

// shoup returns floor(w * 2^64 / Q), the precomputed quotient that lets
// mulShoup multiply by the fixed w without a division.
func shoup(w uint64) uint64 {
	quo, _ := bits.Div64(w, 0, Q)
	return quo
}

// mulShoup returns a * w mod Q, with wp = shoup(w).
func mulShoup(a, w, wp uint64) uint64 {
	hi, _ := bits.Mul64(a, wp)
	r := a*w - hi*Q
	if r >= Q {
		r -= Q
	}
	return r
}

func bits64Mul(a, b uint64) (hi, lo uint64) { return bits.Mul64(a, b) }

func bits64Add(a, b uint64) (sum, carry uint64) { return bits.Add64(a, b, 0) }

// reduce128 returns (hi * 2^64 + lo) mod Q.
func reduce128(hi, lo uint64) uint64 {
	_, r := bits.Div64(hi%Q, lo, Q)
	return r
}

// signedMod maps a small signed integer into [0, Q).
func signedMod(v int64) uint64 {
	if v < 0 {
		return Q - uint64(-v)
	}
	return uint64(v)
}

// The negacyclic NTT of R_q. psi is a primitive 2N-th root of unity mod Q:
// psi = g^((Q-1)/2N) for the smallest g >= 2 with psi^N = -1. The transform
// of a polynomial f is (f(psi^(2*br(i)+1)))_i in the bit-reversed order of
// the Cooley-Tukey butterflies, so that a product in R_q is the pointwise
// product of transforms. A query is sent in this form, so psi is part of the
// wire format.
type nttTables struct {
	psi                     uint64
	psiRev, psiRevShoup     [N]uint64
	psiInvRev, psiInvRevSho [N]uint64
	nInv, nInvShoup         uint64
}

var ntt = newNTTTables()

func newNTTTables() *nttTables {
	t := new(nttTables)
	for g := uint64(2); ; g++ {
		x := powMod(g, (Q-1)/(2*N))
		if powMod(x, N) == Q-1 {
			t.psi = x
			break
		}
	}
	psiInv := powMod(t.psi, Q-2)
	for i := 0; i < N; i++ {
		r := bits.Reverse64(uint64(i)) >> (64 - LogN)
		t.psiRev[i] = powMod(t.psi, r)
		t.psiRevShoup[i] = shoup(t.psiRev[i])
		t.psiInvRev[i] = powMod(psiInv, r)
		t.psiInvRevSho[i] = shoup(t.psiInvRev[i])
	}
	t.nInv = powMod(N, Q-2)
	t.nInvShoup = shoup(t.nInv)
	return t
}

// forwardNTT transforms a (N coefficients below Q) in place.
func forwardNTT(a []uint64) {
	a = a[:N]
	t := N
	for m := 1; m < N; m <<= 1 {
		t >>= 1
		for i := 0; i < m; i++ {
			j1 := 2 * i * t
			w, wp := ntt.psiRev[m+i], ntt.psiRevShoup[m+i]
			for j := j1; j < j1+t; j++ {
				u := a[j]
				v := mulShoup(a[j+t], w, wp)
				a[j] = addMod(u, v)
				a[j+t] = subMod(u, v)
			}
		}
	}
}

// inverseNTT undoes forwardNTT in place.
func inverseNTT(a []uint64) {
	a = a[:N]
	t := 1
	for m := N; m > 1; m >>= 1 {
		j1 := 0
		h := m >> 1
		for i := 0; i < h; i++ {
			w, wp := ntt.psiInvRev[h+i], ntt.psiInvRevSho[h+i]
			for j := j1; j < j1+t; j++ {
				u, v := a[j], a[j+t]
				a[j] = addMod(u, v)
				a[j+t] = mulShoup(subMod(u, v), w, wp)
			}
			j1 += 2 * t
		}
		t <<= 1
	}
	for j := range a {
		a[j] = mulShoup(a[j], ntt.nInv, ntt.nInvShoup)
	}
}

// switchModulus maps x mod Q to round(x * 2^AnswerBits / Q) mod 2^AnswerBits.
func switchModulus(x uint64) uint32 {
	hi, lo := x>>(64-AnswerBits), x<<AnswerBits
	lo, carry := bits.Add64(lo, Q>>1, 0)
	hi += carry
	quo, _ := bits.Div64(hi, lo, Q)
	return uint32(quo & answerMask)
}

// prng is a deterministic byte stream: AES-256 in counter mode under a
// 32-byte key, from a zero counter. Every key is used for one stream only.
type prng struct {
	stream cipher.Stream
	buf    []byte
	pos    int
}

func newPRNG(key [32]byte) *prng {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // a 32-byte key is always accepted
	}
	return &prng{stream: cipher.NewCTR(block, make([]byte, aes.BlockSize)), buf: make([]byte, 8192), pos: 8192}
}

func (p *prng) read(n int) []byte {
	if p.pos+n > len(p.buf) {
		clear(p.buf)
		p.stream.XORKeyStream(p.buf, p.buf)
		p.pos = 0
	}
	out := p.buf[p.pos : p.pos+n]
	p.pos += n
	return out
}

// uniform fills a with independent uniform values mod Q, by rejection from
// 50-bit strings.
func (p *prng) uniform(a []uint64) {
	for i := range a {
		for {
			b := p.read(8)
			v := (uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
				uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56) & (1<<QBits - 1)
			if v < Q {
				a[i] = v
				break
			}
		}
	}
}

// ternary fills s with independent uniform values in {-1, 0, 1}.
func (p *prng) ternary(s []int8) {
	for i := range s {
		for {
			b := p.read(1)[0]
			if b < 255 {
				s[i] = int8(b%3) - 1
				break
			}
		}
	}
}

// centredBinomial fills e with values of the centred binomial distribution
// of parameter errorEta, as residues mod Q.
func (p *prng) centredBinomial(e []uint64) {
	const mask = 1<<errorEta - 1
	for i := range e {
		b := p.read(6)
		v := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40
		x := bits.OnesCount64(v & mask)
		y := bits.OnesCount64((v >> errorEta) & mask)
		e[i] = signedMod(int64(x - y))
	}
}
