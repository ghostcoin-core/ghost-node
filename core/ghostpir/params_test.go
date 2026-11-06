package ghostpir

import (
	"math/big"
	"math/rand/v2"
	"testing"
)

// TestParams checks the modulus is the prime the package comment names and
// that the NTT tables hold a primitive 2N-th root of unity.
func TestParams(t *testing.T) {
	if !new(big.Int).SetUint64(Q).ProbablyPrime(30) {
		t.Fatalf("Q = %d is not prime", Q)
	}
	if Q%(2*N) != 1 || Q >= 1<<QBits {
		t.Fatalf("Q = %d is not 1 mod %d below 2^%d", Q, 2*N, QBits)
	}
	for k := uint64(1); k < 4; k++ {
		if q := uint64(1)<<50 - k*4096 + 1; new(big.Int).SetUint64(q).ProbablyPrime(30) {
			t.Fatalf("%d is a larger prime of the form", q)
		}
	}
	if powMod(ntt.psi, N) != Q-1 || powMod(ntt.psi, 2*N) != 1 {
		t.Fatalf("psi = %d is not a primitive 2N-th root of unity", ntt.psi)
	}
	if Delta != Q/(1<<PBits) || CellBytes != 4096 {
		t.Fatalf("Delta %d, cell %d", Delta, CellBytes)
	}
}

// naiveNegacyclic multiplies in Z_Q[X]/(X^N + 1) by schoolbook.
func naiveNegacyclic(a, b []uint64) []uint64 {
	out := make([]uint64, N)
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			p := mulMod(a[i], b[j])
			if k := i + j; k < N {
				out[k] = addMod(out[k], p)
			} else {
				out[k-N] = subMod(out[k-N], p)
			}
		}
	}
	return out
}

// TestNTTMultipliesInTheRing checks that the transform round trips and that
// the pointwise product of transforms is the negacyclic product.
func TestNTTMultipliesInTheRing(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for trial := 0; trial < 3; trial++ {
		a, b := make([]uint64, N), make([]uint64, N)
		for k := range a {
			a[k], b[k] = r.Uint64N(Q), r.Uint64N(Q)
		}
		if trial == 0 { // X^(N-1) * X = -1
			clear(a)
			clear(b)
			a[N-1], b[1] = 1, 1
		}
		want := naiveNegacyclic(a, b)
		ah, bh := append([]uint64(nil), a...), append([]uint64(nil), b...)
		forwardNTT(ah)
		forwardNTT(bh)
		got := make([]uint64, N)
		for k := range got {
			got[k] = mulMod(ah[k], bh[k])
		}
		inverseNTT(got)
		for k := range got {
			if got[k] != want[k] {
				t.Fatalf("trial %d: coefficient %d is %d, want %d", trial, k, got[k], want[k])
			}
		}
		inverseNTT(ah)
		for k := range ah {
			if ah[k] != a[k] {
				t.Fatalf("trial %d: round trip changed coefficient %d", trial, k)
			}
		}
	}
}

// TestSwitchModulusRounds checks the switch from Q to 2^AnswerBits against
// exact rational rounding.
func TestSwitchModulusRounds(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	qa := new(big.Int).Lsh(big.NewInt(1), AnswerBits)
	bq := new(big.Int).SetUint64(Q)
	for i := 0; i < 10000; i++ {
		x := r.Uint64N(Q)
		switch i {
		case 0:
			x = 0
		case 1:
			x = Q - 1
		case 2:
			x = Q / 2
		}
		num := new(big.Int).Mul(new(big.Int).SetUint64(x), qa)
		num.Add(num, new(big.Int).Rsh(bq, 1))
		num.Div(num, bq)
		num.Mod(num, qa)
		if got := switchModulus(x); uint64(got) != num.Uint64() {
			t.Fatalf("switch(%d) = %d, want %d", x, got, num.Uint64())
		}
	}
}

// TestBitPackingRoundTrips checks the wire packing at both widths.
func TestBitPackingRoundTrips(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for _, width := range []uint{QBits, AnswerBits} {
		vals := make([]uint64, N)
		for k := range vals {
			vals[k] = r.Uint64() & (1<<width - 1)
		}
		buf := make([]byte, N*int(width)/8)
		packBits(buf, vals, width)
		got := make([]uint64, N)
		unpackBits(got, buf, width)
		for k := range got {
			if got[k] != vals[k] {
				t.Fatalf("width %d: value %d is %d, want %d", width, k, got[k], vals[k])
			}
		}
	}
}

// TestCentredBinomialAndTernary checks the moments of the error and secret
// distributions.
func TestCentredBinomialAndTernary(t *testing.T) {
	p := newPRNG([32]byte{7})
	e := make([]uint64, 1<<16)
	p.centredBinomial(e)
	var sum, sq float64
	for _, v := range e {
		x := float64(int64(v))
		if v > Q/2 {
			x = -float64(Q - v)
		}
		if x > errorEta || x < -errorEta {
			t.Fatalf("error %v past eta", x)
		}
		sum += x
		sq += x * x
	}
	n := float64(len(e))
	if mean, variance := sum/n, sq/n-(sum/n)*(sum/n); mean > 0.1 || mean < -0.1 || variance < 9.8 || variance > 11.2 {
		t.Fatalf("error mean %.3f variance %.3f, want 0 and %.1f", mean, variance, float64(errorEta)/2)
	}
	s := make([]int8, 3<<14)
	p.ternary(s)
	var counts [3]int
	for _, v := range s {
		counts[v+1]++
	}
	for i, c := range counts {
		if c < len(s)/3-600 || c > len(s)/3+600 {
			t.Fatalf("ternary value %d drawn %d times of %d", i-1, c, len(s))
		}
	}
}
