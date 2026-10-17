// Copyright 2026 The Ghost Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ghostrules

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"
)

// The expected values below are copied verbatim from the Ghost consensus and
// emission spec (docs/spec/06-consensus-and-emission.md, sections 4.6 and
// 6.6), produced there by an independent script. They are never computed by
// the code under test.

// decimal parses a spec number written with thousands separators.
func decimal(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(strings.ReplaceAll(s, ",", ""), 10)
	if !ok {
		t.Fatalf("bad decimal %q", s)
	}
	return n
}

// asertGenesis is an arbitrary genesis time; the vectors depend only on
// ts - genesis.
const asertGenesis = 1_700_000_000

// asertVectors is the table of spec section 4.6, for the 30-second chain.
var asertVectors = []struct {
	name       string
	height     uint64
	sinceGen   uint64 // ts - genesis
	lag        int64
	exponent   int64
	shifts     int64
	frac       int64
	factor     int64
	difficulty string
}{
	{"on schedule, block 1", 1, 30, 0, 0, 0, 0, 65536, "16,777,216"},
	{"on schedule, block 1000", 1000, 30000, 0, 0, 0, 0, 65536, "16,777,216"},
	{"one second late", 1000, 30001, 1, 18, 0, 18, 65549, "16,773,888"},
	{"one second early (floor of a negative)", 1000, 29999, -1, -19, -1, 65517, 131046, "16,780,544"},
	{"a quarter half-life late", 1000, 30900, 900, 16384, 0, 16384, 77938, "14,107,516"},
	{"half a half-life late", 1000, 31800, 1800, 32768, 0, 32768, 92674, "11,864,294"},
	{"half a half-life early", 1000, 28200, -1800, -32768, -1, 32768, 92674, "23,728,588"},
	{"one half-life late", 1000, 33600, 3600, 65536, 1, 0, 65536, "8,388,608"},
	{"one half-life early", 1000, 26400, -3600, -65536, -1, 0, 65536, "33,554,432"},
	{"two half-lives late", 1000, 37200, 7200, 131072, 2, 0, 65536, "4,194,304"},
	{"three half-lives early", 1000, 19200, -10800, -196608, -3, 0, 65536, "134,217,728"},
	{"odd lag, late", 123456, 3704457, 777, 14144, 0, 14144, 76115, "14,445,400"},
	{"odd lag, early", 123456, 3701179, -2501, -45530, -1, 20006, 80978, "27,155,810"},
	{"24 hours late: clamps to the minimum difficulty", 1000, 116400, 86400, 1572864, 24, 0, 65536, "131,072"},
	{"48 hours early", 10000, 127200, -172800, -3145728, -48, 0, 65536, "4,722,366,482,869,645,213,696"},
	{"lag so large the shift overflows", 1000, 10030000, 10000000, 182044444, 2777, 50972, 112370, "131,072"},
	{"lag so negative the target reaches 1", 1000000, 20000000, -10000000, -182044445, -2778, 14563, 76453,
		"115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,935"},
}

func TestASERTVectors(t *testing.T) {
	p := Launch30s()
	for _, v := range asertVectors {
		t.Run(v.name, func(t *testing.T) {
			ts := asertGenesis + v.sinceGen
			if lag := int64(v.sinceGen) - int64(p.BlockTime*v.height); lag != v.lag {
				t.Fatalf("vector lag %d, table says %d", lag, v.lag)
			}
			s := p.asert(asertGenesis, v.height, ts)
			for _, c := range []struct {
				col  string
				got  *big.Int
				want int64
			}{
				{"exponent", s.exponent, v.exponent},
				{"shifts", s.shifts, v.shifts},
				{"frac", s.frac, v.frac},
				{"factor", s.factor, v.factor},
			} {
				if c.got.Cmp(big.NewInt(c.want)) != 0 {
					t.Errorf("%s = %v, want %d", c.col, c.got, c.want)
				}
			}
			want := decimal(t, v.difficulty)
			if got := p.RequiredDifficulty(asertGenesis, v.height, ts); got.Cmp(want) != 0 {
				t.Errorf("difficulty = %v, want %v", got, want)
			}
		})
	}
}

func TestASERTAnchorConstants(t *testing.T) {
	p := Launch30s()
	// T_START and MAX_TARGET as printed in spec section 4.6.
	wantStart, _ := new(big.Int).SetString("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	wantMax, _ := new(big.Int).SetString("00007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	if got := SealTarget(p.StartDifficulty); got.Cmp(wantStart) != 0 {
		t.Errorf("T_START = %x, want %x", got, wantStart)
	}
	if got := SealTarget(p.MinDifficulty); got.Cmp(wantMax) != 0 {
		t.Errorf("MAX_TARGET = %x, want %x", got, wantMax)
	}
	if p.StartDifficulty.Cmp(decimal(t, "16,777,216")) != 0 || p.MinDifficulty.Cmp(decimal(t, "131,072")) != 0 {
		t.Errorf("D_START, D_MIN = %v, %v", p.StartDifficulty, p.MinDifficulty)
	}
}

func TestASERTHeightZero(t *testing.T) {
	for _, p := range []Params{Launch30s(), Launch60s()} {
		// Far from schedule on purpose: height 0 ignores the timestamp.
		got := p.RequiredDifficulty(asertGenesis, 0, asertGenesis+100_000)
		if got.Cmp(p.StartDifficulty) != 0 {
			t.Errorf("block time %d: height 0 difficulty %v, want %v", p.BlockTime, got, p.StartDifficulty)
		}
		got.SetUint64(1)
		if p.StartDifficulty.Uint64() == 1 {
			t.Fatal("RequiredDifficulty returned the parameter itself")
		}
	}
}

func TestASERTFloorSemantics(t *testing.T) {
	p := Launch30s()
	// One second early: lag -1, so (-1 * 65536) // 3600 is -19 by floor
	// division, where truncation toward zero would give -18.
	s := p.asert(asertGenesis, 1000, asertGenesis+29999)
	if s.exponent.Cmp(big.NewInt(-19)) != 0 {
		t.Fatalf("exponent = %v, want -19", s.exponent)
	}
	if s.shifts.Cmp(big.NewInt(-1)) != 0 || s.frac.Cmp(big.NewInt(65517)) != 0 {
		t.Fatalf("shifts, frac = %v, %v; want -1, 65517", s.shifts, s.frac)
	}
	if want := decimal(t, "16,780,544"); s.difficulty.Cmp(want) != 0 {
		t.Fatalf("difficulty = %v, want %v", s.difficulty, want)
	}
}

func TestParamsValidate(t *testing.T) {
	for _, p := range []Params{Launch30s(), Launch60s()} {
		if err := p.Validate(); err != nil {
			t.Errorf("preset with block time %d: %v", p.BlockTime, err)
		}
	}
	tests := []struct {
		name   string
		mutate func(*Params)
		want   error
	}{
		{"zero block time", func(p *Params) { p.BlockTime = 0 }, errZeroBlockTime},
		{"block time over the emission half-life", func(p *Params) { p.BlockTime = EmissionHalfLife + 1 }, errLongBlockTime},
		{"zero half-life", func(p *Params) { p.HalfLife = 0 }, errZeroHalfLife},
		{"zero minimum difficulty", func(p *Params) { p.MinDifficulty = new(big.Int) }, errBadMinDifficulty},
		{"missing minimum difficulty", func(p *Params) { p.MinDifficulty = nil }, errBadMinDifficulty},
		{"start below minimum", func(p *Params) { p.StartDifficulty = big.NewInt(1<<17 - 1) }, errBadStartDifficulty},
		{"missing start", func(p *Params) { p.StartDifficulty = nil }, errBadStartDifficulty},
		{"missing tail", func(p *Params) { p.TailReward = nil }, errMissingReward},
	}
	for _, tt := range tests {
		p := Launch30s()
		tt.mutate(&p)
		if err := p.Validate(); !errors.Is(err, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, err, tt.want)
		}
	}
	// A starting difficulty equal to the minimum is allowed.
	p := Launch30s()
	p.StartDifficulty = big.NewInt(1 << 17)
	if err := p.Validate(); err != nil {
		t.Errorf("start equal to minimum: %v", err)
	}
}

func TestTimestampRule(t *testing.T) {
	p := Launch30s()
	const (
		parent = uint64(1_700_000_000)
		now    = parent + 100
	)
	tests := []struct {
		name   string
		parent uint64
		time   uint64
		now    uint64
		want   error
	}{
		{"equal to parent", parent, parent, now, ErrTimestampNotAfterParent},
		{"before parent", parent, parent - 1, now, ErrTimestampNotAfterParent},
		{"one second after parent", parent, parent + 1, now, nil},
		{"at now + drift", parent, now + 30, now, nil},
		{"at now + drift + 1", parent, now + 31, now, ErrTimestampTooFarAhead},
		{"2^63", parent, 1 << 63, 1<<63 + 100, ErrTimestampOverflow},
		{"2^63 - 1", parent, 1<<63 - 1, 1 << 63, nil},
		{"not after parent and too far ahead", now + 100, now + 100, now, ErrTimestampNotAfterParent},
		{"now near the top of uint64", parent, parent + 1, ^uint64(0), nil},
	}
	for _, tt := range tests {
		if err := p.CheckTimestamp(tt.parent, tt.time, tt.now); err != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, err, tt.want)
		}
	}
	if ErrTimestampNotAfterParent == ErrTimestampTooFarAhead || ErrTimestampTooFarAhead == ErrTimestampOverflow ||
		ErrTimestampNotAfterParent == ErrTimestampOverflow {
		t.Fatal("timestamp errors are not distinct")
	}
}

// rewardVectors is the reward table of spec section 6.6, in wei.
var rewardVectors = []struct {
	blockTime uint64
	height    uint64
	wei       string
}{
	{30, 1, "6,923,560,000,000,000,000"},
	{30, 2, "6,923,557,717,349,076,136"},
	{30, 1_051_200, "4,895,697,840,030,412,474"},
	{30, 1_051_201, "4,895,696,225,951,932,978"},
	{30, 2_102_400, "3,461,781,141,325,838,219"},
	{30, 2_102_401, "3,461,780,000,000,000,000"},
	{30, 4_204_801, "1,730,890,000,000,000,000"},
	{30, 8_409_601, "432,722,500,000,000,000"},
	{30, 10_512_001, "216,361,250,000,000,000"},
	{30, 10_750_501, "200,000,049,462,428,603"},
	{30, 10_750_502, "200,000,000,000,000,000"},
	{30, 1_000_000_000, "200,000,000,000,000,000"},
	{60, 1, "13,847,120,000,000,000,000"},
	{60, 2, "13,847,110,869,397,809,694"},
	{60, 525_600, "9,791,398,908,218,848,244"},
	{60, 525_601, "9,791,392,451,903,865,956"},
	{60, 1_051_200, "6,923,564,565,304,105,452"},
	{60, 1_051_201, "6,923,560,000,000,000,000"},
	{60, 2_102_401, "3,461,780,000,000,000,000"},
	{60, 4_204_801, "865,445,000,000,000,000"},
	{60, 5_256_001, "432,722,500,000,000,000"},
	{60, 5_375_251, "400,000,098,924,857,207"},
	{60, 5_375_252, "400,000,000,000,000,000"},
	{60, 1_000_000_000, "400,000,000,000,000,000"},
}

func presetFor(t *testing.T, blockTime uint64) Params {
	t.Helper()
	switch blockTime {
	case 30:
		return Launch30s()
	case 60:
		return Launch60s()
	}
	t.Fatalf("no preset for block time %d", blockTime)
	return Params{}
}

func TestRewardVectors(t *testing.T) {
	for _, v := range rewardVectors {
		p := presetFor(t, v.blockTime)
		want := decimal(t, v.wei)
		if got := p.BlockReward(v.height).ToBig(); got.Cmp(want) != 0 {
			t.Errorf("%d s, height %d: reward %v, want %v", v.blockTime, v.height, got, want)
		}
	}
	for _, p := range []Params{Launch30s(), Launch60s()} {
		if got := p.BlockReward(0); !got.IsZero() {
			t.Errorf("%d s: height 0 pays %v", p.BlockTime, got)
		}
		// The largest height must not wrap q past its cap.
		if got := p.BlockReward(^uint64(0)); !got.Eq(p.TailReward) {
			t.Errorf("%d s: max height pays %v", p.BlockTime, got)
		}
	}
}

func TestRewardYearTotals(t *testing.T) {
	// Spec section 6.6: cumulative issuance at the end of the first
	// scheduled years, in GHOST with two decimals. The spec's script cuts
	// the exact wei sum to hundredths rather than rounding it (year 1 at
	// 30 s sums to 6,150,759.3494... and is printed 6,150,759.34), so the
	// sum must lie in [printed, printed + 0.01 GHOST): within 0.005 GHOST
	// of the midpoint of that hundredth, in integer wei.
	checkpoints := []struct {
		blockTime uint64
		height    uint64
		ghost     string
	}{
		{30, 1_051_200, "6,150,759.34"},
		{30, 2_102_400, "10,500,002.99"},
		{60, 525_600, "6,150,760.36"},
	}
	hundredth := uint256.NewInt(10_000_000_000_000_000) // 0.01 GHOST in wei
	sums := map[uint64]*uint256.Int{}
	next := map[uint64]uint64{}
	for _, c := range checkpoints {
		p := presetFor(t, c.blockTime)
		sum, ok := sums[c.blockTime]
		if !ok {
			sum = new(uint256.Int)
			sums[c.blockTime] = sum
			next[c.blockTime] = 1
		}
		for h := next[c.blockTime]; h <= c.height; h++ {
			sum.Add(sum, p.BlockReward(h))
		}
		next[c.blockTime] = c.height + 1

		// "6,150,759.34" GHOST is 615075934 hundredths of a GHOST.
		cents, overflow := uint256.FromBig(decimal(t, strings.ReplaceAll(c.ghost, ".", "")))
		if overflow {
			t.Fatal("expected total overflows")
		}
		low := new(uint256.Int).Mul(cents, hundredth)
		high := new(uint256.Int).Add(low, hundredth)
		if sum.Lt(low) || !sum.Lt(high) {
			t.Errorf("%d s: heights 1..%d sum to %v wei, want [%v, %v)", c.blockTime, c.height, sum, low, high)
		}
	}
}

func TestRewardNonIncreasingAroundTail(t *testing.T) {
	for _, c := range []struct {
		blockTime uint64
		tailStart uint64
	}{
		{30, 10_750_502},
		{60, 5_375_252},
	} {
		p := presetFor(t, c.blockTime)
		if got := p.BlockReward(c.tailStart); !got.Eq(p.TailReward) {
			t.Errorf("%d s: reward at tail start %d is %v, want the tail", c.blockTime, c.tailStart, got)
		}
		if got := p.BlockReward(c.tailStart - 1); !got.Gt(p.TailReward) {
			t.Errorf("%d s: reward before tail start is %v, want above the tail", c.blockTime, got)
		}
		prev := p.BlockReward(c.tailStart - 3000)
		for h := c.tailStart - 2999; h <= c.tailStart+3000; h++ {
			cur := p.BlockReward(h)
			if cur.Gt(prev) {
				t.Fatalf("%d s: reward rises at height %d: %v > %v", c.blockTime, h, cur, prev)
			}
			if cur.Lt(p.TailReward) {
				t.Fatalf("%d s: reward below tail at height %d: %v", c.blockTime, h, cur)
			}
			prev = cur
		}
	}
}

func TestSealTarget(t *testing.T) {
	var maxHash, half, halfPlus [32]byte
	for i := range maxHash {
		maxHash[i] = 0xff
		half[i] = 0xff
	}
	half[0] = 0x7f
	halfPlus[0] = 0x80

	if !SealValid(maxHash, big.NewInt(1)) {
		t.Error("difficulty 1 rejects the maximum hash")
	}
	if !SealValid(half, big.NewInt(2)) {
		t.Error("difficulty 2 rejects 0x7fff...ff")
	}
	if SealValid(halfPlus, big.NewInt(2)) {
		t.Error("difficulty 2 accepts 0x8000...00")
	}
	if SealValid(maxHash, big.NewInt(2)) {
		t.Error("difficulty 2 accepts the maximum hash")
	}
	if want := new(big.Int).SetBytes(half[:]); SealTarget(big.NewInt(2)).Cmp(want) != 0 {
		t.Errorf("SealTarget(2) = %x, want %x", SealTarget(big.NewInt(2)), want)
	}
	for _, d := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if SealTarget(d) != nil || SealValid([32]byte{}, d) {
			t.Errorf("difficulty %v is accepted", d)
		}
	}
}
