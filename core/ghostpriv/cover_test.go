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

package ghostpriv_test

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// coverLimit is the largest base fee of an including block whose burn the
// fee pays, floor(fee / G_PRIV).
func coverLimit(fee ghostpriv.Fee) *big.Int {
	return new(big.Int).Div(fee.Total.ToBig(), new(big.Int).SetUint64(ghostpriv.GasPriv))
}

// TestCoverRuleKnownAnswers checks the split of spec 07, sections 4 and 5:
// the cover limit of the genesis window, the tip below and above the price,
// and the lapse examples of a fee of the previous window.
func TestCoverRuleKnownAnswers(t *testing.T) {
	fee, err := ghostpriv.WindowFee(big.NewInt(1_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	if got := coverLimit(fee); got.String() != "1237555001" {
		t.Fatalf("cover limit %v, want 1237555001", got)
	}
	for _, tt := range []struct {
		beta int64
		tip  string // "" for a rejected reveal
	}{
		{1_000_000_000, "2372772303969038"},
		{1_125_050_001, "2372772303969038"},
		{1_150_000_000, "1846567543659410"},
		{1_160_117_665, "1633182225038030"},
		{1_237_555_001, "2109038"},
		{1_237_555_002, ""},
		{1_250_000_000, ""},
	} {
		split, err := fee.Cover(big.NewInt(tt.beta))
		if tt.tip == "" {
			if !errors.Is(err, ghostpriv.ErrRevealCover) {
				t.Errorf("base fee %d: %v, want the cover rule to fail", tt.beta, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("base fee %d: %v", tt.beta, err)
		}
		if split.Tip.Dec() != tt.tip {
			t.Errorf("base fee %d: tip %v, want %s", tt.beta, split.Tip, tt.tip)
		}
		if new(uint256.Int).Add(split.Burn, split.Tip).Cmp(fee.Total) != 0 {
			t.Errorf("base fee %d: burn %v + tip %v is not the fee %v", tt.beta, split.Burn, split.Tip, fee.Total)
		}
	}
	if _, err := fee.Cover(nil); !errors.Is(err, ghostpriv.ErrBaseFee) {
		t.Errorf("no base fee: %v", err)
	}
}

// TestRevealCoverLimit checks the cover rule in the reveal checks, before
// the proof: an including block whose base fee is exactly the cover limit
// accepts the reveal and one wei above refuses it, for a fee of the
// block's own window and for one of the window before; and the apply step
// pays the finder the fee less the burn, never more than the nominal tip.
func TestRevealCoverLimit(t *testing.T) {
	useStub(t)
	s := newScenario(t, 11)
	miner := common.Address{0xcb, 0xc}
	feeOf := func(bRef *big.Int) ghostpriv.Fee {
		fee, err := ghostpriv.WindowFee(bRef)
		if err != nil {
			t.Fatal(err)
		}
		return fee
	}
	var (
		fee4 = feeOf(s.blocks[3].BaseFee())
		fee8 = feeOf(s.blocks[7].BaseFee())
	)
	if fee4.Total.Eq(fee8.Total) {
		t.Fatal("windows 4 and 8 have the same fee")
	}
	// at is the environment of the block at height n, on block n-1, with
	// the base fee beta.
	at := func(n int, beta *big.Int) (*ghostpriv.BlockEnv, func(*uint256.Int) (ghostpriv.Fee, error)) {
		env, st := nextEnv(t, s.chain, s.blocks[n-2].Header(), miner)
		env.Header.BaseFee = beta
		return env, func(fee *uint256.Int) (ghostpriv.Fee, error) {
			_, paid, err := ghostpriv.CheckReveal(st.Copy(), env, rejectProof{}, envelope(t, s.reveal(t, "cover", u256(ghostAmount(1, 10)), fee)))
			return paid, err
		}
	}
	for _, tt := range []struct {
		name string
		n    int
		fee  ghostpriv.Fee
	}{
		{"own window", 7, fee4},
		{"previous window", 10, fee4},
		{"own window after a change", 10, fee8},
	} {
		limit := coverLimit(tt.fee)
		_, check := at(tt.n, limit)
		_, err := check(tt.fee.Total)
		if !errors.Is(err, ghostpriv.ErrRevealProof) {
			t.Fatalf("%s at the cover limit: %v, want only the proof to fail", tt.name, err)
		}
		_, check = at(tt.n, new(big.Int).Add(limit, common.Big1))
		if _, err := check(tt.fee.Total); !errors.Is(err, ghostpriv.ErrRevealFee) || !errors.Is(err, ghostpriv.ErrRevealCover) {
			t.Errorf("%s one wei above the cover limit: %v", tt.name, err)
		}
		_, check = at(tt.n, nil)
		if _, err := check(tt.fee.Total); !errors.Is(err, ghostpriv.ErrRevealFee) {
			t.Errorf("%s with no base fee: %v", tt.name, err)
		}
	}

	// Applied above the price, the finder gets the fee less G_PRIV times
	// the block's base fee, less than the nominal tip.
	beta := new(big.Int).Add(fee4.Price.ToBig(), big.NewInt(1_000_000))
	env, st := nextEnv(t, s.chain, s.blocks[8].Header(), miner)
	env.Header.BaseFee = beta
	before := st.GetBalance(miner).Clone()
	if err := ghostpriv.ApplyReveal(st, env, stub, envelope(t, s.reveal(t, "cover", u256(ghostAmount(1, 10)), fee4.Total))); err != nil {
		t.Fatalf("block 10 at window 4's fee above its price: %v", err)
	}
	got := new(uint256.Int).Sub(st.GetBalance(miner), before)
	want := new(big.Int).Sub(fee4.Total.ToBig(), new(big.Int).Mul(beta, new(big.Int).SetUint64(ghostpriv.GasPriv)))
	if got.ToBig().Cmp(want) != 0 || !got.Lt(fee4.Tip) {
		t.Errorf("coinbase got %v, want %v below the nominal tip %v", got, want, fee4.Tip)
	}
}

// rejectProof refuses every proof, so a check that reaches the proof shows
// that every check before it passed.
type rejectProof struct{}

func (rejectProof) VerifyReveal(*ghostpriv.VerifyInputs, []byte) error {
	return errors.New("no proof")
}

// TestCoverRuleBurnsBaseFee checks the guarantee of the cover rule over
// random gas limits from MIN_GAS_LIMIT with every block full, the fastest
// the base fee can rise: every reveal accepted in its window or the next
// burns at least G_PRIV times the block's base fee and pays at most the
// nominal tip, and blocks 0 and 1 of the window accept it at any load.
func TestCoverRuleBurnsBaseFee(t *testing.T) {
	s := newScenario(t, 1)
	config := s.chain.Config()
	rng := rand.New(rand.NewSource(20261025))
	g := new(big.Int).SetUint64(ghostpriv.GasPriv)
	accepted := 0
	for trial := 0; trial < 2000; trial++ {
		bRef := new(big.Int).Rand(rng, big.NewInt(1_000_000_000_000))
		fee, err := ghostpriv.WindowFee(bRef)
		if err != nil {
			t.Fatal(err)
		}
		beta := new(big.Int).Set(bRef)
		for j := 0; j < 8; j++ {
			split, err := fee.Cover(beta)
			switch {
			case err != nil && j < 2:
				t.Fatalf("b_ref %v, block %d, base fee %v: %v", bRef, j, beta, err)
			case err != nil:
				if !errors.Is(err, ghostpriv.ErrRevealCover) {
					t.Fatalf("b_ref %v, block %d: %v", bRef, j, err)
				}
			default:
				accepted++
				if split.Burn.ToBig().Cmp(new(big.Int).Mul(g, beta)) < 0 {
					t.Fatalf("b_ref %v, block %d: burn %v below G_PRIV times base fee %v", bRef, j, split.Burn, beta)
				}
				if split.Tip.Gt(fee.Tip) {
					t.Fatalf("b_ref %v, block %d: tip %v above the nominal %v", bRef, j, split.Tip, fee.Tip)
				}
			}
			limit := vars.MinGasLimit + uint64(rng.Int63n(60_000_000))
			parent := &types.Header{Number: big.NewInt(int64(j + 1)), GasLimit: limit, GasUsed: limit, BaseFee: beta}
			beta = eip1559.CalcBaseFee(config, parent)
		}
	}
	if accepted == 0 {
		t.Fatal("no reveal was accepted")
	}
}
