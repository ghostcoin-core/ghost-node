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
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// invariantSeedEnv overrides the seed of the randomized invariant run.
const (
	invariantSeedEnv     = "GHOST_INVARIANT_SEED"
	invariantDefaultSeed = 20261018
	invariantBlocks      = 32
)

// liveCoin is a coin of the run's wallet with the first block that may
// reveal it: the one after the block that appended it.
type liveCoin struct {
	coin
	from uint64
}

// TestAccountingInvariantRandomized builds a chain on the internal network
// from a seeded random mix of transfers, commits and reveals, imports it,
// and after every block checks that the public balances plus the hidden
// total equal what was issued minus what was burned: the base fee times the
// gas of every ordinary transaction and the base part of every reveal. It
// also checks the hidden total against the wallet's own unspent coins.
func TestAccountingInvariantRandomized(t *testing.T) {
	seed := int64(invariantDefaultSeed)
	if s := os.Getenv(invariantSeedEnv); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q: %v", invariantSeedEnv, s, err)
		}
		seed = v
	}
	fmt.Printf("TestAccountingInvariantRandomized: seed %d (%s to change)\n", seed, invariantSeedEnv)
	t.Logf("seed %d (%s to change)", seed, invariantSeedEnv)
	rng := rand.New(rand.NewSource(seed))

	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	var (
		keys      = []*ecdsa.PrivateKey{keyA, keyB, keyC}
		senders   = []common.Address{addrA, addrB, addrC}
		coinbases = []common.Address{{0xcb, 1}, {0xcb, 2}, {0xcb, 3}}
		tracked   = map[common.Address]bool{}
		coins     []liveCoin
		hiddenAt  = map[uint64]*big.Int{0: new(big.Int)}
		reveals   int
		commits   int
		nonce     = map[common.Address]uint64{}
	)
	for _, a := range append(append([]common.Address{}, senders...), coinbases...) {
		tracked[a] = true
	}
	for _, a := range []common.Address{
		ghost.CommitEntryAddress, ghost.PrivTotalsAccount, {},
		ghosttree.TreeAccount(ghosttree.Coin), ghosttree.TreeAccount(ghosttree.Data),
		ghosttree.MarkerAccount(ghosttree.Coin), ghosttree.MarkerAccount(ghosttree.Data),
	} {
		tracked[a] = true
	}
	randomAmount := func(limit *big.Int) *big.Int {
		return new(big.Int).Add(new(big.Int).Rand(rng, limit), big.NewInt(1))
	}
	hidden := new(big.Int)

	blocks, _ := f.generate(invariantBlocks, func(i int, b *core.BlockGen) {
		h := b.Number().Uint64()
		b.SetCoinbase(coinbases[rng.Intn(len(coinbases))])

		// At most one reveal a block: two would not fit the gas limit.
		var ready []int
		for k, c := range coins {
			if c.from <= h {
				ready = append(ready, k)
			}
		}
		if len(ready) > 0 && rng.Intn(3) > 0 {
			k := ready[rng.Intn(len(ready))]
			c := coins[k]
			fee := genWindowFee(t, b).Total
			if !c.value.Lt(fee) {
				left := new(uint256.Int).Sub(c.value, fee)
				out := new(uint256.Int)
				if !left.IsZero() {
					out = u256(new(big.Int).Rand(rng, new(big.Int).Add(left.ToBig(), common.Big1)))
				}
				restValue := new(uint256.Int).Sub(left, out)
				rest := liveCoin{coin: testCoin(fmt.Sprintf("invariant rest %d", h), restValue.ToBig()), from: h + 1}
				recipient := senders[rng.Intn(len(senders))]
				if rng.Intn(2) == 0 {
					recipient = common.Address{0x9e, byte(h)}
					tracked[recipient] = true
				}
				marker := testMarker(fmt.Sprintf("invariant %d", h))
				b.AddTx(revealTx(t, f.newReveal(genParentRoot(b), marker, rest.coin, recipient, out, fee)))
				coins = append(coins[:k], coins[k+1:]...)
				if !restValue.IsZero() {
					coins = append(coins, rest)
				}
				hidden.Sub(hidden, out.ToBig())
				hidden.Sub(hidden, fee.ToBig())
				reveals++
			}
		}
		// Transfers and commits.
		for n := rng.Intn(5); n > 0; n-- {
			s := rng.Intn(len(keys))
			from := senders[s]
			if rng.Intn(2) == 0 {
				c := testCoin(fmt.Sprintf("invariant commit %d %d", h, n), randomAmount(new(big.Int).Mul(big.NewInt(3), oneGhost)))
				b.AddTx(f.commitTx(keys[s], nonce[from], c))
				coins = append(coins, liveCoin{coin: c, from: h + 1})
				hidden.Add(hidden, c.value.ToBig())
				commits++
			} else {
				to := senders[rng.Intn(len(senders))]
				b.AddTx(f.callTx(keys[s], nonce[from], to, randomAmount(oneGhost), nil, 21_000))
			}
			nonce[from]++
		}
		hiddenAt[h] = new(big.Int).Set(hidden)
	})
	if commits == 0 || reveals == 0 {
		t.Fatalf("seed %d: the run made %d commits and %d reveals", seed, commits, reveals)
	}
	t.Logf("seed %d: %d blocks, %d commits, %d reveals", seed, len(blocks), commits, reveals)

	chain := f.newChain()
	var (
		issued = f.allocTotal()
		burned = new(big.Int)
	)
	check := func(header *types.Header) {
		t.Helper()
		st, err := chain.StateAt(header.Root)
		if err != nil {
			t.Fatal(err)
		}
		public := new(big.Int)
		for a := range tracked {
			public.Add(public, st.GetBalance(a).ToBig())
		}
		hid, err := ghostpriv.Hidden(st)
		if err != nil {
			t.Fatalf("seed %d, block %d: %v", seed, header.Number, err)
		}
		if want := hiddenAt[header.Number.Uint64()]; hid.ToBig().Cmp(want) != 0 {
			t.Fatalf("seed %d, block %d: hidden %v, wallet coins %v", seed, header.Number, hid, want)
		}
		left := new(big.Int).Add(public, hid.ToBig())
		right := new(big.Int).Sub(issued, burned)
		if left.Cmp(right) != 0 {
			t.Fatalf("seed %d, block %d: public %v + hidden %v = %v, issued %v - burned %v = %v",
				seed, header.Number, public, hid, left, issued, burned, right)
		}
		if !st.GetBalance(ghost.CommitEntryAddress).IsZero() || !st.GetBalance(ghost.PrivTotalsAccount).IsZero() {
			t.Fatalf("seed %d, block %d: a reserved account holds a balance", seed, header.Number)
		}
	}
	check(chain.Genesis().Header())
	for _, block := range blocks {
		f.insert(chain, []*types.Block{block})
		h := block.NumberU64()
		issued.Add(issued, f.engine.params.BlockReward(h).ToBig())
		for _, r := range chain.GetReceiptsByHash(block.Hash()) {
			if r.Type == types.GhostRevealTxType {
				bRef := block.BaseFee()
				if start := ghostpriv.WindowStart(h); start != h {
					bRef = chain.GetHeaderByNumber(start).BaseFee
				}
				fee, err := ghostpriv.WindowFee(bRef)
				if err != nil {
					t.Fatal(err)
				}
				burned.Add(burned, fee.BasePart.ToBig())
				continue
			}
			burned.Add(burned, new(big.Int).Mul(block.BaseFee(), new(big.Int).SetUint64(r.GasUsed)))
		}
		check(block.Header())
	}
}
