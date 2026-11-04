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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// TestPolicyRevealBlockGas checks RP-24: each reveal type takes exactly its
// own gas from the block gas pool, G_PRIV for the ordinary reveal, G_POLICY
// for the policy reveal and G_DATA for the data reveal, in its receipt and
// the block's gas used. A block whose gas limit is the sum of the three
// takes all three; one gas less and the block carrying them is invalid. The
// data reveal still takes 21,090,372 and pays the window fee priced for that
// gas, within DATA_RESERVE; the window fee of the ordinary class is no data
// reveal's fee. Each class's tip goes to the coinbase.
func TestPolicyRevealBlockGas(t *testing.T) {
	useStub(t)
	if ghostpriv.GasPriv != 21_371_656 || ghostpriv.GasPolicy != 21_604_216 || ghostpriv.GasData != 21_090_372 {
		t.Fatalf("G_PRIV %d, G_POLICY %d, G_DATA %d", ghostpriv.GasPriv, ghostpriv.GasPolicy, ghostpriv.GasData)
	}
	if ghostpriv.GasPolicy-ghostpriv.GasPriv != 16*(types.GhostPolicyRevealEnvelopeSize-types.GhostRevealEnvelopeSize)+(440_000-370_000)+ghostpriv.SlotOpenGas {
		t.Fatal("G_POLICY is not G_PRIV with the policy fields, its larger verification charge and the slot opening")
	}
	all := uint64(ghostpriv.GasPriv + ghostpriv.GasPolicy + ghostpriv.GasData)
	var (
		coinA    = testCoin("gas ordinary", oneGhost)
		coinB    = testCoin("gas policy", oneGhost)
		file     = testDataFile("gas data")
		miner    = common.Address{0xcb, 0x24}
		verifier = common.Address{0x7e, 0x24}
		out      = u256(ghostAmount(1, 5))
	)
	type fees struct{ priv, policy, data ghostpriv.Fee }
	build := func(gasLimit uint64) (*fixture, []*types.Block, fees, []*types.Transaction) {
		f := newFixture(t, gasLimit, policyAlloc())
		var (
			paid fees
			txs  []*types.Transaction
		)
		blocks, _ := f.generate(3, func(i int, b *core.BlockGen) {
			switch i {
			case 0:
				b.AddTx(f.commitTx(keyA, 0, coinA))
				b.AddTx(f.commitTx(keyB, 0, coinB))
				b.AddTx(f.dataCommitTx(keyC, 0, file, reserve()))
			case 2:
				b.SetCoinbase(miner)
				paid = fees{
					priv:   genWindowFeeGas(t, b, ghostpriv.GasPriv),
					policy: genWindowFeeGas(t, b, ghostpriv.GasPolicy),
					data:   genWindowFeeGas(t, b, ghostpriv.GasData),
				}
				root := genParentRoot(b)
				rest := new(uint256.Int).Sub(coinA.value, new(uint256.Int).Add(out, paid.priv.Total))
				txs = []*types.Transaction{
					revealTx(t, f.newReveal(root, testMarker("gas ordinary"), testCoin("gas rest", rest.ToBig()), addrB, out, paid.priv.Total)),
					policyRevealTx(t, f.newPolicyReveal(root, testMarker("gas policy"), testPolicy, testPolicyHash, out, paid.policy.Total)),
					dataRevealTx(t, f.newDataReveal(genParentDataRoot(b), testDataMarker("gas data"), ghostpriv.PurposeReveal, verifier, paid.data.Total)),
				}
				b.AddTx(txs[0])
				b.AddTx(txs[1])
				if b.Gas() >= txs[2].Gas() {
					b.AddTx(txs[2])
				} else {
					b.AddUncheckedTx(txs[2])
				}
			}
		})
		return f, blocks, paid, txs
	}

	f, blocks, paid, txs := build(all)
	for k, want := range []uint64{ghostpriv.GasPriv, ghostpriv.GasPolicy, ghostpriv.GasData} {
		if txs[k].Gas() != want {
			t.Fatalf("transaction %d of type %#x has gas %d, want %d", k, txs[k].Type(), txs[k].Gas(), want)
		}
	}
	// The data reveal's fee is the window fee for G_DATA, within the reserve,
	// and not the ordinary class's.
	if paid.data.Total.Gt(ghostpriv.DataReserve) {
		t.Fatalf("data reveal fee %v above the reserve", paid.data.Total)
	}
	if want := new(uint256.Int).Mul(uint256.NewInt(21_090_372), paid.data.Price); !paid.data.BasePart.Eq(want) {
		t.Fatalf("data reveal base part %v, want 21,090,372 times the price %v", paid.data.BasePart, want)
	}
	if paid.data.Total.Eq(paid.priv.Total) || paid.policy.Total.Eq(paid.priv.Total) {
		t.Fatal("the classes share a window fee")
	}
	chain := f.newChain()
	f.insert(chain, blocks)
	block := chain.GetBlockByNumber(3)
	if block.GasUsed() != all || block.GasLimit() != all {
		t.Fatalf("block gas used %d of %d, want %d", block.GasUsed(), block.GasLimit(), all)
	}
	receipts := chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 3 {
		t.Fatalf("%d receipts", len(receipts))
	}
	var cumulative uint64
	for k, want := range []struct {
		typ byte
		gas uint64
	}{
		{types.GhostRevealTxType, ghostpriv.GasPriv},
		{types.GhostPolicyRevealTxType, ghostpriv.GasPolicy},
		{types.GhostDataRevealTxType, ghostpriv.GasData},
	} {
		cumulative += want.gas
		r := receipts[k]
		if r.Type != want.typ || r.Status != types.ReceiptStatusSuccessful || r.GasUsed != want.gas || r.CumulativeGasUsed != cumulative || r.TxHash != txs[k].Hash() {
			t.Errorf("receipt %d: type %#x gas %d cumulative %d, want %#x, %d and %d", k, r.Type, r.GasUsed, r.CumulativeGasUsed, want.typ, want.gas, cumulative)
		}
	}
	// The coinbase gains the reward and each class's tip, split by the
	// cover rule for the class's own gas.
	st, err := chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	wantMiner := new(uint256.Int).Set(f.engine.params.BlockReward(3))
	for _, c := range []struct {
		fee ghostpriv.Fee
		gas uint64
	}{{paid.priv, ghostpriv.GasPriv}, {paid.policy, ghostpriv.GasPolicy}, {paid.data, ghostpriv.GasData}} {
		split, err := c.fee.CoverGas(block.BaseFee(), c.gas)
		if err != nil {
			t.Fatal(err)
		}
		wantMiner.Add(wantMiner, split.Tip)
	}
	if got := st.GetBalance(miner); !got.Eq(wantMiner) {
		t.Errorf("coinbase %v, want the reward and three tips %v", got, wantMiner)
	}
	if escrow := ghostpriv.TotalEscrow(st); !escrow.Eq(out) {
		t.Errorf("total escrow %v, want %v", escrow, out)
	}

	// A data reveal paying the ordinary class's window fee is refused.
	env, stHead := nextEnv(t, chain, chain.GetBlockByNumber(2).Header(), miner)
	wrong := f.newDataReveal(*blocks[0].Header().DataTreeRoot, testDataMarker("gas data"), ghostpriv.PurposeReveal, verifier, paid.priv.Total)
	if _, _, err := ghostpriv.CheckDataReveal(stHead, env, stub, dataEnvelope(t, wrong)); !errors.Is(err, ghostpriv.ErrDataRevealFee) {
		t.Errorf("data reveal at the ordinary class's fee: %v, want %v", err, ghostpriv.ErrDataRevealFee)
	}

	// One gas less: the block carrying the three is invalid.
	f2, short, _, _ := build(all - 1)
	if len(short[2].Transactions()) != 3 {
		t.Fatal("the short block does not carry the three reveals")
	}
	chain2 := f2.newChain()
	f2.insert(chain2, short[:2])
	if _, err := chain2.InsertChain(short[2:]); !errors.Is(err, core.ErrGasLimitReached) {
		t.Fatalf("block of the three reveals one gas short: %v, want %v", err, core.ErrGasLimitReached)
	}
	if chain2.CurrentBlock().Hash() != short[1].Hash() {
		t.Fatal("the head moved")
	}
}

// policyChainSnapshot reads what a policy reveal and its block change: the
// slot's words, the marker, the totals with total_escrow, the coin tree's
// slots, the nonces of the native accounts and the balances of addrs.
func policyChainSnapshot(t *testing.T, chain *core.BlockChain, root common.Hash, marker common.Hash, addrs []common.Address) map[string]string {
	t.Helper()
	st, err := chain.StateAt(root)
	if err != nil {
		t.Fatal(err)
	}
	snap := accountsSnapshot(t, chain, root, addrs, []common.Hash{marker})
	for i, w := range slotWords(st, marker) {
		snap["slot word "+big.NewInt(int64(i)).String()] = w.Hex()
	}
	snap["total escrow"] = ghostpriv.TotalEscrow(st).String()
	snap["nonce escrow account"] = big.NewInt(int64(st.GetNonce(ghost.EscrowAccount))).String()
	snap["coin leaves"] = big.NewInt(int64(coinLeafCount(st))).String()
	return snap
}

// TestPolicyRevealReorg imports a branch whose block 5 carries a policy
// reveal that opens a slot, then a heavier branch without it: the node ends
// with exactly the state of a node that only saw the heavier branch, the
// slot gone, the marker unspent, total_escrow and the other totals and the
// coin tree rewound, and the policy reveal can then be included on the new
// branch.
func TestPolicyRevealReorg(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, policyAlloc())
	var (
		c      = testCoin("policy reorg", oneGhost)
		marker = testMarker("policy reorg")
		minerA = common.Address{0xa0, 0x53}
		minerB = common.Address{0xb0, 0x53}
		out    = u256(ghostAmount(2, 5))
	)
	reveal := func(b *core.BlockGen) {
		fee := genWindowFeeGas(t, b, ghostpriv.GasPolicy).Total
		b.AddTx(policyRevealTx(t, f.newPolicyReveal(genParentRoot(b), marker, testPolicy, testPolicyHash, out, fee)))
	}
	branch := func(n int, revealAt int) []*types.Block {
		blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
			switch {
			case i == 0:
				b.AddTx(f.commitTx(keyA, 0, c))
			case i >= 4 && revealAt == 4:
				b.SetCoinbase(minerA)
				if i == revealAt {
					reveal(b)
				}
			case i >= 4:
				b.SetCoinbase(minerB)
				if i == revealAt {
					reveal(b)
				}
			}
		})
		return blocks
	}
	a := branch(5, 4)  // the policy reveal in block 5
	b := branch(7, -1) // blocks 5 to 7 without it
	if a[3].Hash() != b[3].Hash() || a[4].Hash() == b[4].Hash() {
		t.Fatal("the branches do not fork after block 4")
	}
	addrs := []common.Address{addrA, minerA, minerB, testPolicy, ghost.EscrowAccount}

	reorged := f.newChain()
	f.insert(reorged, a)
	st, err := reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	slot, ok := ghostpriv.ReadEscrowSlot(st, marker)
	if !ok || !slot.Open || !slot.Remaining.Eq(out) || !ghosttree.IsSpent(st, ghosttree.Coin, marker) || !ghostpriv.TotalEscrow(st).Eq(out) {
		t.Fatal("branch A did not open the slot")
	}
	if receipts := reorged.GetReceiptsByHash(a[4].Hash()); len(receipts) != 1 || receipts[0].Type != types.GhostPolicyRevealTxType || receipts[0].GasUsed != ghostpriv.GasPolicy {
		t.Fatal("branch A's block 5 has no policy reveal receipt")
	}
	atFork := policyChainSnapshot(t, reorged, a[3].Root(), marker, addrs)
	if len(diffMaps(atFork, policyChainSnapshot(t, reorged, a[4].Root(), marker, addrs))) == 0 {
		t.Fatal("the policy reveal changed nothing")
	}

	f.insert(reorged, b)
	if reorged.CurrentBlock().Hash() != b[6].Hash() {
		t.Fatal("the node did not reorganise to branch B")
	}
	onlyB := f.newChain()
	f.insert(onlyB, b)
	after := policyChainSnapshot(t, reorged, reorged.CurrentBlock().Root, marker, addrs)
	for _, d := range diffMaps(after, policyChainSnapshot(t, onlyB, onlyB.CurrentBlock().Root, marker, addrs)) {
		t.Errorf("against the node that saw only B: %s", d)
	}
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ghostpriv.ReadEscrowSlot(st, marker); ok || ghosttree.IsSpent(st, ghosttree.Coin, marker) {
		t.Fatal("the slot or the marker survived the reorganisation")
	}
	if _, o := totals(st); o.Sign() != 0 || !ghostpriv.TotalEscrow(st).IsZero() {
		t.Fatalf("total out %v, total escrow %v after the reorganisation", o, ghostpriv.TotalEscrow(st))
	}
	if n := coinLeafCount(st); n != 1 {
		t.Fatalf("coin tree has %d leaves after the reorganisation, want the commitment only", n)
	}

	// The coin is still there to spend into the slot on branch B.
	longer := branch(8, 7)
	if longer[6].Hash() != b[6].Hash() {
		t.Fatal("branch B did not rebuild identically")
	}
	f.insert(reorged, longer[7:])
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if slot, ok := ghostpriv.ReadEscrowSlot(st, marker); !ok || !slot.Remaining.Eq(out) || slot.Height != 8 || !ghostpriv.TotalEscrow(st).Eq(out) {
		t.Fatal("the policy reveal did not apply on branch B")
	}
}
