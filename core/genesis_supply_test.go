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

package core_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The supply test follows the lifecycle tests of core/ghostpriv/lifecycle: a
// core.BlockChain on the internal genesis, blocks built through exported
// interfaces only (core.ApplyTransaction, ghostpriv.ApplyReveal and the
// RandomX engine's Prepare, FinalizeAndAssemble and Seal) and imported with
// InsertChain, account transactions signed with ML-DSA-44, and reveals
// carrying the stub proof. Those helpers live in another test package, so
// the few this test needs are repeated here in the same shape.

const (
	supplyBlockSpacing = 10
	supplySealTimeout  = 2 * time.Minute
	supplyCommitGas    = 60_000
	supplyTransferGas  = 21_000
	supplyPayerSeed    = 0x5c
)

var supplyGwei = big.NewInt(1_000_000_000)

// supplyChain is one node: the chain, its engine and the test.
type supplyChain struct {
	t      *testing.T
	chain  *core.BlockChain
	engine *randomx.RandomX
}

func newSupplyChain(t *testing.T) *supplyChain {
	t.Helper()
	engine, err := randomx.New(randomx.Config{Params: ghost.InternalNetParams()})
	if err != nil {
		t.Fatalf("RandomX engine: %v", err)
	}
	engine.SetThreads(1)
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, ghost.InternalNetGenesis(), nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	return &supplyChain{t: t, chain: chain, engine: engine}
}

func (c *supplyChain) head() *types.Header { return c.chain.CurrentBlock() }

func (c *supplyChain) stateAt(h *types.Header) *state.StateDB {
	c.t.Helper()
	st, err := c.chain.StateAt(h.Root)
	if err != nil {
		c.t.Fatalf("state of block %d: %v", h.Number, err)
	}
	return st
}

// mine builds a block on the head holding txs, seals it and imports it.
func (c *supplyChain) mine(coinbase common.Address, txs ...*types.Transaction) *types.Block {
	t := c.t
	t.Helper()
	parent := c.head()
	config := c.chain.Config()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + supplyBlockSpacing,
		Coinbase:   coinbase,
		BaseFee:    eip1559.CalcBaseFee(config, parent),
	}
	if err := c.engine.Prepare(c.chain, header); err != nil {
		t.Fatalf("prepare block %d: %v", header.Number, err)
	}
	st := c.stateAt(parent)
	gp := new(core.GasPool).AddGas(header.GasLimit)
	var receipts []*types.Receipt
	for i, tx := range txs {
		st.SetTxContext(tx.Hash(), i)
		var (
			receipt *types.Receipt
			err     error
		)
		if tx.Type() == types.GhostRevealTxType {
			receipt, err = c.applyReveal(gp, st, header, tx)
		} else {
			receipt, err = core.ApplyTransaction(config, c.chain, &header.Coinbase, gp, st, header, tx, &header.GasUsed, vm.Config{})
		}
		if err != nil {
			t.Fatalf("block %d: transaction %d: %v", header.Number, i, err)
		}
		receipts = append(receipts, receipt)
	}
	block, err := c.engine.FinalizeAndAssemble(c.chain, header, st, txs, nil, receipts, nil)
	if err != nil {
		t.Fatalf("assemble block %d: %v", header.Number, err)
	}
	results, stop := make(chan *types.Block, 1), make(chan struct{})
	defer close(stop)
	if err := c.engine.Seal(c.chain, block, results, stop); err != nil {
		t.Fatalf("seal block %d: %v", block.Number(), err)
	}
	select {
	case block = <-results:
	case <-time.After(supplySealTimeout):
		t.Fatalf("block %d not sealed in %v", block.Number(), supplySealTimeout)
	}
	if _, err := c.chain.InsertChain(types.Blocks{block}); err != nil {
		t.Fatalf("import block %d: %v", block.Number(), err)
	}
	if c.head().Hash() != block.Hash() {
		t.Fatalf("block %d is not the head after import", block.Number())
	}
	return block
}

func (c *supplyChain) env(header *types.Header) *ghostpriv.BlockEnv {
	return &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   c.chain,
		ChainID: c.chain.Config().GetChainID(),
		Genesis: c.chain.Genesis().Hash(),
	}
}

func (c *supplyChain) applyReveal(gp *core.GasPool, st *state.StateDB, header *types.Header, tx *types.Transaction) (*types.Receipt, error) {
	if err := gp.SubGas(types.GhostRevealGas); err != nil {
		return nil, err
	}
	if err := ghostpriv.ApplyReveal(st, c.env(header), ghostpriv.ActiveVerifier(), tx.GhostRevealEnvelope()); err != nil {
		return nil, err
	}
	st.Finalise(true)
	header.GasUsed += types.GhostRevealGas
	receipt := &types.Receipt{
		Type:              types.GhostRevealTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: header.GasUsed,
		TxHash:            tx.Hash(),
		GasUsed:           types.GhostRevealGas,
		EffectiveGasPrice: new(big.Int),
		Logs:              st.GetLogs(tx.Hash(), header.Number.Uint64(), common.Hash{}),
	}
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	return receipt, nil
}

// revealFee is the window fee of a reveal in the block after the head.
func (c *supplyChain) revealFee() ghostpriv.Fee {
	c.t.Helper()
	parent := c.head()
	number := parent.Number.Uint64() + 1
	start := ghostpriv.WindowStart(number)
	bRef := eip1559.CalcBaseFee(c.chain.Config(), parent)
	if start != number {
		h := parent
		for h.Number.Uint64() > start {
			h = c.chain.GetHeader(h.ParentHash, h.Number.Uint64()-1)
		}
		bRef = h.BaseFee
	}
	fee, err := ghostpriv.WindowFee(bRef)
	if err != nil {
		c.t.Fatal(err)
	}
	return fee
}

// accountTx is an ML-DSA-44 account transaction from key, signed for the
// chain's genesis.
func (c *supplyChain) accountTx(key *mldsa44.PrivateKey, from common.Address, to common.Address, value *big.Int, data []byte, gas uint64) *types.Transaction {
	c.t.Helper()
	config := c.chain.Config()
	var extra uint64 = 16*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44
	signer := types.NewGhostAccountSigner(types.LatestSigner(config), c.chain.Genesis().Hash())
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   config.GetChainID(),
		Nonce:     c.stateAt(c.head()).GetNonce(from),
		GasTipCap: new(big.Int).Set(supplyGwei),
		GasFeeCap: new(big.Int).Mul(supplyGwei, big.NewInt(100)),
		Gas:       gas + extra,
		To:        &to,
		Value:     value,
		Data:      data,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	return tx
}

func supplyAccount(seed byte) (*mldsa44.PrivateKey, common.Address) {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	pk, sk := mldsa44.NewKeyFromSeed(&s)
	return sk, types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pk.Bytes())
}

func supplyAddress(label string) common.Address {
	return common.BytesToAddress(ghosttree.K("ghost/test-supply/address", []byte(label)).Bytes()[12:])
}

// totalBalance is the sum of the balances of every account in the state,
// read from the whole account trie, so an account the test does not know of
// still counts.
func totalBalance(t *testing.T, st *state.StateDB) *big.Int {
	t.Helper()
	sum := new(big.Int)
	for key, acc := range st.RawDump(&state.DumpConfig{SkipCode: true, SkipStorage: true}).Accounts {
		b, ok := new(big.Int).SetString(acc.Balance, 10)
		if !ok {
			t.Fatalf("account %s: balance %q", key, acc.Balance)
		}
		sum.Add(sum, b)
	}
	return sum
}

// blockEffect is what the test expects a block to do to the total balance:
// the reward, plus what reveals credit (out and tip), minus what commits
// move into the hidden set and what ordinary transactions burn as base fee.
type blockEffect struct {
	revealed  *big.Int
	committed *big.Int
}

// TestSupplyChangesOnlyByRewardAndReveal follows the total balance of every
// account from the genesis through empty blocks, a transfer, a commit and a
// reveal. The genesis holds nothing. In each block the total rises only by
// the block reward and by what a reveal credits; a transfer only moves value
// and burns its base fee, and a commit moves its value into the hidden set,
// whose total in the public accounting is the only place it goes.
func TestSupplyChangesOnlyByRewardAndReveal(t *testing.T) {
	t.Cleanup(ghostpriv.SetVerifier(ghostprivtest.Verifier{}))
	c := newSupplyChain(t)
	params := ghost.InternalNetParams()

	genesis := c.chain.Genesis()
	if total := totalBalance(t, c.stateAt(genesis.Header())); total.Sign() != 0 {
		t.Fatalf("total balance after the genesis is %v, want 0", total)
	}
	if hidden, err := ghostpriv.Hidden(c.stateAt(genesis.Header())); err != nil || !hidden.IsZero() {
		t.Fatalf("hidden set after the genesis is %v (%v), want 0", hidden, err)
	}

	key, payer := supplyAccount(supplyPayerSeed)
	miner := supplyAddress("miner")
	recipient := supplyAddress("recipient")
	oneGhost := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	commitValue := new(big.Int).Mul(oneGhost, big.NewInt(2))

	var (
		minted  = new(big.Int) // rewards and reveal credits so far
		removed = new(big.Int) // base fee burned and value committed so far
	)
	// check mines a block and compares the change of the total balance with
	// the reward, the reveal credits, the commits and the burned base fee.
	check := func(name string, coinbase common.Address, effect blockEffect, txs ...*types.Transaction) *types.Block {
		t.Helper()
		before := totalBalance(t, c.stateAt(c.head()))
		block := c.mine(coinbase, txs...)
		after := totalBalance(t, c.stateAt(block.Header()))

		reward := params.BlockReward(block.NumberU64()).ToBig()
		burned := new(big.Int)
		for i, r := range c.chain.GetReceiptsByHash(block.Hash()) {
			if r.Status != types.ReceiptStatusSuccessful {
				t.Fatalf("%s: transaction %d failed", name, i)
			}
			if r.Type != types.GhostRevealTxType {
				burned.Add(burned, new(big.Int).Mul(new(big.Int).SetUint64(r.GasUsed), block.BaseFee()))
			}
		}
		want := new(big.Int).Add(before, reward)
		if effect.revealed != nil {
			want.Add(want, effect.revealed)
			minted.Add(minted, effect.revealed)
		}
		want.Sub(want, burned)
		removed.Add(removed, burned)
		if effect.committed != nil {
			want.Sub(want, effect.committed)
			removed.Add(removed, effect.committed)
		}
		minted.Add(minted, reward)
		if after.Cmp(want) != 0 {
			t.Fatalf("%s (block %d): total balance %v -> %v, change %v; want reward %v, reveal credit %v, commit %v, burn %v",
				name, block.NumberU64(), before, after, new(big.Int).Sub(after, before), reward, effect.revealed, effect.committed, burned)
		}
		if cum := new(big.Int).Sub(minted, removed); after.Cmp(cum) != 0 {
			t.Fatalf("%s (block %d): total balance %v, want minted %v less removed %v", name, block.NumberU64(), after, minted, removed)
		}
		return block
	}

	// Rewards only: the payer's funds come from mining.
	for i := 0; i < 3; i++ {
		check("empty block", payer, blockEffect{})
	}

	// A transfer moves value and burns its base fee; nothing is created.
	transfer := c.accountTx(key, payer, supplyAddress("friend"), oneGhost, nil, supplyTransferGas)
	check("transfer", miner, blockEffect{}, transfer)

	// A commit moves its value from the payer into the hidden set.
	note := make([]byte, ghostpriv.NoteSize)
	data, err := ghostpriv.CommitData(ghosttree.K("ghost/test-supply/fingerprint"), note)
	if err != nil {
		t.Fatal(err)
	}
	commit := c.accountTx(key, payer, ghost.CommitEntryAddress, commitValue, data, supplyCommitGas)
	commitBlock := check("commit", miner, blockEffect{committed: commitValue}, commit)
	if hidden, err := ghostpriv.Hidden(c.stateAt(commitBlock.Header())); err != nil || hidden.ToBig().Cmp(commitValue) != 0 {
		t.Fatalf("hidden set after the commit is %v (%v), want %v", hidden, err, commitValue)
	}

	// A reveal mints out to the recipient and the tip to the coinbase from the
	// hidden set; the base part of its fee is burned.
	fee := c.revealFee()
	out := uint256.MustFromBig(oneGhost)
	rest := new(uint256.Int).Sub(uint256.MustFromBig(commitValue), out)
	rest.Sub(rest, fee.Total)
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   c.chain.Config().GetChainID().Uint64(),
		Marker:    ghosttree.K("ghost/test-supply/marker"),
		Root:      *c.head().CoinTreeRoot,
		Remainder: ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, ghosttree.K("ghost/test-supply/rest"), rest),
		Recipient: recipient,
		Out:       out,
		Fee:       new(uint256.Int).Set(fee.Total),
	}
	r.Proof = ghostprivtest.Proof(r.BindingDigest(r.ChainID, genesis.Hash()))
	envelope, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reveal, err := types.NewGhostRevealTx(envelope)
	if err != nil {
		t.Fatal(err)
	}
	credit := new(big.Int).Add(out.ToBig(), fee.Tip.ToBig())
	revealBlock := check("reveal", miner, blockEffect{revealed: credit}, reveal)
	if got := c.stateAt(revealBlock.Header()).GetBalance(recipient); !got.Eq(out) {
		t.Fatalf("recipient holds %v after the reveal, want %v", got, out)
	}

	// After the reveal, rewards only again.
	check("empty block after the reveal", miner, blockEffect{})

	// The hidden set holds what was committed less what reveals took out.
	hidden, err := ghostpriv.Hidden(c.stateAt(c.head()))
	if err != nil {
		t.Fatal(err)
	}
	wantHidden := new(big.Int).Sub(commitValue, new(big.Int).Add(out.ToBig(), fee.Total.ToBig()))
	if hidden.ToBig().Cmp(wantHidden) != 0 {
		t.Fatalf("hidden set %v, want %v", hidden, wantHidden)
	}
}
