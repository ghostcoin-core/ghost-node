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

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// pubMiner is the coinbase of the blocks that carry the public roots.
var pubMiner = common.Address{0xcb, 0x56}

// pubTo is a recipient of a binding transaction.
func pubTo(n byte) common.Address { return common.Address{0xb0, 0x57, n} }

// pubIdentity is the key identity of the ML-DSA-44 test account of seed.
func pubIdentity(seed byte) common.Hash {
	_, pub, _ := testAccount(seed)
	return types.GhostAccountKeyIdentityOf(types.GhostSchemeMLDSA44, pub)
}

// The seeds of the test accounts keyA, keyB and keyC.
const (
	seedA byte = 0xa1
	seedB byte = 0xb2
	seedC byte = 0xc3
)

// bundleOnly is a verifier of reveals and bundles that is no public root
// verifier: it has no VerifyPublicRoot.
type bundleOnly struct{}

func (bundleOnly) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	return stub.VerifyReveal(in, proof)
}

func (bundleOnly) VerifyBundle(in *ghostpriv.BundleInputs, proof []byte) error {
	return stub.VerifyBundle(in, proof)
}

// publicChain is a chain whose block 1 registers the keys of accounts A and
// B, imported. Account C never registers. The tests build block 2 with the
// chain maker.
type publicChain struct {
	f      *fixture
	chain  *core.BlockChain
	block1 *types.Block
}

func newPublicChain(t *testing.T) *publicChain {
	t.Helper()
	f := newFixture(t, 30_000_000, nil)
	s := &publicChain{f: f}
	blocks, _ := s.generate(t, 1, nil)
	s.chain = f.newChain()
	f.insert(s.chain, blocks)
	s.block1 = blocks[0]
	st, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if types.GhostRecordedKeyIdentity(st, addrA) != pubIdentity(seedA) || types.GhostRecordedKeyIdentity(st, addrB) != pubIdentity(seedB) {
		t.Fatal("block 1 did not record the keys of A and B")
	}
	if types.GhostRecordedKeyIdentity(st, addrC) != (common.Hash{}) {
		t.Fatal("C has a key recorded")
	}
	return s
}

// registerTx is a key registration of key: an account transaction to the
// key registry with no value and no data.
func (s *publicChain) registerTx(key *mldsa44.PrivateKey, nonce uint64) *types.Transaction {
	return s.f.callTx(key, nonce, types.GhostKeyRegistryAccount, new(big.Int), nil, 30_000)
}

func (s *publicChain) generate(t *testing.T, n int, gen func(b *core.BlockGen)) ([]*types.Block, []types.Receipts) {
	t.Helper()
	return s.f.generate(n, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(s.registerTx(keyA, 0))
			b.AddTx(s.registerTx(keyB, 0))
		case 1:
			b.SetCoinbase(pubMiner)
			gen(b)
		}
	})
}

// build generates block 1 and a block 2 of gen on it, and checks that block
// 1 is the chain's.
func (s *publicChain) build(t *testing.T, gen func(b *core.BlockGen)) ([]*types.Block, []types.Receipts) {
	t.Helper()
	blocks, receipts := s.generate(t, 2, gen)
	if blocks[0].Hash() != s.block1.Hash() {
		t.Fatal("block 1 did not rebuild identically")
	}
	return blocks, receipts
}

// insertBad imports block 1 of blocks and then its invalid block 2 on a
// chain of their own and returns the import error of block 2. The head stays
// block 1.
func (s *publicChain) insertBad(t *testing.T, name string, blocks []*types.Block) error {
	t.Helper()
	chain := s.f.newChain()
	s.f.insert(chain, blocks[:1])
	_, err := chain.InsertChain(blocks[1:])
	if chain.CurrentBlock().Hash() != s.block1.Hash() {
		t.Fatalf("%s: the head moved", name)
	}
	return err
}

// unbound is the unbound binding transaction of account from with nonce,
// sending value to to: the fields of an account transaction with the gas of
// one, and a zero binding.
func (s *publicChain) unbound(nonce uint64, to common.Address, value *big.Int) *types.GhostBindingTx {
	return &types.GhostBindingTx{
		ChainID:   new(big.Int).SetUint64(s.f.chainID),
		Nonce:     nonce,
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       21_000 + accountExtraGas,
		To:        &to,
		Value:     value,
		Scheme:    types.GhostScheme(types.GhostSchemeMLDSA44),
	}
}

// txHash is the transaction hash a binding of inner binds on this chain.
func (s *publicChain) txHash(inner *types.GhostBindingTx) common.Hash {
	h, _ := types.NewTx(inner).GhostBindingTxHash(s.f.genesis.Hash())
	return h
}

// bindingTx is a binding transaction of account from, whose key identity is
// identity, with nonce, sending value to to, carrying the binding of its own
// transaction hash.
func (s *publicChain) bindingTx(from common.Address, identity common.Hash, nonce uint64, to common.Address, value *big.Int) *types.Transaction {
	inner := s.unbound(nonce, to, value)
	inner.Binding = types.NewGhostBinding(from, identity, s.txHash(inner))
	return types.NewTx(inner)
}

// carried is the binding a binding transaction carries.
func carried(tx *types.Transaction) types.GhostBinding {
	_, b, _ := tx.GhostBinding()
	return b
}

// root is a public root over bindings, in order, with the stub proof of the
// inputs of those bindings on this chain.
func (s *publicChain) root(bindings ...types.GhostBinding) *ghostpriv.PublicRoot {
	r := &ghostpriv.PublicRoot{Version: ghostpriv.PublicRootVersion, ChainID: s.f.chainID, Bindings: bindings}
	r.Proof = ghostprivtest.PublicRootProof(r.Inputs(s.f.chainID, s.f.genesis.Hash()).Binding)
	return r
}

// rootOf is the public root of the binding transactions, over the bindings
// they carry.
func (s *publicChain) rootOf(txs ...*types.Transaction) *ghostpriv.PublicRoot {
	var bindings []types.GhostBinding
	for _, tx := range txs {
		bindings = append(bindings, carried(tx))
	}
	return s.root(bindings...)
}

func rootTx(t *testing.T, r *ghostpriv.PublicRoot) *types.Transaction {
	t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.NewGhostPublicRootTx(env)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// unchecked is a block 2 holding txs as they are, none run by the chain
// maker, so that a block the processor refuses can be built.
func (s *publicChain) unchecked(t *testing.T, txs ...*types.Transaction) []*types.Block {
	t.Helper()
	blocks, _ := s.build(t, func(b *core.BlockGen) {
		for _, tx := range txs {
			b.AddUncheckedTx(tx)
		}
	})
	if len(blocks[1].Transactions()) != len(txs) {
		t.Fatal("the block does not carry its transactions")
	}
	return blocks
}

// TestPublicRootBlockImportsAndRefuses checks a block with a public root
// (0x56) and the binding transactions (0x57) it proves on the stub
// verifier: it imports, each binding transaction runs as an account
// transaction of its binding's account at the gas of a raw-signature one,
// and a raw-signature account transaction (0x52) in the same block still
// imports. A wrong binding, a key identity that is not the recorded one, a
// wrong root proof, a root with no binding transactions, binding
// transactions with no root, a second root, a binding transaction before
// the root and a failing state-dependent check of a binding transaction each
// make the block invalid.
func TestPublicRootBlockImportsAndRefuses(t *testing.T) {
	useStub(t)
	s := newPublicChain(t)
	idA, idB, idC := pubIdentity(seedA), pubIdentity(seedB), pubIdentity(seedC)
	value := big.NewInt(1_000_000)
	bindA := s.bindingTx(addrA, idA, 1, pubTo(1), value)
	bindB := s.bindingTx(addrB, idB, 1, pubTo(2), value)
	raw := s.f.callTx(keyC, 0, pubTo(3), value, nil, 21_000)
	good := s.rootOf(bindA, bindB)

	// The node's inputs: account, recorded key identity and transaction
	// hash for every binding transaction, in block order, with the chain id
	// and the genesis as the domain. The root's stub proof is of them only.
	in := ghostpriv.NewPublicRootInputs(s.f.chainID, s.f.genesis.Hash(), []types.GhostBinding{carried(bindA), carried(bindB)})
	if err := ghostpriv.VerifyPublicRoot(stub, in, good.Proof); err != nil {
		t.Fatalf("the root proof: %v", err)
	}
	for name, other := range map[string]*ghostpriv.PublicRootInputs{
		"reordered":    ghostpriv.NewPublicRootInputs(s.f.chainID, s.f.genesis.Hash(), []types.GhostBinding{carried(bindB), carried(bindA)}),
		"removed":      ghostpriv.NewPublicRootInputs(s.f.chainID, s.f.genesis.Hash(), []types.GhostBinding{carried(bindA)}),
		"other chain":  ghostpriv.NewPublicRootInputs(s.f.chainID+1, s.f.genesis.Hash(), in.Bindings),
		"other domain": ghostpriv.NewPublicRootInputs(s.f.chainID, common.Hash{0x0d}, in.Bindings),
	} {
		if err := ghostpriv.VerifyPublicRoot(stub, other, good.Proof); !errors.Is(err, ghostpriv.ErrPublicRootProof) {
			t.Errorf("%s: root proof %v, want %v", name, err, ghostpriv.ErrPublicRootProof)
		}
	}

	// The good block imports.
	blocks, receipts := s.build(t, func(b *core.BlockGen) {
		b.AddTx(rootTx(t, good))
		b.AddTx(bindA)
		b.AddTx(raw)
		b.AddTx(bindB)
	})
	s.f.insert(s.chain, blocks[1:])
	block := s.chain.GetBlockByNumber(2)
	if block == nil || block.Hash() != blocks[1].Hash() {
		t.Fatal("the block with the public root is not the head")
	}
	st, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	for i, to := range []common.Address{pubTo(1), pubTo(2), pubTo(3)} {
		if st.GetBalance(to).ToBig().Cmp(value) != 0 {
			t.Fatalf("transfer %d not applied", i)
		}
	}
	if st.GetNonce(addrA) != 2 || st.GetNonce(addrB) != 2 || st.GetNonce(addrC) != 1 {
		t.Fatalf("nonces %d %d %d", st.GetNonce(addrA), st.GetNonce(addrB), st.GetNonce(addrC))
	}
	rs := s.chain.GetReceiptsByHash(block.Hash())
	if len(rs) != 4 {
		t.Fatalf("%d receipts", len(rs))
	}
	if rs[0].Type != types.GhostPublicRootTxType || rs[0].GasUsed != 0 || rs[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("root receipt: type %#x gas %d status %d", rs[0].Type, rs[0].GasUsed, rs[0].Status)
	}
	if rs[2].Type != types.GhostAccountTxType || rs[2].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("raw-signature receipt: type %#x status %d", rs[2].Type, rs[2].Status)
	}
	for _, k := range []int{1, 3} {
		if rs[k].Type != types.GhostBindingTxType || rs[k].Status != types.ReceiptStatusSuccessful {
			t.Fatalf("binding receipt %d: type %#x status %d", k, rs[k].Type, rs[k].Status)
		}
		// The gas of a raw-signature account transaction of the scheme.
		if rs[k].GasUsed != rs[2].GasUsed || rs[k].GasUsed != 21_000+accountExtraGas {
			t.Fatalf("binding receipt %d: gas %d, raw-signature %d, want %d", k, rs[k].GasUsed, rs[2].GasUsed, 21_000+accountExtraGas)
		}
	}
	if len(receipts[1]) != 4 || receipts[1][1].GasUsed != rs[1].GasUsed {
		t.Fatal("the chain maker's receipts are not the processor's")
	}
	// The gas of a binding transaction is the account transaction's for its
	// scheme, signature bytes and verification included.
	if want := ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44); accountExtraGas != want {
		t.Fatalf("extra gas %d, want %d", accountExtraGas, want)
	}

	// A key registered earlier in the same block is read from state at the
	// root.
	regC := s.registerTx(keyC, 0)
	bindC := s.bindingTx(addrC, idC, 1, pubTo(4), value)
	blocks, _ = s.build(t, func(b *core.BlockGen) {
		b.AddTx(regC)
		b.AddTx(rootTx(t, s.rootOf(bindC)))
		b.AddTx(bindC)
	})
	s.f.insert(s.f.newChain(), blocks)

	// The invalid blocks.
	wrongHash := s.unbound(1, pubTo(1), value)
	wrongHash.Binding = types.NewGhostBinding(addrA, idA, s.txHash(s.unbound(2, pubTo(1), value)))
	bindWrongHash := types.NewTx(wrongHash)
	nodeWrongHash := types.NewGhostBinding(addrA, idA, s.txHash(wrongHash))
	bindOtherKey := s.bindingTx(addrA, idB, 1, pubTo(1), value)
	bindUnregistered := s.bindingTx(addrC, idC, 1, pubTo(4), value)
	bindNonce := s.bindingTx(addrA, idA, 5, pubTo(1), value)
	bindRich := s.bindingTx(addrA, idA, 1, pubTo(1), new(big.Int).Mul(startBal, big.NewInt(2)))
	zeroProof := s.rootOf(bindA, bindB)
	zeroProof.Proof = nil
	otherDomain := s.rootOf(bindA, bindB)
	otherDomain.Proof = ghostprivtest.PublicRootProof(ghostpriv.NewPublicRootInputs(s.f.chainID, common.Hash{0x0d}, otherDomain.Bindings).Binding)
	otherChain := s.rootOf(bindA)
	otherChain.ChainID++
	for _, c := range []struct {
		name string
		txs  []*types.Transaction
		want error
	}{
		{"the root lists a wrong binding", []*types.Transaction{rootTx(t, s.rootOf(bindWrongHash)), bindWrongHash}, ghostpriv.ErrPublicRootBinding},
		{"the transaction carries a wrong binding", []*types.Transaction{rootTx(t, s.root(nodeWrongHash)), bindWrongHash}, ghostpriv.ErrPublicRootBinding},
		{"the root lists another transaction", []*types.Transaction{rootTx(t, s.rootOf(bindB)), bindA}, ghostpriv.ErrPublicRootBinding},
		{"the root lists them reordered", []*types.Transaction{rootTx(t, s.rootOf(bindB, bindA)), bindA, bindB}, ghostpriv.ErrPublicRootBinding},
		{"a key identity that is not the recorded one, listed", []*types.Transaction{rootTx(t, s.rootOf(bindOtherKey)), bindOtherKey}, ghostpriv.ErrPublicRootBinding},
		{"a key identity that is not the recorded one, carried", []*types.Transaction{rootTx(t, s.root(types.NewGhostBinding(addrA, idA, s.txHash(s.unbound(1, pubTo(1), value))))), bindOtherKey}, ghostpriv.ErrPublicKeyIdentity},
		{"no key identity recorded", []*types.Transaction{rootTx(t, s.root(types.NewGhostBinding(addrC, common.Hash{}, carried(bindUnregistered).TxHash()))), bindUnregistered}, ghostpriv.ErrPublicKeyIdentity},
		{"a root proof of zeros", []*types.Transaction{rootTx(t, zeroProof), bindA, bindB}, ghostpriv.ErrPublicRootProof},
		{"a root proof of another domain", []*types.Transaction{rootTx(t, otherDomain), bindA, bindB}, ghostpriv.ErrPublicRootProof},
		{"a root of another chain", []*types.Transaction{rootTx(t, otherChain), bindA}, ghostpriv.ErrPublicRootChainID},
		{"a root with no binding transactions", []*types.Transaction{rootTx(t, s.rootOf(bindA)), raw}, ghostpriv.ErrPublicRootCount},
		{"a root with fewer binding transactions", []*types.Transaction{rootTx(t, s.rootOf(bindA, bindB)), bindA}, ghostpriv.ErrPublicRootCount},
		{"binding transactions with no root", []*types.Transaction{bindA, bindB}, ghostpriv.ErrPublicRootMissing},
		{"a binding transaction before the root", []*types.Transaction{bindA, rootTx(t, s.rootOf(bindB)), bindB}, ghostpriv.ErrPublicRootMissing},
		{"two roots", []*types.Transaction{rootTx(t, s.rootOf(bindA)), bindA, rootTx(t, s.rootOf(bindB)), bindB}, ghostpriv.ErrPublicRootRepeated},
		{"a nonce the state does not hold", []*types.Transaction{rootTx(t, s.rootOf(bindNonce)), bindNonce}, core.ErrNonceTooHigh},
		{"a balance the state does not hold", []*types.Transaction{rootTx(t, s.rootOf(bindRich)), bindRich}, core.ErrInsufficientFunds},
	} {
		if err := s.insertBad(t, c.name, s.unchecked(t, c.txs...)); !errors.Is(err, c.want) {
			t.Errorf("%s: block imported with %v, want %v", c.name, err, c.want)
		}
	}

	// A binding transaction whose gas does not cover an account
	// transaction's intrinsic gas is refused: its gas is not repriced.
	low := s.unbound(1, pubTo(1), value)
	low.Gas = 21_000 + accountExtraGas - 1
	low.Binding = types.NewGhostBinding(addrA, idA, s.txHash(low))
	lowTx := types.NewTx(low)
	if err := s.insertBad(t, "gas below an account transaction's", s.unchecked(t, rootTx(t, s.rootOf(lowTx)), lowTx)); !errors.Is(err, core.ErrIntrinsicGas) {
		t.Errorf("gas below an account transaction's: block imported with %v, want %v", err, core.ErrIntrinsicGas)
	}
}

// TestPublicRootWithoutVerifierIsInvalid checks that the root is verified
// through the optional PublicRootVerifier of the active verifier: a linked
// verifier without VerifyPublicRoot (one of reveals and bundles only, or the
// node's default) fails every root closed with ErrPublicRootUnsupported,
// which is no proof failure, so the block is invalid, while the same block
// imports under the stub, a public root verifier.
func TestPublicRootWithoutVerifierIsInvalid(t *testing.T) {
	useStub(t)
	s := newPublicChain(t)
	value := big.NewInt(1_000_000)
	bindA := s.bindingTx(addrA, pubIdentity(seedA), 1, pubTo(1), value)
	raw := s.f.callTx(keyC, 0, pubTo(3), value, nil, 21_000)
	root := s.rootOf(bindA)
	in := root.Inputs(s.f.chainID, s.f.genesis.Hash())
	blocks, _ := s.build(t, func(b *core.BlockGen) {
		b.AddTx(rootTx(t, root))
		b.AddTx(bindA)
		b.AddTx(raw)
	})

	if _, ok := ghostpriv.Verifier(ghostprivtest.Verifier{}).(ghostpriv.PublicRootVerifier); !ok {
		t.Fatal("the stub verifies no public roots")
	}
	if _, ok := ghostpriv.Verifier(bundleOnly{}).(ghostpriv.PublicRootVerifier); ok {
		t.Fatal("the bundle-only verifier verifies public roots")
	}
	if _, ok := ghostpriv.Verifier(bundleOnly{}).(ghostpriv.BundleVerifier); !ok {
		t.Fatal("the bundle-only verifier verifies no bundles")
	}
	if _, ok := ghostpriv.DefaultVerifier().(ghostpriv.PublicRootVerifier); ok {
		t.Fatal("the default verifier verifies public roots")
	}
	for _, c := range []struct {
		name     string
		verifier ghostpriv.Verifier
	}{
		{"bundle-only verifier", bundleOnly{}},
		{"reveal-only verifier", revealOnly{}},
		{"default verifier", nil},
	} {
		if err := ghostpriv.VerifyPublicRoot(c.verifier, in, root.Proof); !errors.Is(err, ghostpriv.ErrPublicRootUnsupported) || errors.Is(err, ghostpriv.ErrPublicRootProof) {
			t.Fatalf("%s: root %v, want %v", c.name, err, ghostpriv.ErrPublicRootUnsupported)
		}
		restore := ghostpriv.SetVerifier(c.verifier)
		err := s.insertBad(t, c.name, blocks)
		restore()
		if !errors.Is(err, ghostpriv.ErrPublicRootUnsupported) || errors.Is(err, ghostpriv.ErrPublicRootProof) {
			t.Fatalf("%s: block imported with %v, want %v", c.name, err, ghostpriv.ErrPublicRootUnsupported)
		}
	}

	// Without a root, the raw-signature transaction imports under any of
	// them: only the root needs the public root verifier.
	rawOnly, _ := s.build(t, func(b *core.BlockGen) { b.AddTx(raw) })
	restore := ghostpriv.SetVerifier(bundleOnly{})
	chain := s.f.newChain()
	s.f.insert(chain, rawOnly)
	restore()

	// Under the stub the same block imports, on a chain that never saw it.
	chain = s.f.newChain()
	s.f.insert(chain, blocks)
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if st.GetBalance(pubTo(1)).ToBig().Cmp(value) != 0 || st.GetBalance(pubTo(3)).ToBig().Cmp(value) != 0 {
		t.Fatal("the block was not applied under the stub")
	}
}
