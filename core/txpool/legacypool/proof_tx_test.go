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

package legacypool

import (
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// proofTxGas covers the intrinsic gas of a proof-carrying transaction whose
// proof field is mostly zeros, with room for a prefix.
const proofTxGas = 5_000_000

var proofPolicy = common.HexToAddress("0x00000000000000000000000000000000c0ffee20")

// countingPreimageVerifier is the stub verifier, or one that refuses
// everything, that counts its calls.
type countingPreimageVerifier struct {
	refuse bool

	mu    sync.Mutex
	calls int
}

func (v *countingPreimageVerifier) VerifiesPreimage() bool { return true }

func (v *countingPreimageVerifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()
	if v.refuse {
		return ghostprivtest.ErrStubProof
	}
	return ghostprivtest.Verifier{}.VerifyReveal(in, proof)
}

func (v *countingPreimageVerifier) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// setupProofPool returns a pool whose active verifier is a counting stub
// verifier, with proofPolicy registered as a frozen policy created at
// policyHeight.
func setupProofPool(t *testing.T, policyHeight uint64) (*LegacyPool, *countingPreimageVerifier) {
	t.Helper()
	v := new(countingPreimageVerifier)
	t.Cleanup(ghostpriv.SetVerifier(v))
	pool, _, _ := setupPool()
	t.Cleanup(func() { pool.Close() })
	code := []byte{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
	pool.mu.Lock()
	pool.currentState.CreateAccount(proofPolicy)
	pool.currentState.SetCode(proofPolicy, code)
	ghost.RegisterPolicy(pool.currentState, proofPolicy, policyHeight, crypto.Keccak256Hash(code))
	pool.mu.Unlock()
	return pool, v
}

// proofInput returns the checker input of a statement made for policy on
// the test chain, with a valid stub proof or, with valid false, a wrong one.
func proofInput(t *testing.T, policy common.Address, valid bool) []byte {
	t.Helper()
	p := &ghostpriv.Preimage{Y: ghostpriv.PreimageY(common.Hash{0x77})}
	p.Context[5] = 0x55
	p.Proof = ghostprivtest.PreimageProof(p.BindingDigest(params.TestChainConfig.GetChainID().Uint64(), testGenesis.Hash(), policy))
	if !valid {
		p.Proof[100] = 0x01
	}
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// proofTx signs an account transaction to to whose data is a 4-byte
// selector, prefix more bytes and the checker input.
func proofTx(t *testing.T, key *mldsa44.PrivateKey, nonce uint64, price int64, to common.Address, prefix int, input []byte) *types.Transaction {
	t.Helper()
	data := make([]byte, 4+prefix, 4+prefix+len(input))
	copy(data, []byte{0x1e, 0x55, 0xc4, 0x3d})
	data = append(data, input...)
	tx, err := types.SignGhostAccountTx(testSigner, key, &types.GhostAccountTx{
		ChainID:   params.TestChainConfig.GetChainID(),
		Nonce:     nonce,
		GasTipCap: big.NewInt(price),
		GasFeeCap: big.NewInt(price),
		Gas:       proofTxGas,
		To:        &to,
		Value:     new(big.Int),
		Data:      data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// fundedProofKey returns the key of a funded test account of seed.
func fundedProofKey(pool *LegacyPool, seed byte) *mldsa44.PrivateKey {
	key, _, from := testAccount(seed)
	testAddBalance(pool, from, new(big.Int).Lsh(big.NewInt(1), 80))
	return key
}

// TestLegacyPoolAdmitsProofTx checks that an account transaction to a
// frozen policy of an earlier block carrying a valid statement proof is
// admitted from a peer and from RPC, verified once, within the cap of four
// held, one per sender (a replacement at the same nonce excepted), and that
// every other account transaction keeps the 128 KiB cap.
func TestLegacyPoolAdmitsProofTx(t *testing.T) {
	pool, v := setupProofPool(t, 0)
	input := proofInput(t, proofPolicy, true)

	keys := make([]*mldsa44.PrivateKey, ghost.ProofTxMaxHeld+1)
	for i := range keys {
		keys[i] = fundedProofKey(pool, byte(0x40+i))
	}
	held := make([]*types.Transaction, ghost.ProofTxMaxHeld)
	for i := range held {
		held[i] = proofTx(t, keys[i], 0, 1, proofPolicy, 0, input)
		if held[i].Size() <= ghost.AccountTxMaxBytes || held[i].Size() > ghost.ProofTxMaxBytes {
			t.Fatalf("proof-carrying transaction of %d bytes", held[i].Size())
		}
		local := i%2 == 1 // from RPC every other one
		if err := pool.Add([]*types.Transaction{held[i]}, local, true)[0]; err != nil {
			t.Fatalf("proof-carrying transaction %d (local %v) refused: %v", i, local, err)
		}
		if !pool.Has(held[i].Hash()) || pool.Status(held[i].Hash()) != txpool.TxStatusPending {
			t.Fatalf("proof-carrying transaction %d is not pending", i)
		}
	}
	if v.count() != ghost.ProofTxMaxHeld || pool.proofGate.Verified() != ghost.ProofTxMaxHeld {
		t.Fatalf("%d verifications, want one per transaction", v.count())
	}

	// A fifth sender is refused at the cap, a second of a sender at another
	// nonce too, both before any verification.
	fifth := proofTx(t, keys[ghost.ProofTxMaxHeld], 0, 1, proofPolicy, 0, input)
	if err := pool.addRemoteSync(fifth); !errors.Is(err, txpool.ErrProofHeldCap) || txpool.ProofCharged(err) {
		t.Fatalf("fifth proof-carrying transaction: error %v, want ErrProofHeldCap", err)
	}
	second := proofTx(t, keys[0], 1, 1, proofPolicy, 0, input)
	if err := pool.addRemoteSync(second); !errors.Is(err, txpool.ErrProofHeldCap) {
		t.Fatalf("second of one sender: error %v, want ErrProofHeldCap", err)
	}
	if v.count() != ghost.ProofTxMaxHeld {
		t.Fatalf("refused at the cap after %d verifications", v.count()-ghost.ProofTxMaxHeld)
	}
	// A replacement at the same nonce takes the place of the one it replaces.
	replacement := proofTx(t, keys[0], 0, 2, proofPolicy, 0, input)
	if err := pool.addRemoteSync(replacement); err != nil {
		t.Fatalf("replacement at the same nonce refused: %v", err)
	}
	if pool.Has(held[0].Hash()) || !pool.Has(replacement.Hash()) {
		t.Fatal("the replacement did not take the place of the first")
	}

	// Every other account transaction keeps the 128 KiB cap.
	ordinary := fundedProofKey(pool, 0x50)
	large := accountTx(0, proofTxGas, big.NewInt(1), big.NewInt(1), new(big.Int), make([]byte, ghost.AccountTxMaxBytes+1), ordinary)
	if err := pool.addRemoteSync(large); !errors.Is(err, txpool.ErrOversizedData) || txpool.ProofCharged(err) {
		t.Fatalf("large ordinary transaction: error %v, want an uncharged ErrOversizedData", err)
	}
	if err := pool.addRemoteSync(transaction(0, txGas, ordinary)); err != nil {
		t.Fatalf("small transaction refused: %v", err)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
}

// TestLegacyPoolRefusesInvalidProofTx checks that a proof that fails, a
// statement code other than 0x06 and a statement made for another policy
// than to are refused with a charged ErrProofFailed; that a failed hash is
// refused again without a verification; that a bad signature is refused
// before the proof is looked at; and that a state failure costs no proof
// check and is not charged.
func TestLegacyPoolRefusesInvalidProofTx(t *testing.T) {
	pool, v := setupProofPool(t, 0)
	key := fundedProofKey(pool, 0x60)

	bad := proofTx(t, key, 0, 1, proofPolicy, 0, proofInput(t, proofPolicy, false))
	err := pool.addRemoteSync(bad)
	if !errors.Is(err, txpool.ErrProofFailed) || !txpool.ProofCharged(err) || pool.Has(bad.Hash()) {
		t.Fatalf("invalid proof: error %v, want a charged ErrProofFailed", err)
	}
	if v.count() != 1 {
		t.Fatalf("invalid proof: %d verifications", v.count())
	}
	for _, local := range []bool{false, true} {
		err := pool.Add([]*types.Transaction{bad}, local, true)[0]
		if !errors.Is(err, txpool.ErrProofRejectedBefore) || !txpool.ProofCharged(err) {
			t.Fatalf("invalid proof again (local %v): error %v", local, err)
		}
	}
	if v.count() != 1 {
		t.Fatalf("a failed proof was verified again: %d verifications", v.count())
	}

	// A statement code other than 0x06: no verification.
	valid := proofInput(t, proofPolicy, true)
	wrong := append([]byte{0x05}, valid[1:]...)
	if err := pool.addRemoteSync(proofTx(t, key, 0, 1, proofPolicy, 0, wrong)); !errors.Is(err, txpool.ErrProofFailed) || !errors.Is(err, ghostpriv.ErrPreimageInput) {
		t.Fatalf("statement 0x05: error %v", err)
	}
	if v.count() != 1 {
		t.Fatal("a wrong statement code was verified")
	}
	// A statement made for another policy, forwarded by to.
	other := common.HexToAddress("0x00000000000000000000000000000000c0ffee21")
	if err := pool.addRemoteSync(proofTx(t, key, 0, 1, proofPolicy, 0, proofInput(t, other, true))); !errors.Is(err, txpool.ErrProofFailed) {
		t.Fatalf("statement of another policy: error %v", err)
	}

	// A bad signature is refused before the proof.
	good := proofTx(t, key, 0, 1, proofPolicy, 0, valid)
	_, pk, sig, _ := good.GhostAccountAuth()
	sig[9] ^= 0x01
	before := v.count()
	forged := types.NewTx(&types.GhostAccountTx{
		ChainID:   good.ChainId(),
		Nonce:     good.Nonce(),
		GasTipCap: good.GasTipCap(),
		GasFeeCap: good.GasFeeCap(),
		Gas:       good.Gas(),
		To:        good.To(),
		Value:     good.Value(),
		Data:      good.Data(),
		Scheme:    types.GhostScheme(types.GhostSchemeMLDSA44),
		PublicKey: pk,
		Signature: sig,
	})
	if !txpool.IsProofTxClass(forged) {
		t.Fatal("the forged transaction is not in the proof class")
	}
	if err := pool.addRemoteSync(forged); !errors.Is(err, txpool.ErrSignatureFailed) || txpool.ProofCharged(err) {
		t.Fatalf("bad signature: error %v, want ErrSignatureFailed", err)
	}
	// A sender that cannot pay: a state failure, before the signature and
	// the proof, charged to nobody.
	poor, _, _ := testAccount(0x61)
	if err := pool.addRemoteSync(proofTx(t, poor, 0, 1, proofPolicy, 0, valid)); !errors.Is(err, core.ErrInsufficientFunds) || txpool.ProofCharged(err) {
		t.Fatalf("unfunded sender: error %v", err)
	}
	if v.count() != before {
		t.Fatalf("%d proofs verified for a bad signature or a state failure", v.count()-before)
	}
	// The control: the valid one is admitted.
	if err := pool.addRemoteSync(good); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
}

// TestLegacyPoolRefusesOversizedProofTx checks that an account transaction
// above 1 MiB is dropped unread with a charged ErrProofTxOversized, even with
// a valid proof, while one just within it is admitted.
func TestLegacyPoolRefusesOversizedProofTx(t *testing.T) {
	pool, v := setupProofPool(t, 0)
	input := proofInput(t, proofPolicy, true)

	// The envelope overhead of a proof-carrying transaction with no prefix.
	probe := proofTx(t, fundedProofKey(pool, 0x70), 0, 1, proofPolicy, 0, input)
	room := ghost.ProofTxMaxBytes - int(probe.Size()) - 8

	over := proofTx(t, fundedProofKey(pool, 0x71), 0, 1, proofPolicy, room+64, input)
	if over.Size() <= ghost.ProofTxMaxBytes {
		t.Fatalf("oversized transaction of %d bytes", over.Size())
	}
	for _, local := range []bool{false, true} {
		err := pool.Add([]*types.Transaction{over}, local, true)[0]
		if !errors.Is(err, txpool.ErrProofTxOversized) || !txpool.ProofCharged(err) {
			t.Fatalf("above 1 MiB (local %v): error %v, want a charged ErrProofTxOversized", local, err)
		}
	}
	if pool.Has(over.Hash()) || v.count() != 0 {
		t.Fatalf("above 1 MiB: in the pool %v, %d verifications", pool.Has(over.Hash()), v.count())
	}

	within := proofTx(t, fundedProofKey(pool, 0x72), 0, 1, proofPolicy, room, input)
	if within.Size() > ghost.ProofTxMaxBytes || within.Size() < ghost.ProofTxMaxBytes-64 {
		t.Fatalf("transaction just within the cap of %d bytes", within.Size())
	}
	if err := pool.addRemoteSync(within); err != nil {
		t.Fatalf("proof-carrying transaction of %d bytes refused: %v", within.Size(), err)
	}
}

// TestLegacyPoolHeldProofTxNotReverified checks that a held proof-carrying
// transaction is never verified again: not on new heads, not when it is
// delivered again, and not after the verifier changes.
func TestLegacyPoolHeldProofTxNotReverified(t *testing.T) {
	pool, v := setupProofPool(t, 0)
	tx := proofTx(t, fundedProofKey(pool, 0x80), 0, 1, proofPolicy, 0, proofInput(t, proofPolicy, true))
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
	if v.count() != 1 {
		t.Fatalf("%d verifications", v.count())
	}
	// From now on every proof would fail.
	refusing := &countingPreimageVerifier{refuse: true}
	defer ghostpriv.SetVerifier(refusing)()

	parent := common.Hash{}
	for n := uint64(1); n <= 3; n++ {
		head := ghostPoolHead(n, parent, "proof heads")
		<-pool.requestReset(nil, head)
		parent = head.Hash()
		if !pool.Has(tx.Hash()) {
			t.Fatalf("held proof-carrying transaction dropped at head %d", n)
		}
	}
	for _, local := range []bool{false, true} {
		if err := pool.Add([]*types.Transaction{tx}, local, true)[0]; !errors.Is(err, txpool.ErrAlreadyKnown) {
			t.Fatalf("delivered again (local %v): error %v, want ErrAlreadyKnown", local, err)
		}
	}
	if v.count() != 1 || refusing.count() != 0 || pool.proofGate.Verified() != 1 {
		t.Fatalf("the held transaction was verified again: %d, %d", v.count()-1, refusing.count())
	}
	if pool.Status(tx.Hash()) != txpool.TxStatusPending {
		t.Fatal("the held transaction is not pending")
	}
}

// TestLegacyPoolProofTxNeedsCallablePolicy checks that a proof-carrying
// transaction is refused, as oversized and charged to nobody, unless its to
// is a frozen policy created before the next block, before its signature or
// proof is verified, and that a held one is dropped when its policy stops
// being callable after a reorganisation.
func TestLegacyPoolProofTxNeedsCallablePolicy(t *testing.T) {
	const policyHeight = 5
	pool, v := setupProofPool(t, policyHeight)
	key := fundedProofKey(pool, 0x90)
	input := proofInput(t, proofPolicy, true)
	tx := proofTx(t, key, 0, 1, proofPolicy, 0, input)

	// Next block 1: the policy of block 5 is not callable yet.
	if err := pool.addRemoteSync(tx); !errors.Is(err, txpool.ErrOversizedData) || txpool.ProofCharged(err) {
		t.Fatalf("policy of a later block: error %v, want an uncharged ErrOversizedData", err)
	}
	// An address that is no policy at all.
	plain := common.HexToAddress("0x00000000000000000000000000000000c0ffee22")
	if err := pool.addRemoteSync(proofTx(t, key, 0, 1, plain, 0, proofInput(t, plain, true))); !errors.Is(err, txpool.ErrOversizedData) || txpool.ProofCharged(err) {
		t.Fatalf("to no policy: error %v", err)
	}
	// Next block 5, the policy's own: still not callable.
	<-pool.requestReset(nil, ghostPoolHead(policyHeight-1, common.Hash{}, ""))
	if err := pool.addRemoteSync(tx); !errors.Is(err, txpool.ErrOversizedData) {
		t.Fatalf("policy of the next block: error %v", err)
	}
	if v.count() != 0 {
		t.Fatalf("%d proofs verified for a transaction to no callable policy", v.count())
	}

	// Next block 6: the policy is callable, the transaction admitted.
	<-pool.requestReset(nil, ghostPoolHead(policyHeight, common.Hash{}, ""))
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("policy of an earlier block: %v", err)
	}
	if !pool.Has(tx.Hash()) || v.count() != 1 {
		t.Fatalf("admitted %v after %d verifications", pool.Has(tx.Hash()), v.count())
	}
	// A reorganisation to a chain on which the next block is the policy's
	// own: the policy is no longer callable and the transaction is dropped.
	<-pool.requestReset(nil, ghostPoolHead(policyHeight-1, common.Hash{}, "other branch"))
	if pool.Has(tx.Hash()) {
		t.Fatal("the transaction stays after its policy stopped being callable")
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
	if v.count() != 1 {
		t.Fatalf("%d verifications, the drop verified again", v.count())
	}
}
