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

package txpool

import (
	"bytes"
	"errors"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
)

var (
	gateChainID = uint64(6777972)
	gateGenesis = common.HexToHash("0x9e6e515e000000000000000000000000000000000000000000000000000000bb")
	gatePolicy  = common.HexToAddress("0x00000000000000000000000000000000c0ffee10")
)

// gateInput returns the checker input of a statement made for policy, with
// a valid stub proof or, with valid false, one whose proof is wrong.
func gateInput(t *testing.T, policy common.Address, valid bool) []byte {
	t.Helper()
	p := &ghostpriv.Preimage{Y: ghostpriv.PreimageY(common.Hash{0x42})}
	p.Context[0] = 0x0c
	p.Proof = ghostprivtest.PreimageProof(p.BindingDigest(gateChainID, gateGenesis, policy))
	if !valid {
		p.Proof[40] = 0x01
	}
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// gateTx returns an unsigned account transaction to to of nonce whose data
// is prefix followed by input.
func gateTx(nonce uint64, to *common.Address, prefix, input []byte) *types.Transaction {
	data := make([]byte, 0, len(prefix)+len(input))
	data = append(append(data, prefix...), input...)
	return types.NewTx(&types.GhostAccountTx{
		ChainID:   new(big.Int).SetUint64(gateChainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       30_000_000,
		To:        to,
		Value:     new(big.Int),
		Data:      data,
	})
}

// gateVerifier is the stub verifier behind a gate, which counts the
// verifications started and the most running at once.
type gateVerifier struct {
	gate chan struct{} // closed to let the verifications run

	mu     sync.Mutex
	calls  int
	active int
	peak   int
}

func newGateVerifier(open bool) *gateVerifier {
	v := &gateVerifier{gate: make(chan struct{})}
	if open {
		close(v.gate)
	}
	return v
}

func (v *gateVerifier) VerifiesPreimage() bool { return true }

func (v *gateVerifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	v.mu.Lock()
	v.calls++
	v.active++
	if v.active > v.peak {
		v.peak = v.active
	}
	v.mu.Unlock()
	<-v.gate
	err := ghostprivtest.Verifier{}.VerifyReveal(in, proof)
	v.mu.Lock()
	v.active--
	v.mu.Unlock()
	return err
}

func (v *gateVerifier) stats() (calls, active, peak int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls, v.active, v.peak
}

// plainVerifier accepts everything but has no proof system for the
// statement.
type plainVerifier struct{}

func (plainVerifier) VerifyReveal(*ghostpriv.VerifyInputs, []byte) error { return nil }

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		runtime.Gosched()
	}
}

// TestProofTxClassAndSizeBounds checks the size class: an account
// transaction up to 128 KiB is ordinary, one above 1 MiB is dropped unread
// and charged to a peer, one between the two passes the basic checks only
// with the proof-carrying shape, and the state stage takes it only when its
// to is a frozen policy of an earlier block.
func TestProofTxClassAndSizeBounds(t *testing.T) {
	if ghost.AccountTxMaxBytes != 131_072 || ghost.ProofTxMaxBytes != 1_048_576 || ghost.ProofTxMaxHeld != 4 {
		t.Fatalf("caps %d, %d, %d", ghost.AccountTxMaxBytes, ghost.ProofTxMaxBytes, ghost.ProofTxMaxHeld)
	}
	if ghost.ProofPeerBudget != 4 || ghost.ProofFailLimit != 3 || ghost.ProofCheckSlots != 2 || ghost.ProofChecksPerHead != 16 || ghost.ProofRejectedMemory != 4096 {
		t.Fatal("proof budgets are not those of the admission rule")
	}
	input := gateInput(t, gatePolicy, true)
	to := gatePolicy
	var (
		small      = gateTx(0, &to, []byte{1, 2, 3, 4}, nil)
		proof      = gateTx(0, &to, []byte{0xa9, 0x05, 0x9c, 0xbb}, input)
		shortData  = gateTx(0, &to, nil, make([]byte, 200_000))
		create     = gateTx(0, nil, nil, input)
		oversized  = gateTx(0, &to, make([]byte, ghost.ProofTxMaxBytes-len(input)), input)
		exactInput = gateTx(0, &to, nil, input)
	)
	if IsProofTxClass(small) || CheckProofTxSize(small) != nil {
		t.Fatal("a small transaction is in the proof class")
	}
	for name, tx := range map[string]*types.Transaction{"proof": proof, "exact": exactInput} {
		if !IsProofTxClass(tx) {
			t.Fatalf("%s: not in the proof class (%d bytes)", name, tx.Size())
		}
		if err := CheckProofTxSize(tx); err != nil {
			t.Fatalf("%s: size check: %v", name, err)
		}
		if got := ProofTxInput(tx); !bytes.Equal(got, input) {
			t.Fatalf("%s: checker input is not the last 948,321 bytes of the data", name)
		}
	}
	for name, tx := range map[string]*types.Transaction{"data shorter than the checker input": shortData, "contract creation": create} {
		err := CheckProofTxSize(tx)
		if !errors.Is(err, ErrOversizedData) || errors.Is(err, ErrProofTxOversized) || ProofCharged(err) {
			t.Errorf("%s: error %v, want an uncharged ErrOversizedData", name, err)
		}
	}
	if oversized.Size() <= ghost.ProofTxMaxBytes {
		t.Fatalf("oversized transaction of %d bytes", oversized.Size())
	}
	if err := CheckProofTxSize(oversized); !errors.Is(err, ErrProofTxOversized) || !errors.Is(err, ErrOversizedData) || !ProofCharged(err) {
		t.Errorf("above 1 MiB: error %v, want a charged ErrProofTxOversized", err)
	}

	// The basic checks: the proof class passes the size check only for a
	// pool that takes it.
	cfg := params.TestChainConfig
	head := &types.Header{Number: new(big.Int), GasLimit: 30_000_000}
	signer := types.NewGhostAccountSigner(types.LatestSignerForChainID(new(big.Int).SetUint64(gateChainID)), gateGenesis)
	opts := &ValidationOptions{Config: cfg, MaxSize: ghost.AccountTxMaxBytes, MinTip: new(big.Int), AcceptGhostAccount: true}
	if err := ValidateTransaction(proof, head, signer, opts); !errors.Is(err, ErrOversizedData) {
		t.Errorf("pool without the proof class: error %v, want ErrOversizedData", err)
	}
	opts.ProofTxs = true
	if err := ValidateTransaction(proof, head, signer, opts); errors.Is(err, ErrOversizedData) {
		t.Errorf("pool with the proof class: the size check refuses a proof-carrying transaction: %v", err)
	}
	if err := ValidateTransaction(shortData, head, signer, opts); !errors.Is(err, ErrOversizedData) {
		t.Errorf("pool with the proof class: data shorter than the input: error %v", err)
	}
	if err := ValidateTransaction(oversized, head, signer, opts); !errors.Is(err, ErrProofTxOversized) {
		t.Errorf("pool with the proof class: above 1 MiB: error %v", err)
	}

	// The state stage: only a frozen policy created before the next block.
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckProofTxState(proof, st, 10); !errors.Is(err, ErrOversizedData) || ProofCharged(err) {
		t.Errorf("unregistered to: error %v, want an uncharged ErrOversizedData", err)
	}
	ghost.RegisterPolicy(st, gatePolicy, 5, common.Hash{0xc0})
	if err := CheckProofTxState(proof, st, 6); err != nil {
		t.Errorf("policy of an earlier block: %v", err)
	}
	if err := CheckProofTxState(proof, st, 5); !errors.Is(err, ErrOversizedData) {
		t.Errorf("policy of the same block: error %v, want ErrOversizedData", err)
	}
	if err := CheckProofTxState(small, st, 1); err != nil {
		t.Errorf("small transaction to an unregistered policy: %v", err)
	}
}

// TestProofGateBudgetAndSlots checks a peer's budget of four proof-carrying
// deliveries per head and its failed proof limit of three, both refilled
// when the head moves, and the check slots: one open to peers, one kept for
// local RPC, each refusing a second check with a busy error while taken.
func TestProofGateBudgetAndSlots(t *testing.T) {
	peers := NewProofPeers(16)
	h1, h2 := common.Hash{1}, common.Hash{2}
	for i := 0; i < ghost.ProofPeerBudget; i++ {
		if !peers.Take("a", h1) {
			t.Fatalf("delivery %d refused within the budget", i)
		}
	}
	if peers.Take("a", h1) || peers.Available("a", h1) != 0 {
		t.Fatal("a fifth delivery at the head is taken")
	}
	if !peers.Take("b", h1) {
		t.Fatal("another peer's budget is used up by the first")
	}
	if peers.Available("a", h2) != ghost.ProofPeerBudget || !peers.Take("a", h2) {
		t.Fatal("the budget is not refilled when the head moves")
	}
	if peers.Fail("a", h2) || peers.Fail("a", h2) {
		t.Fatal("the peer is dropped before its third failure")
	}
	if !peers.Fail("a", h2) {
		t.Fatal("the third failure at one head does not drop the peer")
	}
	if peers.Fail("a", common.Hash{3}) {
		t.Fatal("the failures are not counted again from a new head")
	}

	// The slots.
	v := newGateVerifier(false)
	g := NewProofGate(gateChainID, gateGenesis, v)
	if g.Slots(SigFromPeer) != 1 || g.Slots(SigFromRPC) != 1 || g.Slots(SigFromPeer)+g.Slots(SigFromRPC) != ghost.ProofCheckSlots {
		t.Fatalf("slots: peers %d, RPC %d", g.Slots(SigFromPeer), g.Slots(SigFromRPC))
	}
	input := gateInput(t, gatePolicy, true)
	to := gatePolicy
	results := make(chan error, 2)
	go func() { results <- g.Check(SigFromPeer, h1, gateTx(1, &to, nil, input)) }()
	waitFor(t, "the peer check runs", func() bool { _, active, _ := v.stats(); return active == 1 })
	if err := g.Check(SigFromPeer, h1, gateTx(2, &to, nil, input)); !errors.Is(err, ErrProofBusy) || ProofCharged(err) {
		t.Fatalf("second peer check: error %v, want an uncharged busy error", err)
	}
	go func() { results <- g.Check(SigFromRPC, h1, gateTx(3, &to, nil, input)) }()
	waitFor(t, "the RPC check runs beside the peer's", func() bool { _, active, _ := v.stats(); return active == 2 })
	if err := g.Check(SigFromRPC, h1, gateTx(4, &to, nil, input)); !errors.Is(err, ErrProofBusy) {
		t.Fatalf("second RPC check: error %v, want busy", err)
	}
	if g.InFlight(SigFromPeer) != 1 || g.InFlight(SigFromRPC) != 1 {
		t.Fatalf("in flight: peers %d, RPC %d", g.InFlight(SigFromPeer), g.InFlight(SigFromRPC))
	}
	close(v.gate)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("check in a slot: %v", err)
		}
	}
	if calls, _, peak := v.stats(); calls != 2 || peak != 2 {
		t.Fatalf("verifications %d, peak %d, want 2 and 2", calls, peak)
	}
	// The slots are free again.
	if err := g.Check(SigFromPeer, h1, gateTx(2, &to, nil, input)); err != nil {
		t.Fatalf("peer check after the slot is freed: %v", err)
	}
}

// TestProofGateFailedHashRefusedWithoutCheck checks that a transaction
// whose proof failed is refused again, from any origin and at any head,
// without a verification, and charged; that a wrong statement code fails
// without one; that a passed transaction is never verified again; that a
// node that cannot verify the statement charges nobody and remembers
// nothing; and that the memory of failed hashes is bounded.
func TestProofGateFailedHashRefusedWithoutCheck(t *testing.T) {
	v := newGateVerifier(true)
	g := NewProofGate(gateChainID, gateGenesis, v)
	to := gatePolicy
	bad := gateTx(1, &to, nil, gateInput(t, gatePolicy, false))
	err := g.Check(SigFromPeer, common.Hash{1}, bad)
	if !errors.Is(err, ErrProofFailed) || !errors.Is(err, ghostpriv.ErrPreimageProof) || !ProofCharged(err) {
		t.Fatalf("invalid proof: error %v, want a charged ErrProofFailed", err)
	}
	if calls, _, _ := v.stats(); calls != 1 || !g.Rejected(bad.Hash()) {
		t.Fatalf("invalid proof: %d verifications, remembered %v", calls, g.Rejected(bad.Hash()))
	}
	for _, origin := range []SigOrigin{SigFromPeer, SigFromRPC} {
		err := g.Check(origin, common.Hash{2}, bad)
		if !errors.Is(err, ErrProofRejectedBefore) || !ProofCharged(err) {
			t.Fatalf("again from %d: error %v, want ErrProofRejectedBefore", origin, err)
		}
	}
	if calls, _, _ := v.stats(); calls != 1 {
		t.Fatalf("a failed hash was verified again: %d verifications", calls)
	}

	// A statement code other than 0x06 fails before any verification.
	input := gateInput(t, gatePolicy, true)
	wrong := append([]byte{0x05}, input[1:]...)
	wrongTx := gateTx(2, &to, nil, wrong)
	if err := g.Check(SigFromPeer, common.Hash{2}, wrongTx); !errors.Is(err, ErrProofFailed) || !errors.Is(err, ghostpriv.ErrPreimageInput) {
		t.Fatalf("statement 0x05: error %v", err)
	}
	if calls, _, _ := v.stats(); calls != 1 || !g.Rejected(wrongTx.Hash()) {
		t.Fatal("statement 0x05 was verified or not remembered")
	}

	// A valid proof passes once and is taken again without a check.
	good := gateTx(3, &to, nil, input)
	for i := 0; i < 3; i++ {
		if err := g.Check(SigFromPeer, common.Hash{byte(10 + i)}, good); err != nil {
			t.Fatalf("valid proof, check %d: %v", i, err)
		}
	}
	if calls, _, _ := v.stats(); calls != 2 || !g.Passed(good.Hash()) {
		t.Fatalf("valid proof: %d verifications in all, want 2", calls)
	}
	// The same statement for another policy, as to, does not verify.
	other := common.Address{0x0e}
	if err := g.Check(SigFromPeer, common.Hash{2}, gateTx(4, &other, nil, input)); !errors.Is(err, ErrProofFailed) {
		t.Fatalf("statement of another policy: error %v", err)
	}

	// A node that cannot verify the statement.
	plain := NewProofGate(gateChainID, gateGenesis, plainVerifier{})
	err = plain.Check(SigFromPeer, common.Hash{1}, good)
	if !errors.Is(err, ErrProofUnsupported) || ProofCharged(err) || plain.Rejected(good.Hash()) || plain.Passed(good.Hash()) {
		t.Fatalf("unsupported statement: error %v", err)
	}

	// The memory is bounded: the oldest failed hash is forgotten first.
	mem := NewProofGate(gateChainID, gateGenesis, v)
	for i := 0; i <= ghost.ProofRejectedMemory; i++ {
		mem.reject(common.BigToHash(big.NewInt(int64(i+1))), ghostpriv.ErrPreimageProof)
	}
	if mem.rejected.Len() != ghost.ProofRejectedMemory {
		t.Fatalf("remembered %d hashes, want %d", mem.rejected.Len(), ghost.ProofRejectedMemory)
	}
	if mem.Rejected(common.BigToHash(big.NewInt(1))) || !mem.Rejected(common.BigToHash(big.NewInt(int64(ghost.ProofRejectedMemory+1)))) {
		t.Fatal("the oldest failed hash is kept or the newest forgotten")
	}
}

// TestProofGateFloodStaysInCheckSlots checks that a flood of proof-carrying
// transactions, from peers and RPC at once, runs at most two verifications
// at a time and sixteen at one head: the rest are dropped unverified with a
// busy error, charged to nobody, and a new head opens the checks again.
func TestProofGateFloodStaysInCheckSlots(t *testing.T) {
	v := newGateVerifier(false)
	g := NewProofGate(gateChainID, gateGenesis, v)
	to := gatePolicy
	input := gateInput(t, gatePolicy, true)
	head := common.Hash{0xfe}

	const flood = 16
	var (
		wg      sync.WaitGroup
		results = make([]error, flood)
		nonce   uint64
	)
	for i := 0; i < flood; i++ {
		origin := SigFromPeer
		if i%4 == 3 {
			origin = SigFromRPC
		}
		nonce++
		tx := gateTx(nonce, &to, nil, input)
		wg.Add(1)
		go func(i int, origin SigOrigin, tx *types.Transaction) {
			defer wg.Done()
			results[i] = g.Check(origin, head, tx)
		}(i, origin, tx)
	}
	// Every check but the two in the slots returns at once.
	waitFor(t, "the flood fills the slots", func() bool {
		_, active, _ := v.stats()
		return active == ghost.ProofCheckSlots
	})
	if g.InFlight(SigFromPeer) > 1 || g.InFlight(SigFromRPC) > 1 {
		t.Fatalf("in flight: peers %d, RPC %d", g.InFlight(SigFromPeer), g.InFlight(SigFromRPC))
	}
	close(v.gate)
	wg.Wait()
	passed := 0
	for i, err := range results {
		switch {
		case err == nil:
			passed++
		case errors.Is(err, ErrProofBusy) && !ProofCharged(err):
		default:
			t.Fatalf("flood check %d: %v", i, err)
		}
	}
	calls, _, peak := v.stats()
	if peak > ghost.ProofCheckSlots || passed != calls || passed < 1 {
		t.Fatalf("flood: %d passed, %d verifications, peak %d", passed, calls, peak)
	}

	// Checks go on one after another until the head's sixteen are used.
	for calls < ghost.ProofChecksPerHead {
		nonce++
		if err := g.Check(SigFromPeer, head, gateTx(nonce, &to, nil, input)); err != nil {
			t.Fatalf("check %d at the head: %v", calls+1, err)
		}
		calls, _, _ = v.stats()
	}
	for _, origin := range []SigOrigin{SigFromPeer, SigFromRPC} {
		nonce++
		if err := g.Check(origin, head, gateTx(nonce, &to, nil, input)); !errors.Is(err, ErrProofBusy) || ProofCharged(err) {
			t.Fatalf("past the head's checks from %d: error %v, want an uncharged busy error", origin, err)
		}
	}
	if calls, _, peak := v.stats(); calls != ghost.ProofChecksPerHead || peak > ghost.ProofCheckSlots || g.Verified() != uint64(calls) {
		t.Fatalf("verifications %d (gate %d), peak %d, want %d and at most %d", calls, g.Verified(), peak, ghost.ProofChecksPerHead, ghost.ProofCheckSlots)
	}
	// A new head opens the checks again.
	nonce++
	if err := g.Check(SigFromPeer, common.Hash{0xff}, gateTx(nonce, &to, nil, input)); err != nil {
		t.Fatalf("check at a new head: %v", err)
	}
}
