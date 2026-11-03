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

package ghostpool

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// The frozen policy of these tests, in the genesis and registered at height
// 0: its code is a single STOP, so that a policy action's call succeeds.
var (
	poolPolicy         = common.HexToAddress("0x9a11c1e5000000000000000000000000000b00c1")
	poolPolicyRuntime  = []byte{byte(vm.STOP)}
	poolPolicyCodeHash = crypto.Keccak256Hash(poolPolicyRuntime)

	// slotOut is the value each test slot opens with, 0.05 GHOST.
	slotOut = new(uint256.Int).Div(uint256.MustFromBig(oneGhost), uint256.NewInt(20))

	// policyCommit is what block 1 of a policy fixture commits.
	policyCommit = new(big.Int).Mul(oneGhost, big.NewInt(2))
)

// genesisRegistry writes registry words into a genesis allocation, so that
// ghost.RegisterPolicy marks a policy of the genesis.
type genesisRegistry struct{ alloc genesisT.GenesisAlloc }

func (a genesisRegistry) account(addr common.Address) genesisT.GenesisAccount {
	acc := a.alloc[addr]
	if acc.Balance == nil {
		acc.Balance = new(big.Int)
	}
	if acc.Storage == nil {
		acc.Storage = map[common.Hash]common.Hash{}
	}
	return acc
}

func (a genesisRegistry) GetState(addr common.Address, key common.Hash) common.Hash {
	return a.alloc[addr].Storage[key]
}

func (a genesisRegistry) SetState(addr common.Address, key, value common.Hash) {
	acc := a.account(addr)
	acc.Storage[key] = value
	a.alloc[addr] = acc
}

func (a genesisRegistry) GetNonce(addr common.Address) uint64 { return a.alloc[addr].Nonce }

func (a genesisRegistry) SetNonce(addr common.Address, nonce uint64) {
	acc := a.account(addr)
	acc.Nonce = nonce
	a.alloc[addr] = acc
}

// policyFixture is a chain with the test policy in its genesis whose block 1
// commits policyCommit and whose next blocks each open one escrow slot of
// the policy by a policy reveal, one a block, all imported; the blocks after
// them are built by the test and imported when it says.
type policyFixture struct {
	*fixture
	db      ethdb.Database // the generator's database, for a fork of the blocks
	engine  *ethash.Ethash
	signer  types.Signer
	chainID uint64
	slots   []*ghostpriv.PolicyReveal // the policy reveal that opened each slot
}

// newPolicyFixture generates 1+slots+extra blocks: the commit, one policy
// reveal opening a slot a block, and extra blocks gen fills, called with the
// index of the block, its height less one. It imports the commit and the
// slots.
func newPolicyFixture(t *testing.T, slots, extra int, gen func(pf *policyFixture, i int, b *core.BlockGen)) *policyFixture {
	t.Helper()
	f := newSpec(t)
	alloc := genesisT.GenesisAlloc{
		poolAddr:   {Balance: new(big.Int).Mul(oneGhost, big.NewInt(100))},
		poolPolicy: {Code: poolPolicyRuntime, Balance: new(big.Int)},
	}
	ghost.RegisterPolicy(genesisRegistry{alloc}, poolPolicy, 0, poolPolicyCodeHash)
	f.gspec.Alloc = alloc
	f.genesis = core.GenesisToBlock(f.gspec, nil)
	pf := &policyFixture{
		fixture: f,
		engine:  ethash.NewFaker(),
		chainID: f.gspec.Config.GetChainID().Uint64(),
		slots:   make([]*ghostpriv.PolicyReveal, slots),
	}
	pf.signer = types.NewGhostAccountSigner(types.LatestSigner(f.gspec.Config), f.genesis.Hash())
	commit := commitTx(t, poolKey, pf.signer, 0, policyCommit)
	db, blocks, _ := core.GenerateChainWithGenesis(f.gspec, pf.engine, 1+slots+extra, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0x01})
		switch {
		case i == 0:
			b.AddTx(commit)
		case i <= slots:
			r := pf.policyReveal(slotMarker(i-1), poolPolicy, poolPolicyCodeHash, genFee(t, b, ghostpriv.GasPolicy))
			pf.slots[i-1] = r
			b.AddTx(pf.policyTx(r))
		case gen != nil:
			gen(pf, i, b)
		}
	})
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, f.gspec, nil, pf.engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	f.chain, f.blocks, pf.db = chain, blocks, db
	for n := 1; n <= 1+slots; n++ {
		f.insert(n)
	}
	return pf
}

// slotMarker is the coin marker the policy reveal of slot i spends.
func slotMarker(i int) common.Hash {
	return ghosttree.K("ghost/test-slot-marker", []byte(fmt.Sprintf("synthetic slot %d", i)))
}

// genFee is the window fee of the class whose gas is gas in the block being
// generated, on a chain generated from the genesis.
func genFee(t *testing.T, b *core.BlockGen, gas uint64) *uint256.Int {
	t.Helper()
	h := b.Number().Uint64()
	start := ghostpriv.WindowStart(h)
	bRef := b.BaseFee()
	if start != h {
		bRef = b.PrevBlock(int(start) - 1).BaseFee()
	}
	fee, err := ghostpriv.WindowFeeGas(bRef, gas)
	if err != nil {
		t.Fatal(err)
	}
	return fee.Total
}

// policyReveal is a policy reveal of marker into policy with the genesis
// coin root, out slotOut, the given fee and the stub proof.
func (pf *policyFixture) policyReveal(marker common.Hash, policy common.Address, codeHash common.Hash, fee *uint256.Int) *ghostpriv.PolicyReveal {
	r := &ghostpriv.PolicyReveal{
		Version:    ghostpriv.PolicyRevealVersion,
		ChainID:    pf.chainID,
		Marker:     marker,
		Root:       *pf.genesis.Header().CoinTreeRoot,
		Remainder:  ghosttree.K("ghost/test-policy-remainder", marker[:]),
		Out:        new(uint256.Int).Set(slotOut),
		Fee:        new(uint256.Int).Set(fee),
		Policy:     policy,
		CodeHash:   codeHash,
		ParamsHash: ghosttree.K("ghost/test-params", marker[:]),
		ActionTag:  ghosttree.K("ghost/test-action-tag", marker[:]),
		ActionSalt: ghosttree.K("ghost/test-action-salt", marker[:]),
		Instr:      ghosttree.K("ghost/test-instr", marker[:]),
	}
	pf.proveReveal(r)
	return r
}

func (pf *policyFixture) proveReveal(r *ghostpriv.PolicyReveal) {
	r.Proof = ghostprivtest.Proof(r.BindingDigest(pf.chainID, pf.genesis.Hash()))
}

func (pf *policyFixture) policyTx(r *ghostpriv.PolicyReveal) *types.Transaction {
	pf.t.Helper()
	env, err := r.MarshalBinary()
	if err != nil {
		pf.t.Fatal(err)
	}
	tx, err := types.NewGhostPolicyRevealTx(env)
	if err != nil {
		pf.t.Fatal(err)
	}
	return tx
}

// next is the height of the block that comes next on the head.
func (pf *policyFixture) next() int { return int(pf.chain.CurrentBlock().Number.Uint64()) + 1 }

// nextPolicyReveal is a policy reveal of marker into the test policy for the
// block that comes next on the head.
func (pf *policyFixture) nextPolicyReveal(marker common.Hash) *ghostpriv.PolicyReveal {
	return pf.policyReveal(marker, poolPolicy, poolPolicyCodeHash, pf.windowFeeGas(pf.next(), ghostpriv.GasPolicy))
}

// nextCoinReveal is a coin reveal of marker i for the block that comes next
// on the head.
func (pf *policyFixture) nextCoinReveal(i int) *types.Transaction {
	return pf.revealWithFee(testMarker(i), recipient(i), pf.windowFee(pf.next()))
}

// nextBaseFee is the base fee of the block that comes next on the head.
func (pf *policyFixture) nextBaseFee() *big.Int {
	return eip1559.CalcBaseFee(pf.gspec.Config, pf.chain.CurrentBlock())
}

// actionBurn is G_ACTION times a base fee.
func actionBurn(baseFee *big.Int) *uint256.Int {
	return new(uint256.Int).Mul(uint256.NewInt(ghostpriv.GasAction), uint256.MustFromBig(baseFee))
}

// slotFields is the part of a slot an action's binding reads, from the
// policy reveal that opened it.
func slotFields(r *ghostpriv.PolicyReveal) *ghostpriv.EscrowSlot {
	return &ghostpriv.EscrowSlot{Policy: r.Policy, ParamsHash: r.ParamsHash, ActionTag: r.ActionTag, ActionSalt: r.ActionSalt, Instr: r.Instr}
}

// slotNow is the slot r opened, in the state of the head.
func (pf *policyFixture) slotNow(r *ghostpriv.PolicyReveal) *ghostpriv.EscrowSlot {
	pf.t.Helper()
	st, err := pf.chain.StateAt(pf.chain.CurrentBlock().Root)
	if err != nil {
		pf.t.Fatal(err)
	}
	slot, ok := ghostpriv.ReadEscrowSlot(st, r.Marker)
	if !ok {
		pf.t.Fatalf("no slot of marker %x at the head", r.Marker)
	}
	return slot
}

// newAction is an action of the given fields on the slot r opened, with
// the stub proof of its binding.
func (pf *policyFixture) newAction(r *ghostpriv.PolicyReveal, nonce uint64, expected, debit *uint256.Int, expiry uint64, calldata []byte) *ghostpriv.Action {
	a := &ghostpriv.Action{
		Version:           ghostpriv.PolicyActionVersion,
		ChainID:           pf.chainID,
		Marker:            r.Marker,
		Nonce:             nonce,
		ExpectedRemaining: new(uint256.Int).Set(expected),
		Debit:             new(uint256.Int).Set(debit),
		Expiry:            expiry,
		Calldata:          common.CopyBytes(calldata),
	}
	pf.proveAction(a, r)
	return a
}

func (pf *policyFixture) proveAction(a *ghostpriv.Action, r *ghostpriv.PolicyReveal) {
	a.Proof = ghostprivtest.ActionProof(a.BindingDigest(pf.chainID, pf.genesis.Hash(), slotFields(r)))
}

// action is a valid action for the block that comes next on the head, on
// the slot r opened: at the slot's nonce and remaining, its debit tip above
// G_ACTION times the next base fee, calldata the one byte salt, expiring far
// ahead.
func (pf *policyFixture) action(r *ghostpriv.PolicyReveal, tip uint64, salt byte) *ghostpriv.Action {
	slot := pf.slotNow(r)
	debit := new(uint256.Int).AddUint64(actionBurn(pf.nextBaseFee()), tip)
	return pf.newAction(r, slot.ActionNonce, slot.Remaining, debit, pf.chain.CurrentBlock().Number.Uint64()+1000, []byte{salt})
}

func (pf *policyFixture) actionTx(a *ghostpriv.Action) *types.Transaction {
	pf.t.Helper()
	env, err := a.MarshalBinary()
	if err != nil {
		pf.t.Fatal(err)
	}
	tx, err := types.NewGhostPolicyActionTx(env)
	if err != nil {
		pf.t.Fatal(err)
	}
	return tx
}

// validAction is the transaction of action on slot i.
func (pf *policyFixture) validAction(i int, tip uint64, salt byte) *types.Transaction {
	return pf.actionTx(pf.action(pf.slots[i], tip, salt))
}

// unprovenAction is a valid action on slot i but for its proof, which is
// missing.
func (pf *policyFixture) unprovenAction(i int, salt byte) *types.Transaction {
	a := pf.action(pf.slots[i], 1000, salt)
	a.Proof = nil
	return pf.actionTx(a)
}

// unprovenPolicy is a policy reveal of marker i for the next block without
// a proof.
func (pf *policyFixture) unprovenPolicy(i int) *types.Transaction {
	r := pf.nextPolicyReveal(testMarker(i))
	r.Proof = nil
	return pf.policyTx(r)
}

// unprovenCoin is a coin reveal of marker i for the next block without a
// proof.
func (pf *policyFixture) unprovenCoin(i int) *types.Transaction {
	return pf.unproven(testMarker(i), pf.windowFee(pf.next()), *pf.genesis.Header().CoinTreeRoot)
}

// slotVerifier is the stub verifier counting its proof checks and the most
// that ran at once, with its first proof checks, up to stalls of them, held
// until the test frees them.
type slotVerifier struct {
	ghostprivtest.Verifier
	calls   atomic.Int64
	running atomic.Int64
	peak    atomic.Int64
	stalls  atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newSlotVerifier(t *testing.T) *slotVerifier {
	v := &slotVerifier{entered: make(chan struct{}, 64), release: make(chan struct{})}
	t.Cleanup(v.free)
	return v
}

func (v *slotVerifier) VerifyReveal(in *ghostpriv.VerifyInputs, proof []byte) error {
	v.calls.Add(1)
	n := v.running.Add(1)
	defer v.running.Add(-1)
	for {
		old := v.peak.Load()
		if n <= old || v.peak.CompareAndSwap(old, n) {
			break
		}
	}
	if v.stalls.Add(-1) >= 0 {
		v.entered <- struct{}{}
		<-v.release
	}
	return v.Verifier.VerifyReveal(in, proof)
}

// free lets every held proof check go on, and every later one too.
func (v *slotVerifier) free() { v.once.Do(func() { close(v.release) }) }

// waitEntered waits for n held proof checks to start.
func (v *slotVerifier) waitEntered(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-v.entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d held proof checks started, want %d", i, n)
		}
	}
}

// peerState is a copy of what peer has used of its budgets, zero for a
// peer the pool does not know.
func peerState(p *Pool, peer string) peerBudget {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if b, ok := p.peers[peer]; ok {
		return *b
	}
	return peerBudget{}
}

// requireHeld fails unless the pool holds exactly want.
func requireHeld(t *testing.T, p *Pool, what string, want ...*types.Transaction) {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.all) != len(want) {
		t.Fatalf("%s: pool holds %d transactions, want %d", what, len(p.all), len(want))
	}
	for _, tx := range want {
		if _, ok := p.all[tx.Hash()]; !ok {
			t.Fatalf("%s: pool does not hold %x", what, tx.Hash())
		}
	}
}

// proofRefused reports whether err is a refusal of a checked proof.
func proofRefused(err error) bool {
	for _, target := range []error{ghostpriv.ErrRevealProof, ghostpriv.ErrDataRevealProof, ghostpriv.ErrPolicyRevealProof, ghostpriv.ErrActionProof} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// TestGhostPoolPolicyRevealAdmission checks that the pool takes the policy
// reveal 0x53: the refusals that need no proof come first, the shape, the
// chain id, the fee for G_POLICY, a spent or zero marker and the policy
// (check 9), each without a proof check; a reveal they pass has its proof
// verified once; and the reveal is held under its coin marker, one reveal a
// marker across the coin reveal of both versions and the policy reveal,
// the first seen kept.
func TestGhostPoolPolicyRevealAdmission(t *testing.T) {
	spent := testMarker(900)
	pf := newPolicyFixture(t, 0, 1, func(pf *policyFixture, i int, b *core.BlockGen) {
		// Block 2 spends a marker by an ordinary reveal.
		b.AddTx(pf.revealWithFee(spent, recipient(90), genFee(t, b, ghostpriv.GasPriv)))
	})
	pf.insert(2)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)

	valid := pf.policyTx(pf.nextPolicyReveal(testMarker(1)))
	actionEnv := make([]byte, types.GhostPolicyActionEnvelopeSize)
	actionEnv[0] = types.GhostPolicyActionTxType
	action, err := types.NewGhostPolicyActionTx(actionEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Filter(valid) || !p.Filter(action) {
		t.Fatal("the pool's filter refuses the policy reveal or the policy action")
	}

	stranger := common.HexToAddress("0x5e1f000000000000000000000000000000000001")
	with := func(i int, change func(r *ghostpriv.PolicyReveal)) *types.Transaction {
		r := pf.nextPolicyReveal(testMarker(i))
		change(r)
		pf.proveReveal(r)
		return pf.policyTx(r)
	}
	cases := []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"another version", with(10, func(r *ghostpriv.PolicyReveal) { r.Version++ }), ghostpriv.ErrPolicyRevealVersion},
		{"another chain", with(11, func(r *ghostpriv.PolicyReveal) { r.ChainID++ }), ghostpriv.ErrPolicyRevealChainID},
		{"a fee off by one", with(12, func(r *ghostpriv.PolicyReveal) { r.Fee.AddUint64(r.Fee, 1) }), ghostpriv.ErrPolicyRevealFee},
		{"the coin reveal's fee", with(13, func(r *ghostpriv.PolicyReveal) { r.Fee = pf.windowFee(pf.next()) }), ghostpriv.ErrPolicyRevealFee},
		{"a spent marker", with(14, func(r *ghostpriv.PolicyReveal) { r.Marker = spent }), ghostpriv.ErrPolicyRevealMarker},
		{"the zero marker", with(15, func(r *ghostpriv.PolicyReveal) { r.Marker = common.Hash{} }), ghostpriv.ErrPolicyRevealMarker},
		{"an unregistered policy", with(16, func(r *ghostpriv.PolicyReveal) { r.Policy = stranger }), ghostpriv.ErrPolicyRevealPolicy},
		{"another code hash", with(17, func(r *ghostpriv.PolicyReveal) { r.CodeHash = ghosttree.K("ghost/test-code", []byte("synthetic")) }), ghostpriv.ErrPolicyRevealPolicy},
	}
	for i, c := range cases {
		for _, peer := range []string{fmt.Sprintf("peer-cheap-%d", i), ""} {
			verifier.calls.Store(0)
			requireErr(t, addOne(p, peer, c.tx), c.want, c.name)
			if calls := verifier.calls.Load(); calls != 0 {
				t.Fatalf("%s: %d proofs checked, want none", c.name, calls)
			}
			if p.Has(c.tx.Hash()) {
				t.Fatalf("%s: held", c.name)
			}
		}
		if b := peerState(p, fmt.Sprintf("peer-cheap-%d", i)); b.tokens != PeerRevealsPerBlock-1 || b.failed != 0 {
			t.Fatalf("%s: peer budget %+v, want one reveal charged and no failed proof", c.name, b)
		}
	}

	// A policy reveal every other check passes has its proof checked once.
	verifier.calls.Store(0)
	requireErr(t, addOne(p, "peer-proof", pf.unprovenPolicy(20)), ghostpriv.ErrPolicyRevealProof, "policy reveal without a proof")
	if calls := verifier.calls.Load(); calls != 1 {
		t.Fatalf("policy reveal without a proof: %d proofs checked, want one", calls)
	}
	verifier.calls.Store(0)
	if err := addOne(p, "peer-a", valid); err != nil {
		t.Fatalf("valid policy reveal refused: %v", err)
	}
	if calls := verifier.calls.Load(); calls != 1 || !p.Has(valid.Hash()) {
		t.Fatalf("valid policy reveal: %d proofs checked, held %v", calls, p.Has(valid.Hash()))
	}
	requireErr(t, addOne(p, "", valid), txpool.ErrAlreadyKnown, "the same policy reveal again")

	// One reveal a coin marker: a coin reveal of either version of the
	// marker the policy reveal holds is refused before its proof.
	v2 := pf.revealWithFee(testMarker(1), recipient(1), pf.windowFee(pf.next()))
	v1r := &ghostpriv.Reveal{
		Version:   ghostpriv.RevealVersionV1,
		ChainID:   pf.chainID,
		Marker:    testMarker(1),
		Root:      *pf.genesis.Header().CoinTreeRoot,
		Remainder: ghosttree.K("ghost/test-remainder", []byte("synthetic v1")),
		Recipient: recipient(2),
		Out:       uint256.NewInt(1000),
		Fee:       pf.windowFeeGas(pf.next(), ghostpriv.GasPrivV1),
	}
	v1r.Proof = ghostprivtest.Proof(v1r.BindingDigest(pf.chainID, pf.genesis.Hash()))
	v1 := encodeReveal(t, v1r)
	verifier.calls.Store(0)
	for _, tx := range []*types.Transaction{v2, v1} {
		requireErr(t, addOne(p, "peer-b", tx), ErrMarkerPending, "coin reveal of the policy reveal's marker")
		requireErr(t, addOne(p, "", tx), ErrMarkerPending, "local coin reveal of the policy reveal's marker")
	}
	// And the other way round: a policy reveal of a marker a coin reveal of
	// either version holds is refused.
	firstV2 := pf.nextCoinReveal(30)
	if err := addOne(p, "peer-c", firstV2); err != nil {
		t.Fatalf("coin reveal refused: %v", err)
	}
	v1r2 := *v1r
	v1r2.Marker = testMarker(31)
	v1r2.Proof = ghostprivtest.Proof(v1r2.BindingDigest(pf.chainID, pf.genesis.Hash()))
	firstV1 := encodeReveal(t, &v1r2)
	if err := addOne(p, "", firstV1); err != nil {
		t.Fatalf("version 1 coin reveal refused: %v", err)
	}
	calls := verifier.calls.Load()
	for _, m := range []int{30, 31} {
		late := pf.policyTx(pf.nextPolicyReveal(testMarker(m)))
		requireErr(t, addOne(p, "peer-d", late), ErrMarkerPending, "policy reveal of a coin reveal's marker")
		requireErr(t, addOne(p, "", late), ErrMarkerPending, "local policy reveal of a coin reveal's marker")
	}
	if got := verifier.calls.Load(); got != calls {
		t.Fatalf("%d proofs checked for reveals of a held marker, want none", got-calls)
	}
	requireHeld(t, p, "first seen of each marker", valid, firstV2, firstV1)
	if b := peerState(p, "peer-b"); b.failed != 0 {
		t.Fatalf("peer of a refused competitor counted %d failed proofs", b.failed)
	}
}

// TestGhostPoolSharedLimitsAllTypes checks that the coin, data and policy
// reveals and the policy action share one peer budget of transactions per
// head, one in-flight cap of announced fetches, whose sizes for 0x53 and
// 0x54 are their envelopes', one held cap per peer, one check slot per peer
// and the check slots open to peers, and one memory of hashes refused for
// good.
func TestGhostPoolSharedLimitsAllTypes(t *testing.T) {
	pf := newPolicyFixture(t, 3, 1, nil)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)
	policy := func(i int) *types.Transaction { return pf.policyTx(pf.nextPolicyReveal(testMarker(i))) }
	dataEnv := make([]byte, types.GhostDataRevealEnvelopeSize)
	dataEnv[0] = types.GhostDataRevealTxType
	badData, err := types.NewGhostDataRevealTx(dataEnv)
	if err != nil {
		t.Fatal(err)
	}

	// One budget of transactions per head across the four types.
	coinA, policyA, actionA := pf.nextCoinReveal(1), policy(2), pf.validAction(0, 1000, 1)
	if err := addOne(p, "peer-a", coinA); err != nil {
		t.Fatalf("coin reveal refused: %v", err)
	}
	requireErr(t, addOne(p, "peer-a", badData), ghostpriv.ErrDataRevealVersion, "data reveal of version 0")
	if err := addOne(p, "peer-a", policyA); err != nil {
		t.Fatalf("policy reveal refused: %v", err)
	}
	if err := addOne(p, "peer-a", actionA); err != nil {
		t.Fatalf("policy action refused: %v", err)
	}
	requireErr(t, addOne(p, "peer-a", policy(3)), ErrPeerBudget, "policy reveal over the head's budget")
	requireErr(t, addOne(p, "peer-a", pf.validAction(1, 1000, 2)), ErrPeerBudget, "policy action over the head's budget")
	if b := peerState(p, "peer-a"); b.tokens != 0 || b.held != 3 {
		t.Fatalf("peer budget %+v, want none left and three held", b)
	}

	// One memory of refusals no head lifts, of any type: each is refused
	// again from another peer without a proof check, charged.
	unprovenPolicy, unprovenAction := pf.unprovenPolicy(4), pf.unprovenAction(1, 3)
	requireErr(t, addOne(p, "peer-c", unprovenPolicy), ghostpriv.ErrPolicyRevealProof, "policy reveal without a proof")
	requireErr(t, addOne(p, "peer-c", unprovenAction), ghostpriv.ErrActionProof, "policy action without a proof")
	calls := verifier.calls.Load()
	for _, c := range []struct {
		tx    *types.Transaction
		first error
	}{{badData, ghostpriv.ErrDataRevealVersion}, {unprovenPolicy, ghostpriv.ErrPolicyRevealProof}, {unprovenAction, ghostpriv.ErrActionProof}} {
		err := addOne(p, "peer-d", c.tx)
		requireErr(t, err, ErrRejectedBefore, "remembered refusal")
		requireErr(t, err, c.first, "remembered refusal")
	}
	if got := verifier.calls.Load(); got != calls {
		t.Fatalf("%d proofs checked for remembered refusals, want none", got-calls)
	}
	if b := peerState(p, "peer-d"); b.tokens != PeerRevealsPerBlock-3 {
		t.Fatalf("peer of three remembered refusals has %d left, want %d", b.tokens, PeerRevealsPerBlock-3)
	}

	// One announcement budget and in-flight cap: the sizes of the policy
	// reveal and the policy action are their envelopes'.
	coinE, policyE, actionE := pf.nextCoinReveal(5), policy(6), pf.validAction(1, 1000, 4)
	kinds := []byte{types.GhostRevealTxType, types.GhostDataRevealTxType, types.GhostPolicyRevealTxType, types.GhostPolicyActionTxType}
	sizes := []uint32{types.GhostRevealEnvelopeSize, types.GhostDataRevealEnvelopeSize, types.GhostPolicyRevealEnvelopeSize, types.GhostPolicyActionEnvelopeSize}
	announced := []common.Hash{coinE.Hash(), {0x51}, policyE.Hash(), actionE.Hash()}
	for i, keep := range p.FilterAnnounced("peer-e", kinds, sizes, announced) {
		if !keep {
			t.Fatalf("announced transaction %d of type %#x not fetched", i, kinds[i])
		}
	}
	if keep := p.FilterAnnounced("peer-e", kinds[3:], sizes[3:], []common.Hash{{0x54}}); keep[0] {
		t.Fatal("fifth announcement of the head fetched")
	}
	if b := peerState(p, "peer-e"); b.tokens != 0 || len(b.announced) != PeerMaxInFlight {
		t.Fatalf("announcing peer %+v, want no budget left and %d in flight", b, PeerMaxInFlight)
	}
	misSized := p.FilterAnnounced("peer-f",
		[]byte{types.GhostPolicyRevealTxType, types.GhostPolicyActionTxType, types.GhostPolicyActionTxType, types.DynamicFeeTxType},
		[]uint32{types.GhostRevealEnvelopeSize, types.GhostPolicyRevealEnvelopeSize, types.GhostPolicyActionEnvelopeSize - 1, 1000},
		[]common.Hash{{0x01}, {0x02}, {0x03}, {0x04}})
	if misSized[0] || misSized[1] || misSized[2] || !misSized[3] {
		t.Fatalf("fetch %v, want the mis-sized policy transactions dropped and the plain one kept", misSized)
	}
	p.mu.RLock()
	charged := p.peers["peer-f"] != nil && p.peers["peer-f"].tokens != PeerRevealsPerBlock
	p.mu.RUnlock()
	if charged {
		t.Fatal("mis-sized announcements were charged")
	}
	// Delivering what the node agreed to fetch costs nothing more.
	if err := addOne(p, "peer-e", policyE); err != nil {
		t.Fatalf("announced policy reveal refused: %v", err)
	}
	if err := addOne(p, "peer-e", actionE); err != nil {
		t.Fatalf("announced policy action refused: %v", err)
	}
	if b := peerState(p, "peer-e"); b.tokens != 0 || b.held != 2 || len(b.announced) != 2 {
		t.Fatalf("announcing peer after its deliveries %+v, want two held and two in flight", b)
	}

	// One held cap across the types, kept over a new head.
	old := pf.chain.CurrentBlock()
	pf.insert(5)
	pf.reset(p, old)
	for _, tx := range []*types.Transaction{coinA, policyA, actionA} {
		if !p.Has(tx.Hash()) {
			t.Fatalf("held transaction %x of type %#x dropped on the new head", tx.Hash(), tx.Type())
		}
	}
	if err := addOne(p, "peer-a", pf.nextCoinReveal(7)); err != nil {
		t.Fatalf("fourth transaction of the peer refused: %v", err)
	}
	requireErr(t, addOne(p, "peer-a", pf.validAction(2, 1000, 5)), ErrPeerBudget, "policy action over the peer's held cap")
	requireErr(t, addOne(p, "peer-a", policy(8)), ErrPeerBudget, "policy reveal over the peer's held cap")

	// One check slot per peer and one set of slots open to peers, whatever
	// the type.
	verifier.stalls.Store(maxValidations - 1)
	type result struct {
		peer string
		err  error
	}
	results := make(chan result, maxValidations)
	stuck := map[string]*types.Transaction{
		"peer-s0": pf.unprovenCoin(9),
		"peer-s1": pf.unprovenPolicy(10),
		"peer-s2": pf.unprovenAction(2, 6),
	}
	for peer, tx := range stuck {
		go func(peer string, tx *types.Transaction) {
			results <- result{peer, addOne(p, peer, tx)}
		}(peer, tx)
	}
	verifier.waitEntered(t, maxValidations-1)
	requireErr(t, addOne(p, "peer-s0", policy(11)), ErrPeerBusy, "policy reveal of a peer with a coin reveal being checked")
	requireErr(t, addOne(p, "peer-s2", pf.nextCoinReveal(12)), ErrPeerBusy, "coin reveal of a peer with an action being checked")
	lateAction := pf.validAction(2, 1000, 7)
	requireErr(t, addOne(p, "peer-s3", lateAction), ErrChecksBusy, "policy action with every peer slot taken")
	requireErr(t, addOne(p, "peer-s4", policy(13)), ErrChecksBusy, "policy reveal with every peer slot taken")
	verifier.free()
	for range stuck {
		select {
		case r := <-results:
			if !proofRefused(r.err) {
				t.Fatalf("stuck transaction of %s: %v, want its proof refused", r.peer, r.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a stuck check never finished")
		}
	}
	if len(p.remoteSlots) != 0 || len(p.validating) != 0 || len(p.actionChecks) != 0 {
		t.Fatal("a check slot was not given back")
	}
	if err := addOne(p, "peer-s3", lateAction); err != nil {
		t.Fatalf("policy action once a slot is free: %v", err)
	}
}

// TestGhostPoolActionCapsSeparate checks RP-23: the policy actions have
// their own caps, 8 actions and 7,594,984 bytes, apart from the reveals' 16
// and 20,983,216 bytes, which the coin and policy reveals share: a pool full
// of actions takes reveals, and one full of reveals takes actions.
func TestGhostPoolActionCapsSeparate(t *testing.T) {
	if MaxActions != 8 {
		t.Fatalf("action cap %d, want 8", MaxActions)
	}
	if MaxActionBytes != 7_594_984 {
		t.Fatalf("action byte cap %d, want 7,594,984", MaxActionBytes)
	}
	if MaxActionBytes != MaxActions*types.GhostPolicyActionEnvelopeSize {
		t.Fatalf("action byte cap %d is not %d action envelopes", MaxActionBytes, MaxActions)
	}
	if MaxReveals != 16 {
		t.Fatalf("reveal cap %d, want 16", MaxReveals)
	}
	if MaxBytes != 20_983_216 {
		t.Fatalf("reveal byte cap %d, want 20,983,216", MaxBytes)
	}
	if MaxBytes != MaxReveals*types.GhostPolicyRevealEnvelopeSize {
		t.Fatalf("reveal byte cap %d is not %d policy reveal envelopes", MaxBytes, MaxReveals)
	}
	pf := newPolicyFixture(t, MaxActions+1, 0, nil)
	actions := make([]*types.Transaction, MaxActions+1)
	for i := range actions {
		actions[i] = pf.validAction(i, 1000, byte(i))
	}
	// The reveal cap holds coin and policy reveals together.
	reveals := make([]*types.Transaction, MaxReveals+1)
	for i := range reveals {
		if i%4 == 3 {
			reveals[i] = pf.policyTx(pf.nextPolicyReveal(testMarker(i)))
		} else {
			reveals[i] = pf.nextCoinReveal(i)
		}
	}
	addAll := func(p *Pool, what string, txs []*types.Transaction) {
		t.Helper()
		for i, err := range p.Add(txs, true, true) {
			if err != nil {
				t.Fatalf("%s %d refused: %v", what, i, err)
			}
		}
	}

	// Actions first: once their cap is full, reveals still fill theirs.
	p := pf.newPool()
	addAll(p, "action", actions[:MaxActions])
	requireErr(t, p.Add(actions[MaxActions:], true, true)[0], ErrPoolFull, "action over the action cap")
	requireErr(t, p.AddFromPeer("peer-a", actions[MaxActions:])[0], ErrPoolFull, "action from a peer over the action cap")
	if p.actionBytes != MaxActionBytes || len(p.actions) != MaxActions {
		t.Fatalf("pool holds %d actions of %d bytes, want %d of %d", len(p.actions), p.actionBytes, MaxActions, MaxActionBytes)
	}
	addAll(p, "reveal beside a full action cap", reveals[:MaxReveals])
	requireErr(t, p.Add(reveals[MaxReveals:], true, true)[0], ErrPoolFull, "reveal over the reveal cap")
	if run, _ := p.Stats(); run != MaxActions+MaxReveals {
		t.Fatalf("pool holds %d transactions, want %d", run, MaxActions+MaxReveals)
	}

	// Reveals first: once their cap is full, actions still fill theirs.
	q := pf.newPool()
	addAll(q, "reveal", reveals[:MaxReveals])
	requireErr(t, q.Add(reveals[MaxReveals:], true, true)[0], ErrPoolFull, "reveal over the reveal cap")
	requireErr(t, q.AddFromPeer("peer-b", reveals[MaxReveals:])[0], ErrPoolFull, "reveal from a peer over the reveal cap")
	addAll(q, "action beside a full reveal cap", actions[:MaxActions])
	requireErr(t, q.Add(actions[MaxActions:], true, true)[0], ErrPoolFull, "action over the action cap")
	if run, _ := q.Stats(); run != MaxActions+MaxReveals {
		t.Fatalf("pool holds %d transactions, want %d", run, MaxActions+MaxReveals)
	}

	// Dropping an action frees a place for an action only.
	q.mu.Lock()
	q.remove(actions[0].Hash())
	q.mu.Unlock()
	requireErr(t, q.Add(reveals[MaxReveals:], true, true)[0], ErrPoolFull, "reveal after an action left")
	if err := q.Add(actions[MaxActions:], true, true)[0]; err != nil {
		t.Fatalf("action after an action left: %v", err)
	}
}

// TestGhostPoolRP22InvalidActionFloodForOneSlot checks RP-22: a flood of
// invalid actions for one slot from many peers, refused by the checks
// before the proof or by the proof, reserves nothing, and a valid action
// for the slot is admitted after it and while invalid ones for the slot are
// still being verified.
func TestGhostPoolRP22InvalidActionFloodForOneSlot(t *testing.T) {
	pf := newPolicyFixture(t, 1, 0, nil)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)
	r := pf.slots[0]
	slot := pf.slotNow(r)
	burn := actionBurn(pf.nextBaseFee())
	head := pf.chain.CurrentBlock().Number.Uint64()
	debit := new(uint256.Int).AddUint64(burn, 1000)

	// Each peer sends an action without a proof, one whose proof is for
	// other fields, and two failing the checks before the proof.
	const peers = 12
	salt := byte(0)
	invalid := func(i int) []*types.Transaction {
		next := func() []byte { salt++; return []byte{salt} }
		noProof := pf.newAction(r, slot.ActionNonce, slot.Remaining, debit, head+100, next())
		noProof.Proof = nil
		rebound := pf.newAction(r, slot.ActionNonce, slot.Remaining, debit, head+100, next())
		rebound.Debit = new(uint256.Int).AddUint64(debit, 1) // the proof is of the old debit
		cheap := []*ghostpriv.Action{
			pf.newAction(r, slot.ActionNonce+1, slot.Remaining, debit, head+100, next()),
			pf.newAction(r, slot.ActionNonce, new(uint256.Int).SubUint64(slot.Remaining, 1), debit, head+100, next()),
			pf.newAction(r, slot.ActionNonce, slot.Remaining, new(uint256.Int).SubUint64(burn, 1), head+100, next()),
			pf.newAction(r, slot.ActionNonce, slot.Remaining, debit, head, next()),
		}
		return []*types.Transaction{pf.actionTx(noProof), pf.actionTx(rebound), pf.actionTx(cheap[i%2*2]), pf.actionTx(cheap[i%2*2+1])}
	}
	for i := 0; i < peers; i++ {
		peer := fmt.Sprintf("flooder-%d", i)
		for j, err := range p.AddFromPeer(peer, invalid(i)) {
			switch {
			case j < 2 && !errors.Is(err, ghostpriv.ErrActionProof):
				t.Fatalf("flooder %d action %d: %v, want its proof refused", i, j, err)
			case j >= 2 && (err == nil || proofRefused(err)):
				t.Fatalf("flooder %d action %d: %v, want a refusal before the proof", i, j, err)
			}
		}
	}
	if calls := verifier.calls.Load(); calls != 2*peers {
		t.Fatalf("%d proofs checked, want %d: one for each action every check before the proof passed", calls, 2*peers)
	}
	p.mu.RLock()
	reserved, held, checking := len(p.actions), len(p.all), len(p.actionChecks)
	p.mu.RUnlock()
	if reserved != 0 || held != 0 || checking != 0 {
		t.Fatalf("after the flood %d keys reserved, %d held and %d checked, want none", reserved, held, checking)
	}

	// Two invalid actions for the slot are stuck in their proof check; a
	// valid one for the same slot is checked beside them and admitted.
	verifier.stalls.Store(2)
	stuck := make(chan error, 2)
	for i, tx := range []*types.Transaction{pf.unprovenAction(0, 200), pf.unprovenAction(0, 201)} {
		go func(i int, tx *types.Transaction) { stuck <- addOne(p, fmt.Sprintf("stuck-%d", i), tx) }(i, tx)
	}
	verifier.waitEntered(t, 2)
	valid := pf.validAction(0, 1000, 202)
	if err := addOne(p, "honest", valid); err != nil {
		t.Fatalf("valid action for the flooded slot refused: %v", err)
	}
	verifier.free()
	for i := 0; i < 2; i++ {
		select {
		case err := <-stuck:
			requireErr(t, err, ghostpriv.ErrActionProof, "stuck invalid action")
		case <-time.After(10 * time.Second):
			t.Fatal("a stuck check never finished")
		}
	}
	requireHeld(t, p, "after the flood", valid)
	if got := hashes(p.PendingReveals()); len(got) != 1 || got[0] != valid.Hash() {
		t.Fatalf("pending %v, want the valid action", got)
	}
}

// TestGhostPoolUnverifiedActionReservesNothing checks that a policy action
// holds no key while its proof is checked, nor after its proof failed: a
// valid action for the same marker and nonce is verified meanwhile and kept,
// being the first to finish, and the one checked before it is then refused
// without a failed proof counted.
func TestGhostPoolUnverifiedActionReservesNothing(t *testing.T) {
	pf := newPolicyFixture(t, 1, 0, nil)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)
	key := actionKey{marker: pf.slots[0].Marker, nonce: pf.slotNow(pf.slots[0]).ActionNonce}

	// A failed proof leaves no key.
	requireErr(t, addOne(p, "peer-x", pf.unprovenAction(0, 1)), ghostpriv.ErrActionProof, "action without a proof")
	p.mu.RLock()
	_, reserved := p.actions[key]
	p.mu.RUnlock()
	if reserved {
		t.Fatal("an action whose proof failed reserved its key")
	}

	// A valid action stuck in its proof check reserves no key.
	slow, fast := pf.validAction(0, 1000, 2), pf.validAction(0, 2000, 3)
	verifier.stalls.Store(1)
	done := make(chan error, 1)
	go func() { done <- addOne(p, "peer-a", slow) }()
	verifier.waitEntered(t, 1)
	p.mu.RLock()
	_, reserved = p.actions[key]
	_, checking := p.actionChecks[slow.Hash()]
	p.mu.RUnlock()
	if reserved || !checking || p.Has(slow.Hash()) {
		t.Fatalf("action being checked: key reserved %v, checked %v, held %v; want only checked", reserved, checking, p.Has(slow.Hash()))
	}
	// Another valid action for the same key is verified meanwhile and is
	// the first to finish: it is kept.
	before := verifier.calls.Load()
	if err := addOne(p, "peer-b", fast); err != nil {
		t.Fatalf("second valid action for the key while the first was checked: %v", err)
	}
	if verifier.calls.Load() != before+1 {
		t.Fatal("the second valid action was not verified")
	}
	verifier.free()
	select {
	case err := <-done:
		requireErr(t, err, ErrActionPending, "valid action that finished second")
		if errors.Is(err, ErrPeerFailLimit) || proofRefused(err) {
			t.Fatalf("action that finished second refused as a failed proof: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stuck check never finished")
	}
	requireHeld(t, p, "after both checks", fast)
	if b := peerState(p, "peer-a"); b.failed != 0 || b.held != 0 || b.validating != 0 {
		t.Fatalf("peer of the action that finished second %+v, want no failed proof", b)
	}
	if p.rejected.lookup(slow.Hash()) != nil {
		t.Fatal("the action that finished second is remembered as refused for good")
	}
}

// TestGhostPoolDuplicateActionKeyKeepsFirst checks that of two valid
// policy actions for one marker and nonce the first is kept and the second
// refused, before its proof and without penalty: no failed proof counted,
// no memory of its hash, no drop however often it comes.
func TestGhostPoolDuplicateActionKeyKeepsFirst(t *testing.T) {
	pf := newPolicyFixture(t, 1, 0, nil)
	verifier := newSlotVerifier(t)
	first, second := pf.validAction(0, 1000, 1), pf.validAction(0, 5000, 2)
	if first.Hash() == second.Hash() {
		t.Fatal("the competing actions are the same")
	}
	for _, order := range [][2]*types.Transaction{{first, second}, {second, first}} {
		p := pf.newCountedPool(pf.chain, verifier)
		if err := addOne(p, "peer-a", order[0]); err != nil {
			t.Fatalf("first action refused: %v", err)
		}
		calls := verifier.calls.Load()
		for i := 0; i < PeerRevealsPerBlock; i++ {
			err := addOne(p, "peer-b", order[1])
			requireErr(t, err, ErrActionPending, "second action for the key")
			if errors.Is(err, ErrPeerFailLimit) {
				t.Fatalf("second action for the key counted against the failed proof limit: %v", err)
			}
		}
		requireErr(t, addOne(p, "", order[1]), ErrActionPending, "local second action for the key")
		if got := verifier.calls.Load(); got != calls {
			t.Fatalf("%d proofs checked for the second action, want none", got-calls)
		}
		if b := peerState(p, "peer-b"); b.failed != 0 || b.held != 0 {
			t.Fatalf("peer of the second action %+v, want no failed proof", b)
		}
		if p.rejected.lookup(order[1].Hash()) != nil {
			t.Fatal("the second action is remembered as refused for good")
		}
		requireHeld(t, p, "after the second action", order[0])
		// Once the first is gone the second is taken: its refusal was not
		// held against it.
		p.mu.Lock()
		p.remove(order[0].Hash())
		p.mu.Unlock()
		if err := addOne(p, "", order[1]); err != nil {
			t.Fatalf("second action once the key is free: %v", err)
		}
	}
}

// TestGhostPoolActionCheapChecksBeforeProof checks that checks 1 to 8 of a
// policy action (spec 10, section 8.3) run before its proof: an action
// failing any of them, each carrying a proof that would verify, is refused
// without a proof check, from a peer or the node, and the peer is charged
// but not counted a failed proof.
func TestGhostPoolActionCheapChecksBeforeProof(t *testing.T) {
	pf := newPolicyFixture(t, 1, 0, nil)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)
	r := pf.slots[0]
	slot := pf.slotNow(r)
	burn := actionBurn(pf.nextBaseFee())
	debit := new(uint256.Int).AddUint64(burn, 1000)
	head := pf.chain.CurrentBlock().Number.Uint64()

	with := func(salt byte, change func(a *ghostpriv.Action)) *types.Transaction {
		a := pf.newAction(r, slot.ActionNonce, slot.Remaining, debit, head+100, []byte{salt})
		change(a)
		pf.proveAction(a, r)
		return pf.actionTx(a)
	}
	// edit changes the envelope of a valid action, whose proof it keeps.
	edit := func(salt byte, change func(env []byte)) *types.Transaction {
		a := pf.newAction(r, slot.ActionNonce, slot.Remaining, debit, head+100, []byte{salt})
		env, err := a.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		change(env)
		tx, err := types.NewGhostPolicyActionTx(env)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	// The envelope offsets of the policy action: the type byte, then the
	// debit word at 82, the calldata length at 122 and the calldata at 124
	// of the payload.
	const (
		envDebit    = 1 + 82
		envCallLen  = 1 + 122
		envCalldata = 1 + 124
	)
	cases := []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"1: version 2", with(1, func(a *ghostpriv.Action) { a.Version = 2 }), ghostpriv.ErrActionVersion},
		{"2: debit not below 2^96", edit(2, func(env []byte) { env[envDebit+19] = 0x01 }), ghostpriv.ErrActionEncoding},
		{"2: calldata length over the field", edit(3, func(env []byte) { env[envCallLen], env[envCallLen+1] = 0xff, 0xff }), ghostpriv.ErrActionEncoding},
		{"2: calldata field not zero past the calldata", edit(4, func(env []byte) { env[envCalldata+1] = 0x01 }), ghostpriv.ErrActionEncoding},
		{"3: another chain", with(5, func(a *ghostpriv.Action) { a.ChainID++ }), ghostpriv.ErrActionChainID},
		{"4: expired", with(6, func(a *ghostpriv.Action) { a.Expiry = head }), ghostpriv.ErrActionExpired},
		{"5: no slot", with(7, func(a *ghostpriv.Action) { a.Marker = slotMarker(99) }), ghostpriv.ErrActionSlot},
		{"6: the next nonce", with(8, func(a *ghostpriv.Action) { a.Nonce++ }), ghostpriv.ErrActionNonce},
		{"7: remaining less one", with(9, func(a *ghostpriv.Action) { a.ExpectedRemaining.SubUint64(a.ExpectedRemaining, 1) }), ghostpriv.ErrActionRemaining},
		{"8: debit below G_ACTION times the base fee", with(10, func(a *ghostpriv.Action) { a.Debit = new(uint256.Int).SubUint64(burn, 1) }), ghostpriv.ErrActionDebit},
		{"8: debit above the remaining", with(11, func(a *ghostpriv.Action) { a.Debit = new(uint256.Int).AddUint64(slot.Remaining, 1) }), ghostpriv.ErrActionDebit},
	}
	for i, c := range cases {
		peer := fmt.Sprintf("peer-%d", i)
		for _, from := range []string{peer, ""} {
			requireErr(t, addOne(p, from, c.tx), c.want, c.name)
			if calls := verifier.calls.Load(); calls != 0 {
				t.Fatalf("%s: %d proofs checked, want none", c.name, calls)
			}
		}
		if p.Has(c.tx.Hash()) {
			t.Fatalf("%s: held", c.name)
		}
		if b := peerState(p, peer); b.tokens != PeerRevealsPerBlock-1 || b.failed != 0 || b.validating != 0 {
			t.Fatalf("%s: peer budget %+v, want the action charged and no failed proof", c.name, b)
		}
	}
	if len(p.remoteSlots) != 0 || len(p.actionChecks) != 0 {
		t.Fatal("a refusal before the proof took a check slot")
	}
	// The same action, every check before the proof passed, has its proof
	// checked once.
	valid := with(12, func(*ghostpriv.Action) {})
	if err := addOne(p, "peer-valid", valid); err != nil {
		t.Fatalf("valid action refused: %v", err)
	}
	if calls := verifier.calls.Load(); calls != 1 {
		t.Fatalf("valid action: %d proofs checked, want one", calls)
	}
}

// TestGhostPoolActionRecheckOnNewHead checks that a held policy action is
// dropped after a head where its slot closed, its nonce moved, its policy
// was removed by a reorganisation, the base fee came to exceed its debit
// over G_ACTION, or its expiry passed, each on its own head while an action
// for which none holds stays; and that no held action is verified again.
func TestGhostPoolActionRecheckOnNewHead(t *testing.T) {
	// The policy the factory creates in block 11, into which block 12 opens
	// a slot.
	initCode := append([]byte{
		byte(vm.PUSH2), 0, 1,
		byte(vm.PUSH2), 0, 15,
		byte(vm.PUSH1), 0, byte(vm.CODECOPY),
		byte(vm.PUSH2), 0, 1,
		byte(vm.PUSH1), 0, byte(vm.RETURN),
	}, poolPolicyRuntime...)
	salt := common.BigToHash(common.Big1)
	latePolicy := ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode))
	lateMarker := slotMarker(50)
	var late *ghostpriv.PolicyReveal

	// Blocks 2 to 6 open slots 0 to 4; block 7 is empty; block 8 closes
	// slot 0 by an action taking all it holds; block 9 moves the nonce of
	// slot 1 by an action; block 10 holds a coin reveal, which raises the
	// base fee; block 11 creates a policy; block 12 opens a slot of it.
	pf := newPolicyFixture(t, 5, 6, func(pf *policyFixture, i int, b *core.BlockGen) {
		number := b.Number().Uint64()
		switch number {
		case 8:
			b.AddTx(pf.actionTx(pf.newAction(pf.slots[0], 0, slotOut, slotOut, number+10, nil)))
		case 9:
			debit := new(uint256.Int).AddUint64(actionBurn(b.BaseFee()), 1000)
			b.AddTx(pf.actionTx(pf.newAction(pf.slots[1], 0, slotOut, debit, number+10, nil)))
		case 10:
			b.AddTx(pf.revealWithFee(testMarker(950), recipient(95), genFee(t, b, ghostpriv.GasPriv)))
		case 11:
			factory := ghost.PolicyFactoryAddress
			b.AddTx(signAccountTransfer(pf.signer, poolKey, 1, &factory, new(big.Int), big.NewInt(1_000_000_000), big.NewInt(100_000_000_000), 500_000+accountTxExtraGas, append(salt.Bytes(), initCode...)))
		case 12:
			late = pf.policyReveal(lateMarker, latePolicy, poolPolicyCodeHash, genFee(t, b, ghostpriv.GasPolicy))
			b.AddTx(pf.policyTx(late))
		}
	})
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)
	step := func(n int) {
		t.Helper()
		old := pf.chain.CurrentBlock()
		pf.insert(n)
		pf.reset(p, old)
	}
	stateAt := func() *state.StateDB {
		t.Helper()
		st, err := pf.chain.StateAt(pf.chain.CurrentBlock().Root)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	// At head 6, for block 7.
	closing := pf.validAction(0, 1000, 1)
	moving := pf.validAction(1, 1000, 2)
	expiring := pf.actionTx(pf.newAction(pf.slots[3], 0, slotOut, new(uint256.Int).AddUint64(actionBurn(pf.nextBaseFee()), 1000), 7, []byte{3}))
	keeper := pf.validAction(4, 10_000_000_000_000_000, 4)
	for _, tx := range []*types.Transaction{closing, moving, expiring, keeper} {
		if err := addOne(p, "", tx); err != nil {
			t.Fatalf("action refused: %v", err)
		}
	}

	// Block 7: the expiry of one action passed.
	step(7)
	requireHeld(t, p, "after its expiry passed", closing, moving, keeper)

	// Block 8: the slot of one action closed.
	step(8)
	if slot, ok := ghostpriv.ReadEscrowSlot(stateAt(), pf.slots[0].Marker); !ok || slot.Open {
		t.Fatal("block 8 did not close slot 0")
	}
	requireHeld(t, p, "after its slot closed", moving, keeper)

	// Block 9: the nonce of one action moved.
	step(9)
	if slot, ok := ghostpriv.ReadEscrowSlot(stateAt(), pf.slots[1].Marker); !ok || !slot.Open || slot.ActionNonce != 1 {
		t.Fatal("block 9 did not move the nonce of slot 1")
	}
	requireHeld(t, p, "after its nonce moved", keeper)

	// Block 10: the base fee came to exceed the debit of an action paying
	// exactly G_ACTION times the base fee of block 10.
	exact := actionBurn(pf.nextBaseFee())
	underpaid := pf.actionTx(pf.newAction(pf.slots[2], 0, slotOut, exact, 1000, []byte{5}))
	if err := addOne(p, "", underpaid); err != nil {
		t.Fatalf("action paying exactly the burn refused: %v", err)
	}
	step(10)
	if !actionBurn(pf.nextBaseFee()).Gt(exact) {
		t.Fatal("block 10 did not raise the base fee")
	}
	requireHeld(t, p, "after the base fee exceeded its debit", keeper)

	// Blocks 11 and 12: a policy and a slot of it; an action on that slot.
	step(11)
	step(12)
	if height, _, ok := ghost.PolicyRegistryEntry(stateAt(), latePolicy); !ok || height != 11 {
		t.Fatalf("the factory policy is not registered at block 11: %v %d", ok, height)
	}
	onLate := pf.actionTx(pf.action(late, 1000, 6))
	if err := addOne(p, "", onLate); err != nil {
		t.Fatalf("action on the new policy's slot refused: %v", err)
	}
	requireHeld(t, p, "with the action on the new policy", keeper, onLate)

	// A reorganisation to a longer branch from block 10 without blocks 11
	// and 12 removes the policy and its slot.
	fork, _ := core.GenerateChain(pf.gspec.Config, pf.blocks[9], pf.engine, pf.db, 3, func(i int, b *core.BlockGen) {
		b.SetCoinbase(common.Address{0xbb})
	})
	old := pf.chain.CurrentBlock()
	if _, err := pf.chain.InsertChain(fork); err != nil {
		t.Fatalf("fork not imported: %v", err)
	}
	if pf.chain.CurrentBlock().Hash() != fork[2].Hash() {
		t.Fatal("the chain did not reorganise to the fork")
	}
	pf.reset(p, old)
	if _, _, ok := ghost.PolicyRegistryEntry(stateAt(), latePolicy); ok {
		t.Fatal("the reorganisation kept the factory policy")
	}
	requireHeld(t, p, "after the reorganisation removed its policy", keeper)

	// Every proof was checked once, at admission.
	if calls := verifier.calls.Load(); calls != 6 {
		t.Fatalf("%d proofs checked, want 6, one per admitted action: a held action is verified again", calls)
	}
}

// TestGhostPoolFailedProofLimit checks that the third failed proof of a
// peer on one head, of any of the pool's types, is refused with
// ErrPeerFailLimit, and so is every transaction of the peer after it on that
// head, without a check; that refusals before the proof, a second action for
// a held key and the node's own failures do not count; that the count starts
// again on a new head; and that a failed proof's hash is refused again
// without a check, and not as the limit of the peer that resends it.
func TestGhostPoolFailedProofLimit(t *testing.T) {
	pf := newPolicyFixture(t, 1, 1, nil)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)

	// Three failed proofs of three types: the third reaches the limit.
	err1 := addOne(p, "peer-x", pf.unprovenCoin(1))
	err2 := addOne(p, "peer-x", pf.unprovenPolicy(2))
	failedAction := pf.unprovenAction(0, 3)
	err3 := addOne(p, "peer-x", failedAction)
	requireErr(t, err1, ghostpriv.ErrRevealProof, "first failed proof")
	requireErr(t, err2, ghostpriv.ErrPolicyRevealProof, "second failed proof")
	if errors.Is(err1, ErrPeerFailLimit) || errors.Is(err2, ErrPeerFailLimit) {
		t.Fatalf("limit before the third failed proof: %v, %v", err1, err2)
	}
	requireErr(t, err3, ErrPeerFailLimit, "third failed proof")
	requireErr(t, err3, ghostpriv.ErrActionProof, "third failed proof")
	// The peer gets no more checks on this head, not even for a valid one.
	calls := verifier.calls.Load()
	validCoin := pf.nextCoinReveal(4)
	requireErr(t, addOne(p, "peer-x", validCoin), ErrPeerFailLimit, "valid reveal of a peer at the limit")
	if verifier.calls.Load() != calls || p.Has(validCoin.Hash()) {
		t.Fatal("a peer at the limit had a transaction checked")
	}

	// In one delivery: the third failure and every transaction after it
	// report the limit.
	batch := []*types.Transaction{pf.unprovenCoin(5), pf.unprovenPolicy(6), pf.unprovenAction(0, 7), pf.nextCoinReveal(8)}
	errs := p.AddFromPeer("peer-z", batch)
	for i, err := range errs {
		if limit := errors.Is(err, ErrPeerFailLimit); limit != (i >= 2) {
			t.Fatalf("delivery transaction %d: %v, limit %v, want %v", i, err, limit, i >= 2)
		}
	}
	if p.Has(batch[3].Hash()) {
		t.Fatal("the valid reveal after the limit is held")
	}

	// Refusals before the proof and a second action for a held key do not
	// count.
	held := pf.validAction(0, 1000, 9)
	if err := addOne(p, "", held); err != nil {
		t.Fatalf("action refused: %v", err)
	}
	wrongNonce := pf.action(pf.slots[0], 1000, 12)
	wrongNonce.Nonce++
	pf.proveAction(wrongNonce, pf.slots[0])
	cheap := []*types.Transaction{
		pf.revealWithFee(testMarker(10), recipient(10), uint256.NewInt(1)),
		pf.validAction(0, 2000, 11),
		pf.actionTx(wrongNonce),
	}
	for i, tx := range cheap {
		err := addOne(p, "peer-y", tx)
		if err == nil || proofRefused(err) || errors.Is(err, ErrPeerFailLimit) {
			t.Fatalf("cheap refusal %d: %v", i, err)
		}
	}
	if b := peerState(p, "peer-y"); b.failed != 0 {
		t.Fatalf("refusals before the proof counted %d failed proofs", b.failed)
	}
	if err := addOne(p, "peer-y", pf.nextCoinReveal(13)); err != nil {
		t.Fatalf("valid reveal after refusals before the proof: %v", err)
	}
	// The node's own failures never reach a limit.
	for i := 0; i < PeerMaxFailedProofs+1; i++ {
		err := addOne(p, "", pf.unprovenCoin(20+i))
		requireErr(t, err, ghostpriv.ErrRevealProof, "local reveal without a proof")
		if errors.Is(err, ErrPeerFailLimit) {
			t.Fatal("the node's own failures reached a limit")
		}
	}

	// A failed proof's hash is refused again without a check, from another
	// peer and from the node, and is not that peer's limit.
	calls = verifier.calls.Load()
	for _, peer := range []string{"peer-w", ""} {
		err := addOne(p, peer, failedAction)
		requireErr(t, err, ErrRejectedBefore, "failed action again")
		requireErr(t, err, ghostpriv.ErrActionProof, "failed action again")
		if errors.Is(err, ErrPeerFailLimit) {
			t.Fatalf("the resent failed action reports the limit: %v", err)
		}
	}
	if verifier.calls.Load() != calls {
		t.Fatal("a remembered failed proof was checked again")
	}
	if b := peerState(p, "peer-w"); b.failed != 0 {
		t.Fatalf("a remembered failed proof counted %d failed proofs", b.failed)
	}

	// Two failures on this head and two on the next stay under the limit.
	for i := 0; i < 2; i++ {
		requireErr(t, addOne(p, "peer-v", pf.unprovenCoin(30+i)), ghostpriv.ErrRevealProof, "failure on the first head")
	}
	old := pf.chain.CurrentBlock()
	pf.insert(3)
	pf.reset(p, old)
	for _, peer := range []string{"peer-x", "peer-z"} {
		if b := peerState(p, peer); b.failed != 0 {
			t.Fatalf("peer %s has %d failed proofs on the new head, want none", peer, b.failed)
		}
	}
	if err := addOne(p, "peer-x", pf.nextCoinReveal(40)); err != nil {
		t.Fatalf("valid reveal of the peer at the old head's limit, on the new head: %v", err)
	}
	for i, tx := range []*types.Transaction{pf.unprovenCoin(41), pf.unprovenPolicy(42)} {
		err := addOne(p, "peer-v", tx)
		if !proofRefused(err) || errors.Is(err, ErrPeerFailLimit) {
			t.Fatalf("failure %d on the new head: %v, want a failed proof under the limit", i, err)
		}
	}
	requireErr(t, addOne(p, "peer-v", pf.unprovenCoin(43)), ErrPeerFailLimit, "third failure on the new head")
}

// TestGhostPoolManyPeerFloodStaysInCheckSlots floods the pool from many
// peers with coin reveals, policy reveals and policy actions whose proofs
// fail, and checks that no more proofs are verified at once than there are
// check slots open to peers, that a peer refused a slot has nothing
// verified, that each peer holds at most one slot, and that the node's own
// action still finds its slot and is admitted.
func TestGhostPoolManyPeerFloodStaysInCheckSlots(t *testing.T) {
	pf := newPolicyFixture(t, 1, 0, nil)
	verifier := newSlotVerifier(t)
	p := pf.newCountedPool(pf.chain, verifier)
	remoteSlots := maxValidations - 1
	const peers = 12
	marker := 0
	flooded := func(i int) *types.Transaction {
		marker++
		switch i % 3 {
		case 0:
			return pf.unprovenCoin(1000 + marker)
		case 1:
			return pf.unprovenPolicy(1000 + marker)
		default:
			return pf.unprovenAction(0, byte(marker))
		}
	}
	first := make([]*types.Transaction, peers)
	for i := range first {
		first[i] = flooded(i)
	}

	// Every peer sends at once; the checks that took a slot are stuck.
	verifier.stalls.Store(int32(remoteSlots))
	results := make(chan error, peers)
	for i := 0; i < peers; i++ {
		go func(i int) { results <- addOne(p, fmt.Sprintf("peer-%d", i), first[i]) }(i)
	}
	verifier.waitEntered(t, remoteSlots)
	for i := 0; i < peers-remoteSlots; i++ {
		select {
		case err := <-results:
			requireErr(t, err, ErrChecksBusy, "flooded transaction with every peer slot taken")
		case <-time.After(10 * time.Second):
			t.Fatal("a flooded transaction waits for a slot")
		}
	}
	if calls := verifier.calls.Load(); calls != int64(remoteSlots) {
		t.Fatalf("%d proofs checked during the flood, want %d, one per slot", calls, remoteSlots)
	}
	p.mu.RLock()
	checking := 0
	for name, b := range p.peers {
		if b.validating > 1 {
			t.Errorf("peer %s holds %d check slots", name, b.validating)
		}
		checking += b.validating
	}
	p.mu.RUnlock()
	if checking != remoteSlots {
		t.Fatalf("%d checks held by peers, want %d", checking, remoteSlots)
	}

	// The node's own valid action finds the slot kept for it.
	local := pf.validAction(0, 1000, 200)
	done := make(chan error, 1)
	go func() { done <- addOne(p, "", local) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("local action refused during the flood: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("local action blocked by the flood")
	}
	if peak := verifier.peak.Load(); peak > int64(maxValidations) {
		t.Fatalf("%d proofs verified at once, want at most %d", peak, maxValidations)
	}

	verifier.free()
	for i := 0; i < remoteSlots; i++ {
		select {
		case err := <-results:
			if !proofRefused(err) {
				t.Fatalf("stuck flooded transaction: %v, want its proof refused", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a stuck check never finished")
		}
	}

	// A second flood, every peer sending its next three at once: the
	// proofs verified at once stay within the slots open to peers, and
	// only a transaction that took a slot has its proof verified.
	verifier.peak.Store(0)
	calls := verifier.calls.Load()
	second := make([][]*types.Transaction, peers)
	for i := range second {
		second[i] = []*types.Transaction{flooded(i), flooded(i + 1), flooded(i + 2)}
	}
	var wg sync.WaitGroup
	var verified atomic.Int64
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for _, err := range p.AddFromPeer(fmt.Sprintf("peer-%d", i), second[i]) {
				if proofRefused(err) {
					verified.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if peak := verifier.peak.Load(); peak > int64(remoteSlots) {
		t.Fatalf("%d proofs verified at once in the peers' flood, want at most %d", peak, remoteSlots)
	}
	if got := verifier.calls.Load() - calls; got != verified.Load() {
		t.Fatalf("%d proofs verified for %d transactions refused by their proof", got, verified.Load())
	}
	if len(p.remoteSlots) != 0 || len(p.localSlot) != 0 || len(p.validating) != 0 || len(p.actionChecks) != 0 {
		t.Fatal("a check slot was not given back")
	}
	requireHeld(t, p, "after the floods", local)
}

// TestGhostPoolPendingOrderByTipPerGas checks the block order of the held
// transactions: the highest tip per gas first, compared as exact fractions,
// then by hash. An action whose tip is below a reveal's but whose tip per
// gas is above comes first, and of two actions whose tips per gas differ by
// less than a wei the higher comes first whatever their hashes.
func TestGhostPoolPendingOrderByTipPerGas(t *testing.T) {
	pf := newPolicyFixture(t, 3, 0, nil)
	p := pf.newPool()
	next := pf.next()
	baseFee := pf.nextBaseFee()
	start := ghostpriv.WindowStart(uint64(next))
	if start == 0 || uint64(next) == start {
		t.Fatalf("block %d does not have a fee window before its own", next)
	}
	curRef := pf.headerAt(int(start)).BaseFee
	prevRef := pf.headerAt(int(start) - 4).BaseFee
	fee := func(bRef *big.Int, gas uint64) ghostpriv.Fee {
		f, err := ghostpriv.WindowFeeGas(bRef, gas)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	tipOf := func(f ghostpriv.Fee, gas uint64) *big.Int {
		split, err := f.CoverGas(baseFee, gas)
		if err != nil {
			t.Fatal(err)
		}
		return split.Tip.ToBig()
	}

	type item struct {
		tx  *types.Transaction
		tip *big.Int
		gas uint64
	}
	var items []item
	add := func(tx *types.Transaction, tip *big.Int, gas uint64) {
		t.Helper()
		if err := p.Add([]*types.Transaction{tx}, true, true)[0]; err != nil {
			t.Fatalf("transaction of type %#x refused: %v", tx.Type(), err)
		}
		items = append(items, item{tx, tip, gas})
	}

	// Coin reveals at the window's fee, two of them, and at the previous
	// window's fee; a policy reveal at its window fee.
	curCoin, prevCoin, curPolicy := fee(curRef, ghostpriv.GasPriv), fee(prevRef, ghostpriv.GasPriv), fee(curRef, ghostpriv.GasPolicy)
	add(pf.revealWithFee(testMarker(1), recipient(1), curCoin.Total), tipOf(curCoin, ghostpriv.GasPriv), ghostpriv.GasPriv)
	add(pf.revealWithFee(testMarker(2), recipient(2), curCoin.Total), tipOf(curCoin, ghostpriv.GasPriv), ghostpriv.GasPriv)
	prevTip := tipOf(prevCoin, ghostpriv.GasPriv)
	prevReveal := pf.revealWithFee(testMarker(3), recipient(3), prevCoin.Total)
	add(prevReveal, prevTip, ghostpriv.GasPriv)
	add(pf.policyTx(pf.nextPolicyReveal(testMarker(4))), tipOf(curPolicy, ghostpriv.GasPolicy), ghostpriv.GasPolicy)

	// An action whose tip is below the previous-fee reveal's, but whose tip
	// per gas is just above it.
	gasA, gasR := new(big.Int).SetUint64(ghostpriv.GasAction), new(big.Int).SetUint64(ghostpriv.GasPriv)
	topTip := new(big.Int).Div(new(big.Int).Mul(prevTip, gasA), gasR)
	topTip.Add(topTip, common.Big1)
	if topTip.Cmp(prevTip) >= 0 {
		t.Fatalf("the action's tip %v is not below the reveal's %v", topTip, prevTip)
	}
	burn := actionBurn(baseFee)
	actionWithTip := func(slot int, tip *big.Int, calldata []byte) *types.Transaction {
		debit := new(uint256.Int).Add(burn, uint256.MustFromBig(tip))
		s := pf.slotNow(pf.slots[slot])
		return pf.actionTx(pf.newAction(pf.slots[slot], s.ActionNonce, s.Remaining, debit, uint64(next)+100, calldata))
	}
	top := actionWithTip(0, topTip, []byte{1})
	add(top, topTip, ghostpriv.GasAction)

	// Two actions whose tips per gas differ by one wei over G_ACTION: the
	// one paying more has the higher hash, so that the hash order says
	// otherwise.
	low := big.NewInt(1_000_003)
	higher := actionWithTip(2, new(big.Int).Add(low, common.Big1), []byte{2})
	var lower *types.Transaction
	for i := 0; ; i++ {
		lower = actionWithTip(1, low, []byte{3, byte(i)})
		if bytes.Compare(lower.Hash().Bytes(), higher.Hash().Bytes()) < 0 {
			break
		}
	}
	add(lower, low, ghostpriv.GasAction)
	add(higher, new(big.Int).Add(low, common.Big1), ghostpriv.GasAction)

	// The order: by tip per gas as fractions, then by hash.
	sort.Slice(items, func(i, j int) bool {
		l := new(big.Int).Mul(items[i].tip, new(big.Int).SetUint64(items[j].gas))
		r := new(big.Int).Mul(items[j].tip, new(big.Int).SetUint64(items[i].gas))
		if c := l.Cmp(r); c != 0 {
			return c > 0
		}
		return bytes.Compare(items[i].tx.Hash().Bytes(), items[j].tx.Hash().Bytes()) < 0
	})
	got := hashes(p.PendingReveals())
	if len(got) != len(items) {
		t.Fatalf("%d pending, want %d", len(got), len(items))
	}
	for i, it := range items {
		if got[i] != it.tx.Hash() {
			t.Fatalf("pending %d is %x, want %x of type %#x", i, got[i], it.tx.Hash(), it.tx.Type())
		}
	}
	index := make(map[common.Hash]int)
	for i, h := range got {
		index[h] = i
	}
	if index[top.Hash()] != 0 || index[top.Hash()] > index[prevReveal.Hash()] {
		t.Fatal("the action of the highest tip per gas is not first")
	}
	if index[higher.Hash()] > index[lower.Hash()] {
		t.Fatal("of two actions a wei over G_ACTION apart, the lower comes first")
	}
	if index[lower.Hash()] != len(got)-1 {
		t.Fatal("the action of the lowest tip per gas is not last")
	}
}
