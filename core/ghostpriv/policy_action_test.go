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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

// The frozen policies of the action tests, in the genesis and registered at
// height 0. A and B forward their calldata to the escrow natives at 0x60 and
// return the success flag and the native's return data; R does the same and
// then reverts.
var (
	actionPolicyA = common.HexToAddress("0x9a11c1e5000000000000000000000000000ac7a1")
	actionPolicyB = common.HexToAddress("0x9a11c1e5000000000000000000000000000ac7b1")
	actionPolicyR = common.HexToAddress("0x9a11c1e5000000000000000000000000000ac7f1")
)

// forwarderPolicyCode calls 0x60 with its calldata by CALL and returns, or
// with revertAfter reverts with, the success flag as a word and the native's
// return data. It uses no opcode a frozen context forbids.
func forwarderPolicyCode(revertAfter bool) []byte {
	end := vm.RETURN
	if revertAfter {
		end = vm.REVERT
	}
	return []byte{
		byte(vm.CALLDATASIZE), byte(vm.PUSH1), 0, byte(vm.PUSH2), 0x01, 0x00, byte(vm.CALLDATACOPY),
		byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.CALLDATASIZE), byte(vm.PUSH2), 0x01, 0x00, byte(vm.PUSH1), 0,
		byte(vm.PUSH1), 0x60, byte(vm.PUSH4), 0xff, 0xff, 0xff, 0xff, byte(vm.CALL),
		byte(vm.PUSH1), 0, byte(vm.MSTORE),
		byte(vm.RETURNDATASIZE), byte(vm.PUSH1), 0, byte(vm.PUSH1), 32, byte(vm.RETURNDATACOPY),
		byte(vm.RETURNDATASIZE), byte(vm.PUSH1), 32, byte(vm.ADD), byte(vm.PUSH1), 0, byte(end),
	}
}

func actionPolicyCode(p common.Address) []byte { return forwarderPolicyCode(p == actionPolicyR) }

// actionAlloc is the genesis allocation of the three policies.
func actionAlloc() genesisT.GenesisAlloc {
	alloc := genesisT.GenesisAlloc{}
	for _, p := range []common.Address{actionPolicyA, actionPolicyB, actionPolicyR} {
		code := actionPolicyCode(p)
		alloc[p] = genesisT.GenesisAccount{Code: code, Balance: new(big.Int)}
		ghost.RegisterPolicy(allocRegistry{alloc}, p, 0, crypto.Keccak256Hash(code))
	}
	return alloc
}

func actionCoin(p common.Address) coin { return testCoin("action "+p.Hex(), oneGhost) }

func actionMarker(p common.Address) common.Hash { return testMarker("action " + p.Hex()) }

// actionOut is the value each test slot opens with.
func actionOut() *uint256.Int { return u256(ghostAmount(1, 2)) }

// The inputs of the escrow natives.
func nativeSlotIn(m common.Hash) []byte {
	return append(common.CopyBytes(vm.EscrowSlotSelector[:]), m[:]...)
}

func nativeCloseIn(m common.Hash) []byte {
	return append(common.CopyBytes(vm.EscrowCloseSelector[:]), m[:]...)
}

func nativePayIn(m common.Hash, dest common.Address, amount uint64) []byte {
	in := append(common.CopyBytes(vm.EscrowPaySelector[:]), m[:]...)
	in = append(in, common.LeftPadBytes(dest[:], 32)...)
	return append(in, word(amount)...)
}

func nativeRecommitIn(m, f common.Hash, amount uint64, note []byte) []byte {
	in := append(common.CopyBytes(vm.EscrowRecommitSelector[:]), m[:]...)
	in = append(in, f[:]...)
	in = append(in, make([]byte, 32)...) // a zero salt
	in = append(in, word(amount)...)
	in = append(in, word(0xa0)...)
	in = append(in, word(uint64(len(note)))...)
	padded := make([]byte, (len(note)+31)/32*32)
	copy(padded, note)
	return append(in, padded...)
}

// genActionBlocks builds n blocks on the genesis of f: block 1 commits one
// coin for each policy, blocks 3 on open the slot of each policy in turn with
// out actionOut, one policy reveal a block, and extra, if any, fills each
// block after the last of them. It returns the blocks and the policy reveals by policy.
func genActionBlocks(t *testing.T, f *fixture, policies []common.Address, n int, extra func(i int, b *core.BlockGen, reveals map[common.Address]*ghostpriv.PolicyReveal)) ([]*types.Block, map[common.Address]*ghostpriv.PolicyReveal) {
	t.Helper()
	keys := []*mldsa44.PrivateKey{keyA, keyB, keyC}
	if len(policies) > len(keys) {
		t.Fatal("too many policies")
	}
	reveals := make(map[common.Address]*ghostpriv.PolicyReveal)
	blocks, _ := f.generate(n, func(i int, b *core.BlockGen) {
		switch {
		case i == 0:
			for k, p := range policies {
				b.AddTx(f.commitTx(keys[k], 0, actionCoin(p)))
			}
		case i >= 2 && i-2 < len(policies):
			p := policies[i-2]
			fee := genWindowFeeGas(t, b, ghostpriv.GasPolicy).Total
			r := f.newPolicyReveal(genParentRoot(b), actionMarker(p), p, crypto.Keccak256Hash(actionPolicyCode(p)), actionOut(), fee)
			reveals[p] = r
			b.AddTx(policyRevealTx(t, r))
		case i >= 2+len(policies) && extra != nil:
			extra(i, b, reveals)
		}
	})
	return blocks, reveals
}

// slotOfReveal is the part of a slot an action's binding reads, from the
// policy reveal that opened it.
func slotOfReveal(r *ghostpriv.PolicyReveal) *ghostpriv.EscrowSlot {
	return &ghostpriv.EscrowSlot{Policy: r.Policy, ParamsHash: r.ParamsHash, ActionTag: r.ActionTag, ActionSalt: r.ActionSalt, Instr: r.Instr}
}

// newAction is an action on the slot r opened, with the stub proof of its
// binding digest on the chain of f.
func (f *fixture) newAction(r *ghostpriv.PolicyReveal, nonce uint64, expected, debit *uint256.Int, expiry uint64, calldata []byte) *ghostpriv.Action {
	a := &ghostpriv.Action{
		Version:           ghostpriv.PolicyActionVersion,
		ChainID:           f.chainID,
		Marker:            r.Marker,
		Nonce:             nonce,
		ExpectedRemaining: new(uint256.Int).Set(expected),
		Debit:             new(uint256.Int).Set(debit),
		Expiry:            expiry,
		Calldata:          common.CopyBytes(calldata),
	}
	f.proveAction(a, r)
	return a
}

func (f *fixture) proveAction(a *ghostpriv.Action, r *ghostpriv.PolicyReveal) {
	a.Proof = ghostprivtest.ActionProof(a.BindingDigest(f.chainID, f.genesis.Hash(), slotOfReveal(r)))
}

func actionEnvelope(t *testing.T, a *ghostpriv.Action) []byte {
	t.Helper()
	env, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func actionTx(t *testing.T, a *ghostpriv.Action) *types.Transaction {
	t.Helper()
	tx, err := types.NewGhostPolicyActionTx(actionEnvelope(t, a))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// actionBurn is G_ACTION times a base fee.
func actionBurn(baseFee *big.Int) *uint256.Int {
	return new(uint256.Int).Mul(uint256.NewInt(ghostpriv.GasAction), u256(baseFee))
}

// actionTip is the tip the actions of these tests pay above the burn.
var actionTip = uint256.NewInt(123_456_789)

// actionDebit is the burn of a block with base fee baseFee and actionTip.
func actionDebit(baseFee *big.Int) *uint256.Int {
	return new(uint256.Int).Add(actionBurn(baseFee), actionTip)
}

// actionScenario is a chain whose blocks open one slot for each policy, all
// imported, and the environment and state of the block after them.
type actionScenario struct {
	f       *fixture
	chain   *core.BlockChain
	blocks  []*types.Block
	reveals map[common.Address]*ghostpriv.PolicyReveal
	env     *ghostpriv.BlockEnv
	st      *state.StateDB
	miner   common.Address
}

func newActionScenario(t *testing.T, policies ...common.Address) *actionScenario {
	t.Helper()
	f := newFixture(t, ghost.InternalNetGasLimit, actionAlloc())
	n := 2 + len(policies)
	blocks, reveals := genActionBlocks(t, f, policies, n, nil)
	chain := f.newChain()
	f.insert(chain, blocks)
	miner := common.Address{0xcb, 0x54}
	env, st := nextEnv(t, chain, blocks[n-1].Header(), miner)
	return &actionScenario{f: f, chain: chain, blocks: blocks, reveals: reveals, env: env, st: st, miner: miner}
}

func (s *actionScenario) height() uint64 { return s.env.Header.Number.Uint64() }

func (s *actionScenario) slot(t *testing.T, p common.Address) *ghostpriv.EscrowSlot {
	t.Helper()
	slot, ok := ghostpriv.ReadEscrowSlot(s.st, actionMarker(p))
	if !ok {
		t.Fatalf("no slot of %v", p)
	}
	return slot
}

// next is a valid action on the slot of p in the next block, at the slot's
// nonce and remaining, with the debit of actionDebit.
func (s *actionScenario) next(t *testing.T, p common.Address, calldata []byte) *ghostpriv.Action {
	slot := s.slot(t, p)
	return s.f.newAction(s.reveals[p], slot.ActionNonce, slot.Remaining, actionDebit(s.env.Header.BaseFee), s.height()+5, calldata)
}

// apply runs an action through core.ApplyPolicyAction on the scenario's
// state with gp, the gas pool of the block.
func (s *actionScenario) apply(t *testing.T, a *ghostpriv.Action, gp *core.GasPool, cfg vm.Config) (*types.Receipt, uint64, error) {
	t.Helper()
	tx := actionTx(t, a)
	s.st.SetTxContext(tx.Hash(), 0)
	var used uint64
	r, err := core.ApplyPolicyAction(s.chain.Config(), s.chain, gp, s.st, s.env.Header, s.f.genesis.Hash(), common.Hash{}, tx, &used, cfg)
	return r, used, err
}

func (s *actionScenario) fingerprint() string {
	return fmt.Sprintf("%x %d", s.st.Copy().IntermediateRoot(true), len(s.st.Logs()))
}

// actionResult is the action-result log of a receipt.
type actionResult struct {
	nonce   uint64
	debit   *uint256.Int
	success bool
	gasUsed uint64
	retHash common.Hash
}

func resultOf(t *testing.T, logs []*types.Log, marker common.Hash) actionResult {
	t.Helper()
	var found []*types.Log
	for _, l := range logs {
		if l.Address == ghost.EscrowAccount && len(l.Topics) == 2 && l.Topics[0] == ghosttree.K(ghostpriv.TagActionResult) {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d action-result logs", len(found))
	}
	l := found[0]
	if l.Topics[1] != marker || len(l.Data) != 160 {
		t.Fatalf("action-result log: marker %x, %d bytes", l.Topics[1], len(l.Data))
	}
	if !bytes.Equal(l.Data[:24], make([]byte, 24)) || !bytes.Equal(l.Data[64:95], make([]byte, 31)) || !bytes.Equal(l.Data[96:120], make([]byte, 24)) {
		t.Fatal("action-result words are not right-aligned")
	}
	return actionResult{
		nonce:   binary.BigEndian.Uint64(l.Data[24:32]),
		debit:   new(uint256.Int).SetBytes(l.Data[32:64]),
		success: l.Data[95] == 1,
		gasUsed: binary.BigEndian.Uint64(l.Data[120:128]),
		retHash: common.BytesToHash(l.Data[128:160]),
	}
}

// failedNativeReturn is what a forwarder policy returns when the native
// fails: the success flag 0 and no return data.
var failedNativeReturn = ghostpriv.ActionReturnHash(make([]byte, 32))

// TestPolicyActionRP12CrossPolicy checks RP-12 by an action: an action on
// policy A's slot whose call asks the natives to read, pay, recommit or
// close policy B's slot is admitted and takes its debit from A's slot, but
// the native refuses each and B's slot does not change. The action context
// is A's: actionMarker answers A's marker. An action on B's own slot pays
// from it.
func TestPolicyActionRP12CrossPolicy(t *testing.T) {
	useStub(t)
	s := newActionScenario(t, actionPolicyA, actionPolicyB)
	markerB := actionMarker(actionPolicyB)
	dest := common.Address{0xde, 0x12}
	wordsB := slotWords(s.st, markerB)
	for k, calldata := range [][]byte{
		nativeSlotIn(markerB),
		nativePayIn(markerB, dest, 1000),
		nativeRecommitIn(markerB, common.Hash{0x12}, 1000, testNote(0x12)),
		nativeCloseIn(markerB),
	} {
		before := s.slot(t, actionPolicyA)
		a := s.next(t, actionPolicyA, calldata)
		gp := new(core.GasPool).AddGas(ghostpriv.GasAction)
		receipt, _, err := s.apply(t, a, gp, vm.Config{})
		if err != nil {
			t.Fatalf("action %d on A's slot refused: %v", k, err)
		}
		res := resultOf(t, receipt.Logs, actionMarker(actionPolicyA))
		if !res.success || res.retHash != failedNativeReturn || res.nonce != uint64(k) {
			t.Errorf("action %d: result %+v, want the native refused", k, res)
		}
		if slotWords(s.st, markerB) != wordsB {
			t.Fatalf("action %d on A's slot changed B's slot", k)
		}
		after := s.slot(t, actionPolicyA)
		if want := new(uint256.Int).Sub(before.Remaining, a.Debit); !after.Remaining.Eq(want) || after.ActionNonce != before.ActionNonce+1 {
			t.Fatalf("action %d: A's slot remaining %v nonce %d", k, after.Remaining, after.ActionNonce)
		}
		if !s.st.GetBalance(dest).IsZero() {
			t.Fatal("B's slot paid out")
		}
	}
	// The action context is A's.
	a := s.next(t, actionPolicyA, vm.ActionMarkerSelector[:])
	receipt, _, err := s.apply(t, a, new(core.GasPool).AddGas(ghostpriv.GasAction), vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	markerA := actionMarker(actionPolicyA)
	if res := resultOf(t, receipt.Logs, markerA); res.retHash != ghostpriv.ActionReturnHash(append(word(1), markerA[:]...)) {
		t.Fatal("actionMarker in A's action does not answer A's marker")
	}
	// B pays from its own slot through its own action.
	a = s.next(t, actionPolicyB, nativePayIn(markerB, dest, 1000))
	if _, _, err := s.apply(t, a, new(core.GasPool).AddGas(ghostpriv.GasAction), vm.Config{}); err != nil {
		t.Fatal(err)
	}
	if slot := s.slot(t, actionPolicyB); !slot.Paid.Eq(uint256.NewInt(1000)) || !s.st.GetBalance(dest).Eq(uint256.NewInt(1000)) {
		t.Fatalf("B's own action did not pay: %+v", slot)
	}
	// An action for B's slot cannot be proven with A's binding: the stub
	// proof of A's slot fields fails B's.
	a = s.next(t, actionPolicyB, nil)
	a.Proof = ghostprivtest.ActionProof(a.BindingDigest(s.f.chainID, s.f.genesis.Hash(), slotOfReveal(s.reveals[actionPolicyA])))
	if _, _, err := ghostpriv.CheckAction(s.st, s.env, stub, actionEnvelope(t, a)); !errors.Is(err, ghostpriv.ErrActionProof) {
		t.Fatalf("an action on B's slot bound to A's fields: %v, want %v", err, ghostpriv.ErrActionProof)
	}
}

// Envelope offsets of the action fields, for tampering.
const (
	envActionVersion  = 1
	envActionChainID  = 3
	envActionExpected = 51
	envActionDebit    = 83
	envActionCallLen  = 123
	envActionCalldata = 125
)

// TestPolicyActionCheckOrder gives the block after the slot opens an action
// that fails each of checks 1 to 10 of spec 10, section 8.3, in turn, and
// where it can a later one too: the first failing check is the one
// reported, nothing changes, and the verifier is called zero times for every
// check before 10. A valid action passes with one call of the verifier, with
// the inputs the node computed, and its debit split into the burn of
// G_ACTION times the base fee and the tip. The default verifier of a build
// without the proof verifier refuses it at check 10.
func TestPolicyActionCheckOrder(t *testing.T) {
	useStub(t)
	s := newActionScenario(t, actionPolicyA)
	p := actionPolicyA
	r := s.reveals[p]
	out := actionOut()
	height := s.height()
	debit := actionDebit(s.env.Header.BaseFee)
	burn := actionBurn(s.env.Header.BaseFee)
	calldata := nativeSlotIn(r.Marker)
	valid := func() *ghostpriv.Action { return s.f.newAction(r, 0, out, debit, height, calldata) }
	with := func(change func(a *ghostpriv.Action), prove bool) []byte {
		a := valid()
		change(a)
		if prove {
			s.f.proveAction(a, r)
		}
		return actionEnvelope(t, a)
	}
	tamper := func(change func(env []byte)) []byte {
		env := actionEnvelope(t, valid())
		change(env)
		return env
	}
	closed := s.st.Copy()
	if err := ghostpriv.CloseEscrowSlot(closed, height, p, r.Marker); err != nil {
		t.Fatal(err)
	}
	unknown := testMarker("no such slot")
	tests := []struct {
		name string
		env  []byte
		st   *state.StateDB
		want error
	}{
		{"1: short", tamper(func(env []byte) {})[:types.GhostPolicyActionEnvelopeSize-1], nil, ghostpriv.ErrActionLength},
		{"1: type 0x53", tamper(func(env []byte) { env[0] = types.GhostPolicyRevealTxType }), nil, ghostpriv.ErrActionLength},
		{"1: version 2, wrong chain", tamper(func(env []byte) { env[envActionVersion+1] = 2; env[envActionChainID] ^= 1 }), nil, ghostpriv.ErrActionVersion},
		{"2: debit of 2^96, wrong chain", tamper(func(env []byte) { env[envActionDebit+19] = 1; env[envActionChainID] ^= 1 }), nil, ghostpriv.ErrActionEncoding},
		{"2: expected remaining of 2^160", tamper(func(env []byte) { env[envActionExpected] = 1 }), nil, ghostpriv.ErrActionEncoding},
		{"2: calldata longer than its field", tamper(func(env []byte) { binary.BigEndian.PutUint16(env[envActionCallLen:], ghostpriv.ActionCalldataSize+1) }), nil, ghostpriv.ErrActionEncoding},
		{"2: calldata padding", tamper(func(env []byte) { env[envActionCalldata+len(calldata)] = 1 }), nil, ghostpriv.ErrActionEncoding},
		{"3: chain id, expired", with(func(a *ghostpriv.Action) { a.ChainID++; a.Expiry = height - 1 }, true), nil, ghostpriv.ErrActionChainID},
		{"4: expired, wrong nonce", with(func(a *ghostpriv.Action) { a.Expiry = height - 1; a.Nonce = 9 }, true), nil, ghostpriv.ErrActionExpired},
		{"5: no slot, wrong nonce", with(func(a *ghostpriv.Action) { a.Marker = unknown; a.Nonce = 9 }, true), nil, ghostpriv.ErrActionSlot},
		{"5: closed slot", with(func(a *ghostpriv.Action) {}, true), closed, ghostpriv.ErrActionSlot},
		{"6: nonce, wrong expected remaining", with(func(a *ghostpriv.Action) { a.Nonce = 1; a.ExpectedRemaining = uint256.NewInt(1) }, true), nil, ghostpriv.ErrActionNonce},
		{"7: expected remaining, low debit", with(func(a *ghostpriv.Action) {
			a.ExpectedRemaining = new(uint256.Int).AddUint64(out, 1)
			a.Debit = uint256.NewInt(1)
		}, true), nil, ghostpriv.ErrActionRemaining},
		{"8: debit one below G_ACTION times the base fee", with(func(a *ghostpriv.Action) { a.Debit = new(uint256.Int).SubUint64(burn, 1) }, true), nil, ghostpriv.ErrActionDebit},
		{"8: debit above remaining", with(func(a *ghostpriv.Action) { a.Debit = new(uint256.Int).AddUint64(out, 1) }, true), nil, ghostpriv.ErrActionDebit},
		{"10: proof of other calldata", with(func(a *ghostpriv.Action) { a.Calldata = nativeCloseIn(r.Marker) }, false), nil, ghostpriv.ErrActionProof},
		{"10: proof of another debit", with(func(a *ghostpriv.Action) { a.Debit = new(uint256.Int).AddUint64(debit, 1) }, false), nil, ghostpriv.ErrActionProof},
		{"10: no proof", with(func(a *ghostpriv.Action) { a.Proof = nil }, false), nil, ghostpriv.ErrActionProof},
	}
	for _, tt := range tests {
		st := tt.st
		if st == nil {
			st = s.st
		}
		before := fmt.Sprintf("%x %d", st.Copy().IntermediateRoot(true), len(st.Logs()))
		v := new(countingVerifier)
		_, _, err := ghostpriv.CheckAction(st, s.env, v, tt.env)
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: error %v, want %v", tt.name, err, tt.want)
		}
		wantCalls := 0
		if tt.want == ghostpriv.ErrActionProof {
			wantCalls = 1
		}
		if v.calls != wantCalls {
			t.Errorf("%s: verifier called %d times, want %d", tt.name, v.calls, wantCalls)
		}
		if after := fmt.Sprintf("%x %d", st.Copy().IntermediateRoot(true), len(st.Logs())); after != before {
			t.Errorf("%s: the check changed the state", tt.name)
		}
	}

	// The valid action, at the last height of its expiry.
	v := new(countingVerifier)
	a, fee, err := ghostpriv.CheckAction(s.st, s.env, v, actionEnvelope(t, valid()))
	if err != nil {
		t.Fatalf("valid action: %v", err)
	}
	if v.calls != 1 || !bytes.Equal(a.Calldata, calldata) {
		t.Fatalf("valid action: %d calls", v.calls)
	}
	in := v.last
	slot := s.slot(t, p)
	if ghostpriv.PurposeAction != 0x06 {
		t.Fatalf("action purpose %#x", ghostpriv.PurposeAction)
	}
	if in.Kind != ghosttree.Coin || in.Purpose != ghostpriv.PurposeAction || in.Marker != r.Marker || in.Policy != p ||
		in.ActionTag != slot.ActionTag || in.ActionSalt != slot.ActionSalt || in.ParamsHash != slot.ParamsHash || in.Instr != slot.Instr ||
		in.ActionNonce != 0 || !in.ExpectedRemaining.Eq(out) || !in.Debit.Eq(debit) || in.Expiry != height ||
		in.CalldataHash != ghostpriv.ActionCalldataHash(calldata) || in.Binding != a.BindingDigest(s.f.chainID, s.f.genesis.Hash(), slot) {
		t.Fatalf("verifier inputs %+v", in)
	}
	if len(a.BindingInput(s.f.chainID, s.f.genesis.Hash(), slot)) != ghostpriv.ActionBindingSize || ghostpriv.ActionBindingSize != 273 {
		t.Fatal("binding input size")
	}
	if !fee.Burn.Eq(burn) || !fee.Tip.Eq(actionTip) || !fee.Total.Eq(debit) || !new(uint256.Int).Add(fee.Burn, fee.Tip).Eq(debit) {
		t.Fatalf("fee split %+v, burn %v", fee, burn)
	}
	// A debit of exactly the burn and one of the whole remaining pass.
	for _, d := range []*uint256.Int{burn, out} {
		if _, _, err := ghostpriv.CheckAction(s.st, s.env, stub, actionEnvelope(t, s.f.newAction(r, 0, out, d, height, nil))); err != nil {
			t.Errorf("debit %v: %v", d, err)
		}
	}
	// The stub of a reveal-sized proof never verifies an action.
	reveal := s.f.newAction(r, 0, out, debit, height, nil)
	if err := stub.VerifyReveal(reveal.VerifyInputs(s.f.chainID, s.f.genesis.Hash(), slot), ghostprivtest.Proof(reveal.BindingDigest(s.f.chainID, s.f.genesis.Hash(), slot))); err == nil {
		t.Fatal("the stub verifier takes a reveal-sized action proof")
	}
	// Decode, encode round trip.
	env := actionEnvelope(t, valid())
	dec, err := ghostpriv.DecodeAction(env)
	if err != nil {
		t.Fatal(err)
	}
	if again := actionEnvelope(t, dec); !bytes.Equal(again, env) || len(env) != types.GhostPolicyActionEnvelopeSize {
		t.Fatal("decode and encode do not round trip")
	}
	// A build without the proof verifier refuses the action at the proof.
	useDefault(t)
	if _, _, err := ghostpriv.CheckAction(s.st, s.env, ghostpriv.ActiveVerifier(), env); !errors.Is(err, ghostpriv.ErrActionProof) {
		t.Fatalf("the default verifier: %v, want %v", err, ghostpriv.ErrActionProof)
	}
}

// TestPolicyActionRP18DebitBurnTip checks RP-18 on a chain: an admitted
// action lowers remaining by exactly its debit, which action_debits and the
// fall of total_escrow match; G_ACTION times the base fee of the block is
// burned and the rest of the debit is the coinbase's tip; the nonce rises by
// one; the block's gas used and the receipt are G_ACTION.
func TestPolicyActionRP18DebitBurnTip(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, actionAlloc())
	miner := common.Address{0xcb, 0x18}
	var (
		debit *uint256.Int
		tx    *types.Transaction
	)
	blocks, reveals := genActionBlocks(t, f, []common.Address{actionPolicyA}, 4, func(i int, b *core.BlockGen, reveals map[common.Address]*ghostpriv.PolicyReveal) {
		b.SetCoinbase(miner)
		debit = actionDebit(b.BaseFee())
		r := reveals[actionPolicyA]
		tx = actionTx(t, f.newAction(r, 0, actionOut(), debit, b.Number().Uint64(), nativeSlotIn(r.Marker)))
		b.AddTx(tx)
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	block := chain.GetBlockByNumber(4)
	if len(block.Transactions()) != 1 || block.GasUsed() != ghostpriv.GasAction {
		t.Fatalf("block 4 gas used %d", block.GasUsed())
	}
	before, err := chain.StateAt(blocks[2].Root())
	if err != nil {
		t.Fatal(err)
	}
	after, err := chain.StateAt(block.Root())
	if err != nil {
		t.Fatal(err)
	}
	marker := reveals[actionPolicyA].Marker
	s0, _ := ghostpriv.ReadEscrowSlot(before, marker)
	s1, _ := ghostpriv.ReadEscrowSlot(after, marker)
	if want := new(uint256.Int).Sub(s0.Remaining, debit); !s1.Remaining.Eq(want) || !s1.ActionDebits.Eq(debit) || s1.ActionNonce != 1 || !s1.Open || !s1.Balanced() {
		t.Fatalf("slot after the action %+v, debit %v", s1, debit)
	}
	if fall := new(uint256.Int).Sub(ghostpriv.TotalEscrow(before), ghostpriv.TotalEscrow(after)); !fall.Eq(debit) {
		t.Fatalf("total escrow fell by %v, want the debit %v", fall, debit)
	}
	burn := actionBurn(block.BaseFee())
	tip := new(uint256.Int).Sub(debit, burn)
	if !tip.Eq(actionTip) {
		t.Fatalf("tip %v, want %v", tip, actionTip)
	}
	wantMiner := new(uint256.Int).Add(f.engine.params.BlockReward(4), tip)
	if got := after.GetBalance(miner); !got.Eq(wantMiner) {
		t.Fatalf("coinbase %v, want the reward and the tip %v", got, wantMiner)
	}
	// Nothing else is credited: the native accounts and the policy hold no
	// balance, and the totals of the hidden set do not move.
	for _, addr := range []common.Address{ghost.EscrowAccount, ghost.ActionCallerAddress, actionPolicyA, ghost.PrivTotalsAccount} {
		if !after.GetBalance(addr).IsZero() {
			t.Errorf("%v holds %v", addr, after.GetBalance(addr))
		}
	}
	in0, out0 := ghostpriv.Totals(before)
	in1, out1 := ghostpriv.Totals(after)
	if !in0.Eq(in1) || !out0.Eq(out1) {
		t.Fatal("the action moved total_in or total_out")
	}
	receipts := chain.GetReceiptsByHash(block.Hash())
	if len(receipts) != 1 {
		t.Fatalf("%d receipts", len(receipts))
	}
	r := receipts[0]
	if r.Type != types.GhostPolicyActionTxType || r.Status != types.ReceiptStatusSuccessful || r.GasUsed != ghostpriv.GasAction || r.CumulativeGasUsed != ghostpriv.GasAction || r.TxHash != tx.Hash() {
		t.Fatalf("receipt %+v", r)
	}
	res := resultOf(t, r.Logs, marker)
	if res.nonce != 0 || !res.debit.Eq(debit) || !res.success {
		t.Fatalf("action result %+v", res)
	}
	// The transaction reads back from the chain as the same action.
	got, _, _, _ := rawTx(chain, tx.Hash())
	if got == nil || !bytes.Equal(got.GhostPolicyActionEnvelope(), tx.GhostPolicyActionEnvelope()) {
		t.Fatal("the action does not read back from the chain")
	}
}

// rawTx looks a transaction up in the chain's database.
func rawTx(chain *core.BlockChain, hash common.Hash) (*types.Transaction, common.Hash, uint64, uint64) {
	for n := chain.CurrentBlock().Number.Uint64(); n > 0; n-- {
		b := chain.GetBlockByNumber(n)
		for i, tx := range b.Transactions() {
			if tx.Hash() == hash {
				return tx, b.Hash(), n, uint64(i)
			}
		}
	}
	return nil, common.Hash{}, 0, 0
}

// TestPolicyActionRP19RevertKeepsDebit checks RP-19: an action whose policy
// call pays from the slot and then reverts keeps its debit, the burn and
// tip, and the spent nonce, while the pay, its balance credit and its log
// are undone; its receipt is successful with the action-result log of a
// failed call. The same action on a policy that does not revert pays.
func TestPolicyActionRP19RevertKeepsDebit(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, actionAlloc())
	destR, destA := common.Address{0xde, 0x19, 1}, common.Address{0xde, 0x19, 2}
	debits := map[common.Address]*uint256.Int{}
	blocks, reveals := genActionBlocks(t, f, []common.Address{actionPolicyR, actionPolicyA}, 6, func(i int, b *core.BlockGen, reveals map[common.Address]*ghostpriv.PolicyReveal) {
		p, dest := actionPolicyR, destR
		if i == 5 {
			p, dest = actionPolicyA, destA
		}
		r := reveals[p]
		debits[p] = actionDebit(b.BaseFee())
		b.AddTx(actionTx(t, f.newAction(r, 0, actionOut(), debits[p], b.Number().Uint64(), nativePayIn(r.Marker, dest, 1000))))
	})
	chain := f.newChain()
	f.insert(chain, blocks)
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	// The reverting policy: the debit and the nonce stay, the pay is gone.
	slotR, _ := ghostpriv.ReadEscrowSlot(st, reveals[actionPolicyR].Marker)
	if want := new(uint256.Int).Sub(actionOut(), debits[actionPolicyR]); !slotR.Remaining.Eq(want) || slotR.ActionNonce != 1 || !slotR.ActionDebits.Eq(debits[actionPolicyR]) || !slotR.Paid.IsZero() || !slotR.Balanced() {
		t.Fatalf("slot of the reverting policy %+v", slotR)
	}
	if !st.GetBalance(destR).IsZero() {
		t.Fatal("the reverted pay credited its destination")
	}
	receiptsR := chain.GetReceiptsByHash(blocks[4].Hash())
	if len(receiptsR) != 1 || receiptsR[0].Status != types.ReceiptStatusSuccessful || receiptsR[0].GasUsed != ghostpriv.GasAction {
		t.Fatal("the reverted action's receipt is not a successful G_ACTION receipt")
	}
	if len(receiptsR[0].Logs) != 1 {
		t.Fatalf("the reverted action left %d logs, want the action result only", len(receiptsR[0].Logs))
	}
	if res := resultOf(t, receiptsR[0].Logs, reveals[actionPolicyR].Marker); res.success || res.nonce != 0 || !res.debit.Eq(debits[actionPolicyR]) || res.gasUsed == 0 || res.gasUsed > ghostpriv.ActionCallGas {
		t.Fatalf("reverted action result %+v", res)
	}
	// The policy that does not revert: the pay is kept.
	slotA, _ := ghostpriv.ReadEscrowSlot(st, reveals[actionPolicyA].Marker)
	want := new(uint256.Int).Sub(actionOut(), debits[actionPolicyA])
	want.SubUint64(want, 1000)
	if !slotA.Remaining.Eq(want) || slotA.ActionNonce != 1 || !slotA.Paid.Eq(uint256.NewInt(1000)) || !st.GetBalance(destA).Eq(uint256.NewInt(1000)) || !slotA.Balanced() {
		t.Fatalf("slot of the paying policy %+v", slotA)
	}
	receiptsA := chain.GetReceiptsByHash(blocks[5].Hash())
	if len(receiptsA) != 1 || len(receiptsA[0].Logs) != 2 {
		t.Fatal("the paying action has no slot-paid log and action result")
	}
	if res := resultOf(t, receiptsA[0].Logs, reveals[actionPolicyA].Marker); !res.success {
		t.Fatalf("paying action result %+v", res)
	}
	// The escrow total is the two remainders.
	if total := new(uint256.Int).Add(slotA.Remaining, slotR.Remaining); !ghostpriv.TotalEscrow(st).Eq(total) {
		t.Fatalf("total escrow %v, want %v", ghostpriv.TotalEscrow(st), total)
	}
}

// TestPolicyActionRP20Reorg imports a branch whose block 5 carries an action,
// then a heavier branch without it: the node ends with exactly the state of
// a node that saw only the heavier branch, the debit, the burn and tip and
// the nonce rewound, and the same action, at the same nonce, then applies on
// the new branch.
func TestPolicyActionRP20Reorg(t *testing.T) {
	useStub(t)
	f := newFixture(t, ghost.InternalNetGasLimit, actionAlloc())
	var (
		minerA = common.Address{0xa0, 0x54}
		minerB = common.Address{0xb0, 0x54}
		p      = actionPolicyA
	)
	branch := func(n, actionAt int, miner common.Address) []*types.Block {
		blocks, _ := genActionBlocks(t, f, []common.Address{p}, n, func(i int, b *core.BlockGen, reveals map[common.Address]*ghostpriv.PolicyReveal) {
			if i < 4 {
				return
			}
			b.SetCoinbase(miner)
			if i == actionAt {
				r := reveals[p]
				b.AddTx(actionTx(t, f.newAction(r, 0, actionOut(), actionDebit(b.BaseFee()), b.Number().Uint64()+10, nativeSlotIn(r.Marker))))
			}
		})
		return blocks
	}
	a := branch(5, 4, minerA)  // the action in block 5
	b := branch(7, -1, minerB) // blocks 5 to 7 without it
	if a[3].Hash() != b[3].Hash() || a[4].Hash() == b[4].Hash() {
		t.Fatal("the branches do not fork after block 4")
	}
	marker := actionMarker(p)
	addrs := []common.Address{minerA, minerB, p, ghost.EscrowAccount, ghost.ActionCallerAddress}

	reorged := f.newChain()
	f.insert(reorged, a)
	st, err := reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if slot, ok := ghostpriv.ReadEscrowSlot(st, marker); !ok || slot.ActionNonce != 1 || slot.ActionDebits.IsZero() {
		t.Fatal("branch A did not take the action")
	}
	f.insert(reorged, b)
	if reorged.CurrentBlock().Hash() != b[6].Hash() {
		t.Fatal("the node did not reorganise to branch B")
	}
	onlyB := f.newChain()
	f.insert(onlyB, b)
	after := policyChainSnapshot(t, reorged, reorged.CurrentBlock().Root, marker, addrs)
	if diffs := diffMaps(after, policyChainSnapshot(t, onlyB, onlyB.CurrentBlock().Root, marker, addrs)); len(diffs) != 0 {
		t.Fatalf("against the node that saw only B: %v", diffs)
	}
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	slot, _ := ghostpriv.ReadEscrowSlot(st, marker)
	if slot.ActionNonce != 0 || !slot.ActionDebits.IsZero() || !slot.Remaining.Eq(actionOut()) || !ghostpriv.TotalEscrow(st).Eq(actionOut()) {
		t.Fatalf("slot after the reorganisation %+v", slot)
	}
	if !st.GetBalance(minerA).IsZero() {
		t.Fatal("the tip of the rewound action stayed")
	}
	// The same action, at nonce 0, applies on branch B.
	longer := branch(8, 7, minerB)
	if longer[6].Hash() != b[6].Hash() {
		t.Fatal("branch B did not rebuild identically")
	}
	f.insert(reorged, longer[7:])
	st, err = reorged.State()
	if err != nil {
		t.Fatal(err)
	}
	if slot, _ := ghostpriv.ReadEscrowSlot(st, marker); slot.ActionNonce != 1 || slot.ActionDebits.IsZero() {
		t.Fatal("the action did not apply on branch B")
	}
}

// TestPolicyActionRP21RejectedBeforeProof checks RP-21: an action with a
// wrong nonce, a wrong expected remaining, a passed expiry or a debit under
// G_ACTION times the base fee is refused before the proof, which is not
// verified, and charges nothing: core.ApplyPolicyAction leaves the state and
// the block gas pool as they were. A block holding one is invalid and the
// head stays.
func TestPolicyActionRP21RejectedBeforeProof(t *testing.T) {
	useStub(t)
	s := newActionScenario(t, actionPolicyA)
	r := s.reveals[actionPolicyA]
	out := actionOut()
	debit := actionDebit(s.env.Header.BaseFee)
	height := s.height()
	cases := []struct {
		name string
		make func(baseFee *big.Int, height uint64) *ghostpriv.Action
		want error
	}{
		{"wrong nonce", func(bf *big.Int, h uint64) *ghostpriv.Action {
			return s.f.newAction(r, 1, out, actionDebit(bf), h, nil)
		}, ghostpriv.ErrActionNonce},
		{"wrong expected remaining", func(bf *big.Int, h uint64) *ghostpriv.Action {
			return s.f.newAction(r, 0, new(uint256.Int).SubUint64(out, 1), actionDebit(bf), h, nil)
		}, ghostpriv.ErrActionRemaining},
		{"passed expiry", func(bf *big.Int, h uint64) *ghostpriv.Action {
			return s.f.newAction(r, 0, out, actionDebit(bf), h-1, nil)
		}, ghostpriv.ErrActionExpired},
		{"debit under G_ACTION times the base fee", func(bf *big.Int, h uint64) *ghostpriv.Action {
			return s.f.newAction(r, 0, out, new(uint256.Int).SubUint64(actionBurn(bf), 1), h, nil)
		}, ghostpriv.ErrActionDebit},
	}
	minerBefore := s.st.GetBalance(s.miner).Clone()
	for _, c := range cases {
		a := c.make(s.env.Header.BaseFee, height)
		v := new(countingVerifier)
		if _, _, err := ghostpriv.CheckAction(s.st, s.env, v, actionEnvelope(t, a)); !errors.Is(err, c.want) || v.calls != 0 {
			t.Errorf("%s: %v with %d proof checks, want %v before the proof", c.name, err, v.calls, c.want)
		}
		before := s.fingerprint()
		gp := new(core.GasPool).AddGas(ghostpriv.GasAction + 1)
		receipt, used, err := s.apply(t, a, gp, vm.Config{})
		if !errors.Is(err, c.want) || receipt != nil || used != 0 || gp.Gas() != ghostpriv.GasAction+1 {
			t.Errorf("%s applied: %v, used %d, pool %d", c.name, err, used, gp.Gas())
		}
		if s.fingerprint() != before || !s.st.GetBalance(s.miner).Eq(minerBefore) {
			t.Errorf("%s: the refused action charged something", c.name)
		}
	}
	if slot := s.slot(t, actionPolicyA); slot.ActionNonce != 0 || !slot.Remaining.Eq(out) {
		t.Fatal("a refused action moved the slot")
	}
	// The control: the valid action of the same block applies.
	if _, _, err := s.apply(t, s.f.newAction(r, 0, out, debit, height, nil), new(core.GasPool).AddGas(ghostpriv.GasAction), vm.Config{}); err != nil {
		t.Fatalf("the valid action: %v", err)
	}

	// A block holding one is invalid.
	for _, c := range cases {
		f := newFixture(t, ghost.InternalNetGasLimit, actionAlloc())
		blocks, _ := genActionBlocks(t, f, []common.Address{actionPolicyA}, 4, func(i int, b *core.BlockGen, reveals map[common.Address]*ghostpriv.PolicyReveal) {
			b.AddUncheckedTx(actionTx(t, c.make(b.BaseFee(), b.Number().Uint64())))
		})
		chain := f.newChain()
		f.insert(chain, blocks[:3])
		if _, err := chain.InsertChain(blocks[3:]); !errors.Is(err, c.want) {
			t.Errorf("block with an action of %s: %v, want %v", c.name, err, c.want)
		}
		if chain.CurrentBlock().Hash() != blocks[2].Hash() {
			t.Errorf("%s: the head moved", c.name)
		}
	}
}

// callTracer records the top-level call of an action and the frames it
// enters.
type callTracer struct {
	origin   common.Address
	gasPrice *big.Int
	from, to common.Address
	gas      uint64
	used     uint64
	input    []byte
	value    *big.Int
	starts   int
}

func (c *callTracer) CaptureTxStart(uint64) {}
func (c *callTracer) CaptureTxEnd(uint64)   {}
func (c *callTracer) CaptureStart(env *vm.EVM, from, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	c.starts++
	c.origin, c.gasPrice = env.Origin, env.GasPrice
	c.from, c.to, c.gas, c.input, c.value = from, to, gas, common.CopyBytes(input), value
}
func (c *callTracer) CaptureEnd(output []byte, used uint64, err error) { c.used = used }
func (c *callTracer) CaptureEnter(vm.OpCode, common.Address, common.Address, []byte, uint64, *big.Int) {
}
func (c *callTracer) CaptureExit([]byte, uint64, error) {}
func (c *callTracer) CaptureState(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, []byte, int, error) {
}
func (c *callTracer) CaptureFault(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, int, error) {
}

// TestPolicyActionNoRefundAndGas checks the policy call and the gas of an
// action: the policy is called from ACTION_CALLER, which is also ORIGIN, at
// GASPRICE zero, with ACTION_CALL_GAS of 250,000, no value and the action's
// calldata; the action takes G_ACTION from the block gas pool, refunds none
// of what the call left, and a pool that holds less refuses it and changes
// nothing; the receipt is successful with gas used G_ACTION and the
// action-result log whether the call succeeds or fails; and an action whose
// debit is the whole remaining closes the slot.
func TestPolicyActionNoRefundAndGas(t *testing.T) {
	useStub(t)
	if ghostpriv.ActionCallGas != 250_000 || ghostpriv.GasAction != 15_585_968 || types.GhostPolicyActionGas != 15_585_968 {
		t.Fatalf("ACTION_CALL_GAS %d, G_ACTION %d", ghostpriv.ActionCallGas, ghostpriv.GasAction)
	}
	s := newActionScenario(t, actionPolicyA, actionPolicyR)
	rA := s.reveals[actionPolicyA]
	out := actionOut()

	// A pool one gas short refuses the action and changes nothing.
	full := s.f.newAction(rA, 0, out, out, s.height(), nativeSlotIn(rA.Marker))
	before := s.fingerprint()
	gp := new(core.GasPool).AddGas(ghostpriv.GasAction - 1)
	if _, used, err := s.apply(t, full, gp, vm.Config{}); !errors.Is(err, core.ErrGasLimitReached) || used != 0 || gp.Gas() != ghostpriv.GasAction-1 {
		t.Fatalf("pool one gas short: %v, used %d, pool %d", err, used, gp.Gas())
	}
	if s.fingerprint() != before {
		t.Fatal("the refused action changed the state")
	}

	// The whole remaining as the debit: the call, the gas, the closing.
	tracer := new(callTracer)
	gp = new(core.GasPool).AddGas(ghostpriv.GasAction + 7)
	minerBefore := s.st.GetBalance(s.miner).Clone()
	receipt, used, err := s.apply(t, full, gp, vm.Config{Tracer: tracer})
	if err != nil {
		t.Fatal(err)
	}
	if tracer.starts != 1 || tracer.from != ghost.ActionCallerAddress || tracer.origin != ghost.ActionCallerAddress || tracer.to != actionPolicyA ||
		tracer.gas != ghostpriv.ActionCallGas || tracer.gasPrice == nil || tracer.gasPrice.Sign() != 0 || !bytes.Equal(tracer.input, full.Calldata) ||
		(tracer.value != nil && tracer.value.Sign() != 0) {
		t.Fatalf("policy call: %d calls from %v origin %v to %v gas %d price %v", tracer.starts, tracer.from, tracer.origin, tracer.to, tracer.gas, tracer.gasPrice)
	}
	if tracer.used == 0 || tracer.used >= ghostpriv.ActionCallGas/2 {
		t.Fatalf("the call used %d gas", tracer.used)
	}
	if gp.Gas() != 7 || used != ghostpriv.GasAction || receipt.GasUsed != ghostpriv.GasAction || receipt.CumulativeGasUsed != ghostpriv.GasAction {
		t.Fatalf("pool left %d, used %d, receipt %d: some gas was refunded", gp.Gas(), used, receipt.GasUsed)
	}
	if receipt.Type != types.GhostPolicyActionTxType || receipt.Status != types.ReceiptStatusSuccessful || receipt.EffectiveGasPrice.Sign() != 0 {
		t.Fatalf("receipt %+v", receipt)
	}
	res := resultOf(t, receipt.Logs, rA.Marker)
	if !res.success || res.gasUsed != tracer.used || !res.debit.Eq(out) || res.nonce != 0 {
		t.Fatalf("action result %+v, call used %d", res, tracer.used)
	}
	slot := s.slot(t, actionPolicyA)
	if slot.Open || !slot.Remaining.IsZero() || !slot.ActionDebits.Eq(out) || slot.ActionNonce != 1 || slot.ActionTag != (common.Hash{}) || !slot.Balanced() {
		t.Fatalf("slot after a debit of the whole %+v", slot)
	}
	var closedLog bool
	for _, l := range receipt.Logs {
		if l.Address == ghost.EscrowAccount && l.Topics[0] == ghosttree.K(ghostpriv.TagSlotClosed) && bytes.Equal(l.Data, word(0)) {
			closedLog = true
		}
	}
	if !closedLog {
		t.Fatal("no slot-closed log with nothing forfeited")
	}
	burn := actionBurn(s.env.Header.BaseFee)
	if got := new(uint256.Int).Sub(s.st.GetBalance(s.miner), minerBefore); !got.Eq(new(uint256.Int).Sub(out, burn)) {
		t.Fatalf("coinbase gained %v, want the debit less the burn", got)
	}
	// A closed slot takes no more action.
	again := s.f.newAction(rA, 1, uint256.NewInt(0), burn, s.height(), nil)
	if _, _, err := s.apply(t, again, new(core.GasPool).AddGas(ghostpriv.GasAction), vm.Config{}); !errors.Is(err, ghostpriv.ErrActionSlot) {
		t.Fatalf("an action on the closed slot: %v", err)
	}

	// A failing call: the receipt is still successful, with the result log
	// of a failed call, and no gas comes back.
	tracer = new(callTracer)
	gp = new(core.GasPool).AddGas(ghostpriv.GasAction)
	rR := s.reveals[actionPolicyR]
	receipt, used, err = s.apply(t, s.next(t, actionPolicyR, nativeSlotIn(rR.Marker)), gp, vm.Config{Tracer: tracer})
	if err != nil {
		t.Fatal(err)
	}
	if gp.Gas() != 0 || used != ghostpriv.GasAction || receipt.Status != types.ReceiptStatusSuccessful || receipt.GasUsed != ghostpriv.GasAction {
		t.Fatalf("failing call: pool %d, used %d, receipt %+v", gp.Gas(), used, receipt)
	}
	if res := resultOf(t, receipt.Logs, rR.Marker); res.success || res.gasUsed != tracer.used || res.nonce != 0 {
		t.Fatalf("failing call result %+v", res)
	}
	if s.slot(t, actionPolicyR).ActionNonce != 1 {
		t.Fatal("a failing call gave the nonce back")
	}
	if tracer.from != ghost.ActionCallerAddress || tracer.origin != ghost.ActionCallerAddress {
		t.Fatal("the failing call did not come from ACTION_CALLER")
	}
}
