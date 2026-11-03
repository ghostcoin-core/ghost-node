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

package vm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The block the escrow tests run their calls in; their policies are created
// in block 1.
const escrowBlock = 2

// nativeCallBlock is the bytecode of one call of kind op (CALL or
// STATICCALL) to 0x60 with the calldata copied at 0x100 as its input, all
// the gas the 63/64 rule leaves and no value; it leaves the success flag on
// the stack. It uses no opcode a frozen context forbids.
func nativeCallBlock(op OpCode) []byte {
	code := []byte{byte(PUSH1), 0, byte(PUSH1), 0, byte(CALLDATASIZE), byte(PUSH2), 0x01, 0x00}
	if op == CALL || op == CALLCODE {
		code = append(code, byte(PUSH1), 0)
	}
	return append(code, byte(PUSH1), 0x60, byte(PUSH4), 0xff, 0xff, 0xff, 0xff, byte(op))
}

// copyCalldata copies the calldata to memory at 0x100.
var copyCalldata = []byte{byte(CALLDATASIZE), byte(PUSH1), 0, byte(PUSH2), 0x01, 0x00, byte(CALLDATACOPY)}

// nativeCallerCode calls 0x60 with op and its calldata, and returns, or
// with revertAfter reverts with, the success flag as a word followed by the
// native's return data.
func nativeCallerCode(op OpCode, revertAfter bool) []byte {
	end := RETURN
	if revertAfter {
		end = REVERT
	}
	return cat(copyCalldata, nativeCallBlock(op),
		[]byte{byte(PUSH1), 0, byte(MSTORE)},
		[]byte{byte(RETURNDATASIZE), byte(PUSH1), 0, byte(PUSH1), 32, byte(RETURNDATACOPY)},
		[]byte{byte(RETURNDATASIZE), byte(PUSH1), 32, byte(ADD), byte(PUSH1), 0, byte(end)},
	)
}

// nativeTwiceCode calls 0x60 twice with its calldata and returns the two
// success flags as two words.
func nativeTwiceCode() []byte {
	return cat(copyCalldata,
		nativeCallBlock(CALL), []byte{byte(PUSH1), 0, byte(MSTORE)},
		nativeCallBlock(CALL), []byte{byte(PUSH1), 32, byte(MSTORE)},
		[]byte{byte(PUSH1), 64, byte(PUSH1), 0, byte(RETURN)},
	)
}

// relayCode is an ordinary contract: it calls target with op (DELEGATECALL
// or STATICCALL) and its calldata, and returns the target's return data.
func relayCode(op OpCode, target common.Address) []byte {
	return cat(
		[]byte{byte(CALLDATASIZE), byte(PUSH1), 0, byte(PUSH1), 0, byte(CALLDATACOPY)},
		[]byte{byte(PUSH1), 0, byte(PUSH1), 0, byte(CALLDATASIZE), byte(PUSH1), 0},
		pushAddr(target),
		[]byte{byte(PUSH4), 0xff, 0xff, 0xff, 0xff, byte(op), byte(POP)},
		[]byte{byte(RETURNDATASIZE), byte(PUSH1), 0, byte(PUSH1), 0, byte(RETURNDATACOPY)},
		[]byte{byte(RETURNDATASIZE), byte(PUSH1), 0, byte(RETURN)},
	)
}

// opCallerCode is an ordinary contract that calls target with op, no input,
// no value and 1,000,000 gas, and returns the success flag.
func opCallerCode(op OpCode, target common.Address) []byte {
	code := []byte{byte(PUSH1), 0, byte(PUSH1), 0, byte(PUSH1), 0, byte(PUSH1), 0}
	if op == CALL || op == CALLCODE {
		code = append(code, byte(PUSH1), 0)
	}
	code = append(code, pushAddr(target)...)
	code = append(code, byte(PUSH3), 0x0f, 0x42, 0x40, byte(op))
	return cat(code, []byte{byte(PUSH1), 0, byte(MSTORE), byte(PUSH1), 32, byte(PUSH1), 0, byte(RETURN)})
}

// The inputs of the natives.
func word(v uint64) []byte { return common.BigToHash(new(big.Int).SetUint64(v)).Bytes() }

func slotIn(m common.Hash) []byte  { return cat(EscrowSlotSelector[:], m[:]) }
func closeIn(m common.Hash) []byte { return cat(EscrowCloseSelector[:], m[:]) }

func payIn(m common.Hash, dest common.Address, amount uint64) []byte {
	return cat(EscrowPaySelector[:], m[:], addrWord(dest), word(amount))
}

func recommitIn(m, f common.Hash, salt [ghostpriv.SaltSize]byte, amount uint64, note []byte) []byte {
	padded := make([]byte, (len(note)+31)/32*32)
	copy(padded, note)
	return cat(EscrowRecommitSelector[:], m[:], f[:], common.RightPadBytes(salt[:], 32), word(amount), word(0xa0), word(uint64(len(note))), padded)
}

func escrowMarker(name string) common.Hash {
	return ghosttree.K("ghost/test-escrow-marker", []byte(name))
}

func escrowNote(seed byte, n int) []byte {
	note := make([]byte, n)
	for i := range note {
		note[i] = seed ^ byte(i) | 1
	}
	return note
}

// openSlot opens the slot of marker for policy with out, in block 1.
func (e *policyEnv) openSlot(marker common.Hash, policy common.Address, out uint64) {
	e.t.Helper()
	err := ghostpriv.OpenEscrowSlot(e.state, marker, &ghostpriv.EscrowSlot{
		Policy:     policy,
		Out:        uint256.NewInt(out),
		Height:     1,
		Timestamp:  ghost.InternalNetTimestamp + 1,
		ParamsHash: ghosttree.K("ghost/test-params", marker[:]),
		ActionTag:  ghosttree.K("ghost/test-action-tag", marker[:]),
		ActionSalt: ghosttree.K("ghost/test-action-salt", marker[:]),
		Instr:      ghosttree.K("ghost/test-instr", marker[:]),
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *policyEnv) escrowSlot(marker common.Hash) *ghostpriv.EscrowSlot {
	e.t.Helper()
	s, ok := ghostpriv.ReadEscrowSlot(e.state, marker)
	if !ok {
		e.t.Fatalf("no slot %x", marker)
	}
	return s
}

// slotWordsOf reads the eight storage words of a slot.
func (e *policyEnv) slotWordsOf(marker common.Hash) [ghostpriv.EscrowSlotWords]common.Hash {
	var w [ghostpriv.EscrowSlotWords]common.Hash
	for i := range w {
		w[i] = e.state.GetState(ghost.EscrowAccount, ghostpriv.EscrowSlotKey(marker, byte(i)))
	}
	return w
}

// fingerprint is the whole state and the number of logs.
func (e *policyEnv) fingerprint() string {
	return fmt.Sprintf("%x %d", e.state.Copy().IntermediateRoot(true), len(e.state.Logs()))
}

// call runs a top-level call from policySender to to in the escrow block
// and returns the result of a native caller: the success flag and the
// native's return data.
func (e *policyEnv) callNative(evm preparedEVM, to common.Address, input []byte) (bool, []byte) {
	e.t.Helper()
	ret, _, err := evm.Call(AccountRef(policySender), to, input, policyTestGas, new(uint256.Int))
	if err != nil {
		e.t.Fatalf("the call to %v fails: %v", to, err)
	}
	if len(ret) < 32 {
		e.t.Fatalf("the caller returns %d bytes", len(ret))
	}
	return new(big.Int).SetBytes(ret[:32]).Sign() != 0, ret[32:]
}

// nativeTracer records every frame of a call to 0x60: the gas given, the
// gas used and the error.
type nativeTracer struct {
	stack  []nativeFrame
	native []nativeFrame
	frames []common.Address // every frame entered, by its address
}

type nativeFrame struct {
	to        common.Address
	op        OpCode
	gas, used uint64
	err       error
}

func (n *nativeTracer) CaptureTxStart(uint64) {}
func (n *nativeTracer) CaptureTxEnd(uint64)   {}
func (n *nativeTracer) CaptureStart(_ *EVM, _ common.Address, to common.Address, _ bool, _ []byte, gas uint64, _ *big.Int) {
	n.stack = append(n.stack, nativeFrame{to: to, op: CALL, gas: gas})
	n.frames = append(n.frames, to)
}
func (n *nativeTracer) CaptureEnd(out []byte, used uint64, err error) { n.pop(used, err) }
func (n *nativeTracer) CaptureEnter(op OpCode, _ common.Address, to common.Address, _ []byte, gas uint64, _ *big.Int) {
	n.stack = append(n.stack, nativeFrame{to: to, op: op, gas: gas})
	n.frames = append(n.frames, to)
}
func (n *nativeTracer) CaptureExit(out []byte, used uint64, err error) { n.pop(used, err) }
func (n *nativeTracer) CaptureState(uint64, OpCode, uint64, uint64, *ScopeContext, []byte, int, error) {
}
func (n *nativeTracer) CaptureFault(uint64, OpCode, uint64, uint64, *ScopeContext, int, error) {}

func (n *nativeTracer) pop(used uint64, err error) {
	f := n.stack[len(n.stack)-1]
	n.stack = n.stack[:len(n.stack)-1]
	f.used, f.err = used, err
	if f.to == ghost.EscrowNativeAddress {
		n.native = append(n.native, f)
	}
}

// escrowSetup is a state with two policies, A and B, of the same native
// caller code, each with an open slot of 1,000 wei, an ordinary contract X
// with the same code, and an ordinary contract D that delegates to A.
type escrowSetup struct {
	env              *policyEnv
	a, b, x, d       common.Address
	markerA, markerB common.Hash
}

func newEscrowSetup(t *testing.T) *escrowSetup {
	env := newPolicyEnv(t)
	s := &escrowSetup{
		env:     env,
		a:       env.mustCreatePolicy(1, saltOf(1), nativeCallerCode(CALL, false)),
		b:       env.mustCreatePolicy(1, saltOf(2), nativeCallerCode(CALL, false)),
		x:       common.HexToAddress("0x0bad0000000000000000000000000000000000c1"),
		d:       common.HexToAddress("0x0bad0000000000000000000000000000000000d1"),
		markerA: escrowMarker("A"),
		markerB: escrowMarker("B"),
	}
	env.setContract(s.x, nativeCallerCode(CALL, false))
	env.setContract(s.d, relayCode(DELEGATECALL, s.a))
	env.openSlot(s.markerA, s.a, 1000)
	env.openSlot(s.markerB, s.b, 1000)
	return s
}

// TestEscrowNativesRP12CrossPolicy checks RP-12 by call and by DELEGATECALL:
// policy A cannot read, pay, recommit or close a slot of policy B, and a
// contract that is not frozen, an ordinary contract with the same code or
// one that reaches A's code by DELEGATECALL, reaches neither A's slot nor
// B's. Each refused call changes nothing; B, and A, do each on their own
// slot.
func TestEscrowNativesRP12CrossPolicy(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	dest := common.HexToAddress("0x00000000000000000000000000000000d0d0d0d0")
	var salt [ghostpriv.SaltSize]byte
	note := escrowNote(3, ghostpriv.NoteSize)
	inputs := func(m common.Hash) map[string][]byte {
		return map[string][]byte{
			"slot":     slotIn(m),
			"pay":      payIn(m, dest, 10),
			"recommit": recommitIn(m, ghosttree.K("ghost/test-f", m[:]), salt, 10, note),
			"close":    closeIn(m),
		}
	}
	for _, c := range []struct {
		name   string
		caller common.Address
		marker common.Hash
	}{
		{"policy A on B's slot by call", s.a, s.markerB},
		{"policy B on A's slot by call", s.b, s.markerA},
		{"ordinary contract on A's slot", s.x, s.markerA},
		{"DELEGATECALL into A's code on A's slot", s.d, s.markerA},
		{"DELEGATECALL into A's code on B's slot", s.d, s.markerB},
	} {
		for _, fn := range []string{"slot", "pay", "recommit", "close"} {
			before := env.fingerprint()
			words := env.slotWordsOf(c.marker)
			ok, data := env.callNative(env.evm(escrowBlock, nil), c.caller, inputs(c.marker)[fn])
			if ok || len(data) != 0 {
				t.Errorf("%s: %s succeeds (%d bytes)", c.name, fn, len(data))
			}
			if env.fingerprint() != before || env.slotWordsOf(c.marker) != words {
				t.Errorf("%s: a refused %s changed the state", c.name, fn)
			}
		}
	}
	// Each policy reads, pays, recommits and closes its own slot.
	for _, own := range []struct {
		policy common.Address
		marker common.Hash
	}{{s.a, s.markerA}, {s.b, s.markerB}} {
		in := inputs(own.marker)
		for _, fn := range []string{"slot", "pay", "recommit", "close"} {
			ok, _ := env.callNative(env.evm(escrowBlock, nil), own.policy, in[fn])
			if !ok {
				t.Fatalf("policy %v: %s on its own slot fails", own.policy, fn)
			}
		}
		slot := env.escrowSlot(own.marker)
		if slot.Open || !slot.Paid.Eq(uint256.NewInt(10)) || !slot.Recommitted.Eq(uint256.NewInt(10)) || !slot.Forfeited.Eq(uint256.NewInt(980)) {
			t.Fatalf("policy %v: slot after its own calls %+v", own.policy, slot)
		}
	}
}

// TestEscrowNativesAccountsRejectEVMAccess checks spec 10, section 7.1: the
// three native accounts ESCROW_ACCOUNT, POLICY_REGISTRY and ACTION_CALLER
// reject every CALL, CALLCODE, DELEGATECALL and STATICCALL, from the EVM's
// entry points and from bytecode, using up the gas given, as the commit
// entry addresses do. The same calls to an empty address succeed.
func TestEscrowNativesAccountsRejectEVMAccess(t *testing.T) {
	env := newPolicyEnv(t)
	env.openSlot(escrowMarker("accounts"), common.HexToAddress("0x9a11c1e5000000000000000000000000000beef1"), 5)
	accounts := []common.Address{ghost.EscrowAccount, ghost.PolicyRegistryAccount, ghost.ActionCallerAddress}
	for _, addr := range accounts {
		if !ghost.IsEscrowNativeAccount(addr) {
			t.Fatalf("%v is not an escrow native account", addr)
		}
	}
	const gas = 100_000
	for _, addr := range accounts {
		evm := env.evm(escrowBlock, nil)
		caller := AccountRef(policySender)
		for name, call := range map[string]func() ([]byte, uint64, error){
			"CALL":         func() ([]byte, uint64, error) { return evm.EVM.Call(caller, addr, nil, gas, new(uint256.Int)) },
			"CALL value":   func() ([]byte, uint64, error) { return evm.EVM.Call(caller, addr, nil, gas, uint256.NewInt(1)) },
			"CALLCODE":     func() ([]byte, uint64, error) { return evm.CallCode(caller, addr, nil, gas, new(uint256.Int)) },
			"DELEGATECALL": func() ([]byte, uint64, error) { return evm.DelegateCall(caller, addr, nil, gas) },
			"STATICCALL":   func() ([]byte, uint64, error) { return evm.StaticCall(caller, addr, nil, gas) },
		} {
			before := env.fingerprint()
			ret, left, err := call()
			if !errors.Is(err, ErrEscrowAccountCall) || left != 0 || len(ret) != 0 {
				t.Errorf("%s to %v: error %v, gas left %d", name, addr, err, left)
			}
			if env.fingerprint() != before {
				t.Errorf("%s to %v changed the state", name, addr)
			}
		}
	}
	empty := common.HexToAddress("0x00000000000000000000000000000000e3e3e3e3")
	for i, op := range []OpCode{CALL, CALLCODE, DELEGATECALL, STATICCALL} {
		for j, addr := range append(accounts, empty) {
			caller := common.BytesToAddress([]byte{0xca, 0x11, byte(i), byte(j)})
			env.setContract(caller, opCallerCode(op, addr))
			ret, _, err := env.evm(escrowBlock, nil).Call(AccountRef(policySender), caller, nil, policyTestGas, new(uint256.Int))
			if err != nil {
				t.Fatalf("%v to %v: the caller fails: %v", op, addr, err)
			}
			if ok := new(big.Int).SetBytes(ret).Sign() != 0; ok != (addr == empty) {
				t.Errorf("%v from bytecode to %v: success %v", op, addr, ok)
			}
		}
	}
	// A top-level transaction to one is refused the same way.
	for _, addr := range accounts {
		if _, left, err := env.evm(escrowBlock, nil).Call(AccountRef(policySender), addr, []byte{1}, gas, new(uint256.Int)); !errors.Is(err, ErrEscrowAccountCall) || left != 0 {
			t.Errorf("top-level call to %v: %v, gas left %d", addr, err, left)
		}
	}
}

// TestEscrowNativesFailureIsRevert checks that a native fails revert-style:
// the call returns failure with empty return data, the native's flat gas is
// spent and the rest goes back, and nothing changes. The caller check is on
// the executing account, ADDRESS, never ORIGIN; and the static-context rule
// refuses pay, recommit and close in a static context, by STATICCALL to the
// native or under a STATICCALL further up, while slot reads.
func TestEscrowNativesFailureIsRevert(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	dest := common.HexToAddress("0x00000000000000000000000000000000d0d0d0d1")

	// A failing pay, from the policy: revert-style, flat gas spent.
	tracer := new(nativeTracer)
	before := env.fingerprint()
	ok, data := env.callNative(env.evm(escrowBlock, tracer), s.a, payIn(s.markerA, dest, 1001))
	if ok || len(data) != 0 {
		t.Fatalf("a pay above remaining succeeds or returns %d bytes", len(data))
	}
	if len(tracer.native) != 1 {
		t.Fatalf("%d native frames", len(tracer.native))
	}
	f := tracer.native[0]
	if !errors.Is(f.err, ErrExecutionReverted) || f.used != EscrowPayGas || f.gas <= EscrowPayGas {
		t.Fatalf("failed pay: error %v, used %d of %d, want revert using %d", f.err, f.used, f.gas, EscrowPayGas)
	}
	if env.fingerprint() != before {
		t.Fatal("a failed pay changed the state")
	}

	// From the entry point: the gas left is the gas given less the flat
	// gas, and the error is the revert.
	for _, c := range []struct {
		name  string
		input []byte
		gas   uint64
	}{
		{"slot", slotIn(s.markerA), EscrowSlotGas},
		{"pay", payIn(s.markerA, dest, 1), EscrowPayGas},
		{"recommit", recommitIn(s.markerA, common.Hash{1}, [16]byte{}, 1, escrowNote(1, ghostpriv.NoteSize)), EscrowRecommitGas},
		{"close", closeIn(s.markerA), EscrowCloseGas},
		{"actionMarker", ActionMarkerSelector[:], EscrowActionMarkerGas},
		{"actionSettle", ActionSettleSelector[:], EscrowActionSettleGas},
		{"no function", []byte{1, 2, 3, 4}, EscrowActionMarkerGas},
		{"short", []byte{1}, EscrowActionMarkerGas},
	} {
		ret, left, err := env.evm(escrowBlock, nil).EVM.Call(AccountRef(policySender), ghost.EscrowNativeAddress, c.input, 100_000, new(uint256.Int))
		if !errors.Is(err, ErrExecutionReverted) || len(ret) != 0 || left != 100_000-c.gas {
			t.Errorf("%s from an account: error %v, %d bytes, gas left %d, want %d", c.name, err, len(ret), left, 100_000-c.gas)
		}
		// Less gas than the flat gas: out of gas, all used.
		if _, left, err := env.evm(escrowBlock, nil).EVM.Call(AccountRef(policySender), ghost.EscrowNativeAddress, c.input, c.gas-1, new(uint256.Int)); !errors.Is(err, ErrOutOfGas) || left != 0 {
			t.Errorf("%s below its flat gas: %v, left %d", c.name, err, left)
		}
	}
	if env.fingerprint() != before {
		t.Fatal("refused entry-point calls changed the state")
	}

	// ADDRESS, never ORIGIN: an origin that is the slot's policy gives an
	// ordinary contract nothing, and the policy itself reads its slot
	// whatever the origin.
	evm := env.evm(escrowBlock, nil)
	evm.Origin = s.a
	if ok, _ := env.callNative(evm, s.x, slotIn(s.markerA)); ok {
		t.Fatal("ORIGIN equal to the policy lets an ordinary contract read its slot")
	}
	if _, _, err := env.evm(escrowBlock, nil).EVM.Call(AccountRef(s.a), ghost.EscrowNativeAddress, slotIn(s.markerA), 100_000, new(uint256.Int)); !errors.Is(err, ErrExecutionReverted) {
		t.Fatalf("a caller that is the policy's address but no frozen frame reads the slot: %v", err)
	}
	evm = env.evm(escrowBlock, nil)
	evm.Origin = common.HexToAddress("0x00000000000000000000000000000000000077")
	ok, data = env.callNative(evm, s.a, slotIn(s.markerA))
	if !ok || len(data) != EscrowSlotWordCount*32 {
		t.Fatalf("the policy cannot read its own slot: %v, %d bytes", ok, len(data))
	}
	if !bytes.Equal(data, EscrowSlotWords(env.escrowSlot(s.markerA))) {
		t.Fatal("slot() returns other words than the slot's")
	}

	// CALL with value, CALLCODE and DELEGATECALL to the native fail the same
	// way, moving nothing.
	contract := NewContract(AccountRef(policySender), AccountRef(s.a), new(uint256.Int), policyTestGas)
	contract.frozen = true
	evm = env.evm(escrowBlock, nil)
	env.state.SetBalance(s.a, uint256.NewInt(0))
	for name, call := range map[string]func() ([]byte, uint64, error){
		"CALL value": func() ([]byte, uint64, error) {
			return evm.EVM.Call(contract, ghost.EscrowNativeAddress, slotIn(s.markerA), 100_000, uint256.NewInt(1))
		},
		"CALLCODE": func() ([]byte, uint64, error) {
			return evm.CallCode(contract, ghost.EscrowNativeAddress, slotIn(s.markerA), 100_000, new(uint256.Int))
		},
		"DELEGATECALL": func() ([]byte, uint64, error) {
			return evm.DelegateCall(contract, ghost.EscrowNativeAddress, slotIn(s.markerA), 100_000)
		},
	} {
		ret, left, err := call()
		if !errors.Is(err, ErrExecutionReverted) || len(ret) != 0 || left != 100_000-EscrowSlotGas {
			t.Errorf("%s: %v, %d bytes, left %d", name, err, len(ret), left)
		}
	}
	// The same frame by CALL reads.
	if ret, _, err := evm.EVM.Call(contract, ghost.EscrowNativeAddress, slotIn(s.markerA), 100_000, new(uint256.Int)); err != nil || len(ret) != EscrowSlotWordCount*32 {
		t.Fatalf("the frozen frame's CALL fails: %v", err)
	}

	// The static-context rule: a policy that reaches the native by
	// STATICCALL reads but cannot pay, recommit or close.
	staticPolicy := env.mustCreatePolicy(1, saltOf(30), nativeCallerCode(STATICCALL, false))
	m := escrowMarker("static")
	env.openSlot(m, staticPolicy, 100)
	var salt [ghostpriv.SaltSize]byte
	writes := map[string][]byte{
		"pay":      payIn(m, dest, 1),
		"recommit": recommitIn(m, common.Hash{7}, salt, 1, escrowNote(2, ghostpriv.NoteSize)),
		"close":    closeIn(m),
	}
	if ok, data := env.callNative(env.evm(escrowBlock, nil), staticPolicy, slotIn(m)); !ok || len(data) != EscrowSlotWordCount*32 {
		t.Fatal("slot fails in a static context")
	}
	for name, in := range writes {
		before := env.fingerprint()
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), staticPolicy, in); ok {
			t.Errorf("%s by STATICCALL succeeds", name)
		}
		if env.fingerprint() != before {
			t.Errorf("%s by STATICCALL changed the state", name)
		}
	}
	// Under a STATICCALL further up: an ordinary contract STATICCALLs
	// policy A, which CALLs the native.
	upper := common.HexToAddress("0x0bad0000000000000000000000000000000000e1")
	env.setContract(upper, relayCode(STATICCALL, s.a))
	if ok, data := env.callNative(env.evm(escrowBlock, nil), upper, slotIn(s.markerA)); !ok || len(data) != EscrowSlotWordCount*32 {
		t.Fatal("slot fails under a STATICCALL")
	}
	// In this order: close last, as it ends the slot.
	for _, w := range []struct {
		name string
		in   []byte
	}{
		{"pay", payIn(s.markerA, dest, 1)},
		{"recommit", recommitIn(s.markerA, common.Hash{7}, salt, 1, escrowNote(2, ghostpriv.NoteSize))},
		{"close", closeIn(s.markerA)},
	} {
		name, in := w.name, w.in
		before := env.fingerprint()
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), upper, in); ok {
			t.Errorf("%s under a STATICCALL succeeds", name)
		}
		if env.fingerprint() != before {
			t.Errorf("%s under a STATICCALL changed the state", name)
		}
		// The same call without the STATICCALL above works.
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, in); !ok {
			t.Errorf("%s by CALL fails", name)
		}
	}
}

// TestEscrowNativesFlatGas checks the six flat gases, slot 16,900, pay
// 56,000, recommit 31,000, close 20,000, actionMarker 200 and actionSettle
// 200, that each is charged, no more and no less, on success and on
// failure, and that none is below the sum rule of section 7.2 as this change
// reads it: 2,100 for each storage word only read (a cold SLOAD), 5,000 for
// each storage word written (a cold SSTORE that changes a word: the slot's
// words and the totals), and for pay the value transfer (9,000) and the new
// account (25,000) of a balance credit.
func TestEscrowNativesFlatGas(t *testing.T) {
	want := map[string]uint64{
		"slot": 16_900, "pay": 56_000, "recommit": 31_000, "close": 20_000,
		"actionMarker": 200, "actionSettle": 200,
	}
	have := map[string]uint64{
		"slot": EscrowSlotGas, "pay": EscrowPayGas, "recommit": EscrowRecommitGas, "close": EscrowCloseGas,
		"actionMarker": EscrowActionMarkerGas, "actionSettle": EscrowActionSettleGas,
	}
	const (
		coldRead    = 2_100
		storeWord   = 5_000
		valueCredit = 9_000
		newAccount  = 25_000
	)
	sum := map[string]uint64{
		"slot":         ghostpriv.EscrowSlotWords * coldRead,   // the eight words
		"pay":          3*storeWord + valueCredit + newAccount, // remaining, paid, total_escrow
		"recommit":     4 * storeWord,                          // remaining, recommitted, total_escrow, total_in
		"close":        4 * storeWord,                          // open, remaining, forfeited, total_escrow
		"actionMarker": 0,                                      // the running action, no storage
		"actionSettle": 0,                                      // the running action, no storage
	}
	for name, w := range want {
		if have[name] != w {
			t.Errorf("%s: flat gas %d, want %d", name, have[name], w)
		}
		if have[name] < sum[name] {
			t.Errorf("%s: flat gas %d below the sum rule %d", name, have[name], sum[name])
		}
	}
	if got := len(map[[4]byte]bool{EscrowSlotSelector: true, EscrowPaySelector: true, EscrowRecommitSelector: true, EscrowCloseSelector: true, ActionMarkerSelector: true, ActionSettleSelector: true}); got != 6 {
		t.Fatalf("%d distinct selectors", got)
	}
	if EscrowSlotSelector != [4]byte(crypto.Keccak256([]byte("slot(bytes32)"))[:4]) {
		t.Fatal("the slot selector is not the ABI selector")
	}

	// Measured on success and on failure, through a policy.
	s := newEscrowSetup(t)
	env := s.env
	dest := common.HexToAddress("0x00000000000000000000000000000000d0d0d0d2")
	var salt [ghostpriv.SaltSize]byte
	note := escrowNote(4, ghostpriv.NoteSize)
	run := func(input []byte, action *ActionContext) (bool, nativeFrame) {
		tracer := new(nativeTracer)
		evm := env.evm(escrowBlock, tracer)
		evm.SetActionContext(action)
		ok, _ := env.callNative(evm, s.a, input)
		if len(tracer.native) != 1 {
			t.Fatalf("%d native frames", len(tracer.native))
		}
		return ok, tracer.native[0]
	}
	action := &ActionContext{Marker: s.markerA, Policy: s.a, Debit: uint256.NewInt(5), Remaining: uint256.NewInt(7)}
	for _, c := range []struct {
		name    string
		good    []byte
		bad     []byte
		action  *ActionContext
		flatGas uint64
	}{
		{"slot", slotIn(s.markerA), slotIn(s.markerB), nil, EscrowSlotGas},
		{"pay", payIn(s.markerA, dest, 1), payIn(s.markerA, dest, 5000), nil, EscrowPayGas},
		{"recommit", recommitIn(s.markerA, common.Hash{9}, salt, 1, note), recommitIn(s.markerA, common.Hash{9}, salt, 1, note[:100]), nil, EscrowRecommitGas},
		{"actionMarker", ActionMarkerSelector[:], ActionMarkerSelector[:], action, EscrowActionMarkerGas},
		{"actionSettle", ActionSettleSelector[:], ActionSettleSelector[:], action, EscrowActionSettleGas},
		{"close", closeIn(s.markerA), closeIn(s.markerA), nil, EscrowCloseGas},
	} {
		ok, f := run(c.good, c.action)
		if !ok || f.err != nil || f.used != c.flatGas {
			t.Errorf("%s: success %v, error %v, used %d, want %d", c.name, ok, f.err, f.used, c.flatGas)
		}
		// The failure: another slot, too much, a short note, no running
		// action, a closed slot.
		ok, f = run(c.bad, nil)
		if ok || !errors.Is(f.err, ErrExecutionReverted) || f.used != c.flatGas {
			t.Errorf("%s failing: success %v, error %v, used %d, want %d", c.name, ok, f.err, f.used, c.flatGas)
		}
	}
}

// TestEscrowNativesRP14PayBounds checks RP-14: a pay above remaining fails
// and changes nothing; a pay of the whole closes the slot and a second pay
// of the whole fails; within one call, two pays of more than half each
// leave the second failing, as remaining is lowered first.
func TestEscrowNativesRP14PayBounds(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	dest := common.HexToAddress("0x00000000000000000000000000000000d0d0d0d3")

	for _, amount := range []uint64{1001, 0} {
		before := env.fingerprint()
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, payIn(s.markerA, dest, amount)); ok {
			t.Fatalf("a pay of %d of 1,000 succeeds", amount)
		}
		if env.fingerprint() != before {
			t.Fatalf("a refused pay of %d changed the state", amount)
		}
	}
	// An amount word of 2^96 or more does not decode.
	huge := cat(EscrowPaySelector[:], s.markerA[:], addrWord(dest), common.BigToHash(new(big.Int).Lsh(big.NewInt(1), 96)).Bytes())
	if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, huge); ok {
		t.Fatal("a pay of 2^96 succeeds")
	}
	ok, data := env.callNative(env.evm(escrowBlock, nil), s.a, payIn(s.markerA, dest, 1000))
	if !ok || !bytes.Equal(data, word(0)) {
		t.Fatalf("a pay of the whole fails: %v %x", ok, data)
	}
	slot := env.escrowSlot(s.markerA)
	if slot.Open || !slot.Remaining.IsZero() || !slot.Paid.Eq(uint256.NewInt(1000)) || !env.state.GetBalance(dest).Eq(uint256.NewInt(1000)) {
		t.Fatalf("after the pay of the whole: %+v, dest %v", slot, env.state.GetBalance(dest))
	}
	before := env.fingerprint()
	if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, payIn(s.markerA, dest, 1000)); ok {
		t.Fatal("a second pay of the whole succeeds")
	}
	if env.fingerprint() != before || !env.state.GetBalance(dest).Eq(uint256.NewInt(1000)) {
		t.Fatal("the second pay changed the state")
	}
	if !ghostpriv.TotalEscrow(env.state).Eq(uint256.NewInt(1000)) {
		t.Fatalf("total escrow %v, want B's 1,000", ghostpriv.TotalEscrow(env.state))
	}

	// Two pays of 600 of 1,000 in one call: the first lowers remaining to
	// 400 before anything else, so the second fails.
	twice := env.mustCreatePolicy(1, saltOf(40), nativeTwiceCode())
	m := escrowMarker("twice")
	env.openSlot(m, twice, 1000)
	ret, _, err := env.evm(escrowBlock, nil).Call(AccountRef(policySender), twice, payIn(m, dest, 600), policyTestGas, new(uint256.Int))
	if err != nil || len(ret) != 64 {
		t.Fatalf("the double pay fails: %v", err)
	}
	if new(big.Int).SetBytes(ret[:32]).Sign() == 0 || new(big.Int).SetBytes(ret[32:]).Sign() != 0 {
		t.Fatalf("double pay of 600: success flags %x", ret)
	}
	slot = env.escrowSlot(m)
	if !slot.Remaining.Eq(uint256.NewInt(400)) || !slot.Paid.Eq(uint256.NewInt(600)) || !slot.Open || !env.state.GetBalance(dest).Eq(uint256.NewInt(1600)) {
		t.Fatalf("after the double pay: %+v, dest %v", slot, env.state.GetBalance(dest))
	}
	if !slot.Balanced() {
		t.Fatal("the slot is out of balance")
	}
}

// TestEscrowNativesRP15PayRunsNoCode checks RP-15: a pay to a contract is a
// plain balance credit. The contract's code, which would write its storage
// or revert, never runs: no frame enters it and its storage is unchanged,
// and the pay succeeds even to a contract that always reverts. A pay to a
// registered policy or a reserved address is refused.
func TestEscrowNativesRP15PayRunsNoCode(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	writer := common.HexToAddress("0x0000000000000000000000000000000000c0ffee")
	env.setContract(writer, []byte{byte(PUSH1), 1, byte(PUSH1), 0, byte(SSTORE), byte(STOP)})
	reverter := common.HexToAddress("0x0000000000000000000000000000000000c0fff0")
	env.setContract(reverter, []byte{byte(PUSH1), 0, byte(PUSH1), 0, byte(REVERT)})

	for _, dest := range []common.Address{writer, reverter} {
		tracer := new(nativeTracer)
		ok, _ := env.callNative(env.evm(escrowBlock, tracer), s.a, payIn(s.markerA, dest, 100))
		if !ok {
			t.Fatalf("a pay to the contract %v fails", dest)
		}
		for _, f := range tracer.frames {
			if f == dest {
				t.Fatalf("a frame entered the paid contract %v", dest)
			}
		}
		if !env.state.GetBalance(dest).Eq(uint256.NewInt(100)) {
			t.Fatalf("contract %v holds %v", dest, env.state.GetBalance(dest))
		}
	}
	if env.state.GetState(writer, common.Hash{}) != (common.Hash{}) {
		t.Fatal("the paid contract's code ran")
	}
	// The slot-paid log: the destination and the amount.
	var paid []*types.Log
	for _, l := range env.state.Logs() {
		if l.Address == ghost.EscrowAccount && l.Topics[0] == ghosttree.K(ghostpriv.TagSlotPaid) {
			paid = append(paid, l)
		}
	}
	if len(paid) != 2 || paid[0].Topics[1] != s.markerA || !bytes.Equal(paid[0].Data, cat(addrWord(writer), word(100))) {
		t.Fatalf("slot-paid logs %v", paid)
	}
	// No pay to a policy or to a reserved address.
	for _, dest := range []common.Address{s.b, ghost.EscrowAccount, ghost.PrivTotalsAccount, common.BytesToAddress([]byte{0x04})} {
		before := env.fingerprint()
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, payIn(s.markerA, dest, 1)); ok {
			t.Errorf("a pay to %v succeeds", dest)
		}
		if env.fingerprint() != before {
			t.Errorf("a refused pay to %v changed the state", dest)
		}
	}
}

// fillCoinTree makes the coin tree full in the block at height.
func fillCoinTree(e *policyEnv, height uint64) {
	addr := ghosttree.TreeAccount(ghosttree.Coin)
	e.state.SetNonce(addr, 1)
	e.state.SetState(addr, ghosttree.Slot(ghosttree.SlotLeafCount), common.BigToHash(new(big.Int).Lsh(big.NewInt(1), 32)))
	e.state.SetState(addr, ghosttree.Slot(ghosttree.SlotLastFilled), common.BigToHash(new(big.Int).SetUint64(height)))
	e.state.SetState(addr, ghosttree.Slot(ghosttree.SlotFinalRoot), ghosttree.K("ghost/test-final-root"))
	for l := uint64(0); l < ghosttree.MaxDepth; l++ {
		e.state.SetState(addr, ghosttree.Slot(ghosttree.SlotFrontier+l), ghosttree.K("ghost/test-frontier", []byte{byte(l)}))
	}
}

func coinLeaves(e *policyEnv) uint64 {
	return e.state.GetState(ghosttree.TreeAccount(ghosttree.Coin), ghosttree.Slot(ghosttree.SlotLeafCount)).Big().Uint64()
}

// TestEscrowNativesRecommit checks recommit: it appends the version 2 coin
// commitment of f and the amount to the coin tree with the commit receipt,
// which carries the note and the salt, adds the amount to total_in, lowers
// remaining and writes the slot-recommitted log. It fails, changing
// nothing, for a note of other than 380 bytes, a badly encoded input, a
// zero f, an amount above remaining, and on a full coin tree.
func TestEscrowNativesRecommit(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	f := ghosttree.K("ghost/test-recommit-f")
	salt := [ghostpriv.SaltSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	note := escrowNote(5, ghostpriv.NoteSize)

	bad := map[string][]byte{
		"note of 379 bytes": recommitIn(s.markerA, f, salt, 100, note[:379]),
		"note of 381 bytes": recommitIn(s.markerA, f, salt, 100, append(append([]byte{}, note...), 1)),
		"empty note":        recommitIn(s.markerA, f, salt, 100, nil),
		"zero f":            recommitIn(s.markerA, common.Hash{}, salt, 100, note),
		"above remaining":   recommitIn(s.markerA, f, salt, 1001, note),
		"zero amount":       recommitIn(s.markerA, f, salt, 0, note),
		"trailing byte":     append(recommitIn(s.markerA, f, salt, 100, note), 0),
		"short":             recommitIn(s.markerA, f, salt, 100, note)[:200],
	}
	wrongOffset := recommitIn(s.markerA, f, salt, 100, note)
	wrongOffset[4+4*32+31] = 0xc0
	bad["note offset"] = wrongOffset
	dirtySalt := recommitIn(s.markerA, f, salt, 100, note)
	dirtySalt[4+2*32+20] = 1
	bad["salt padding"] = dirtySalt
	dirtyNote := recommitIn(s.markerA, f, salt, 100, note)
	dirtyNote[len(dirtyNote)-1] = 1
	bad["note padding"] = dirtyNote
	for name, in := range bad {
		before := env.fingerprint()
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, in); ok {
			t.Errorf("recommit with %s succeeds", name)
		}
		if env.fingerprint() != before {
			t.Errorf("recommit with %s changed the state", name)
		}
	}

	inBefore, _ := ghostpriv.Totals(env.state)
	leaves := coinLeaves(env)
	logs := len(env.state.Logs())
	ok, data := env.callNative(env.evm(escrowBlock, nil), s.a, recommitIn(s.markerA, f, salt, 300, note))
	if !ok || !bytes.Equal(data, word(700)) {
		t.Fatalf("recommit fails: %v %x", ok, data)
	}
	inAfter, _ := ghostpriv.Totals(env.state)
	if new(uint256.Int).Sub(inAfter, inBefore).Uint64() != 300 {
		t.Fatalf("total in rose by %v, want 300", new(uint256.Int).Sub(inAfter, inBefore))
	}
	if coinLeaves(env) != leaves+1 {
		t.Fatalf("coin tree has %d leaves, want %d", coinLeaves(env), leaves+1)
	}
	slot := env.escrowSlot(s.markerA)
	if !slot.Remaining.Eq(uint256.NewInt(700)) || !slot.Recommitted.Eq(uint256.NewInt(300)) || !slot.Open || !slot.Balanced() {
		t.Fatalf("slot after recommit %+v", slot)
	}
	if !ghostpriv.TotalEscrow(env.state).Eq(uint256.NewInt(1700)) {
		t.Fatalf("total escrow %v", ghostpriv.TotalEscrow(env.state))
	}
	newLogs := env.state.Logs()[logs:]
	if len(newLogs) != 2 {
		t.Fatalf("%d logs, want the commit receipt and the slot-recommitted log", len(newLogs))
	}
	leaf := ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, f, uint256.NewInt(300))
	receipt := newLogs[0]
	if receipt.Address != ghosttree.TreeAccount(ghosttree.Coin) || receipt.Topics[0] != ghosttree.K(ghostpriv.TagCommitReceipt) {
		t.Fatalf("first log is not the commit receipt: %+v", receipt)
	}
	if !bytes.Equal(receipt.Data[8:40], leaf[:]) || !bytes.Equal(receipt.Data[40:72], word(300)) || !bytes.Equal(receipt.Data[72:72+ghostpriv.NoteSize], note) || !bytes.Equal(receipt.Data[72+ghostpriv.NoteSize:], salt[:]) {
		t.Fatal("the commit receipt does not carry the leaf, the amount, the note and the salt")
	}
	recommitted := newLogs[1]
	if recommitted.Address != ghost.EscrowAccount || recommitted.Topics[0] != ghosttree.K(ghostpriv.TagSlotRecommitted) || recommitted.Topics[1] != s.markerA || !bytes.Equal(recommitted.Data, word(300)) {
		t.Fatalf("slot-recommitted log %+v", recommitted)
	}

	// A full coin tree: the recommit fails and nothing changes.
	fillCoinTree(env, escrowBlock)
	before := env.fingerprint()
	if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, recommitIn(s.markerA, f, salt, 100, note)); ok {
		t.Fatal("recommit into a full coin tree succeeds")
	}
	if env.fingerprint() != before {
		t.Fatal("recommit into a full tree changed the state")
	}
	// Recommitting the rest closes the slot, once the tree has room.
	env2 := newEscrowSetup(t)
	if ok, _ := env2.env.callNative(env2.env.evm(escrowBlock, nil), env2.a, recommitIn(env2.markerA, f, salt, 1000, note)); !ok {
		t.Fatal("recommit of the whole fails")
	}
	if slot := env2.env.escrowSlot(env2.markerA); slot.Open || !slot.Recommitted.Eq(uint256.NewInt(1000)) {
		t.Fatalf("recommit of the whole left %+v", slot)
	}
}

// TestEscrowNativesCloseAndAccounting checks close and the accounting of a
// slot: after a pay, a recommit and an action debit, close forfeits the
// rest, out = remaining + paid + recommitted + action_debits + forfeited
// holds at every step, total_escrow falls to zero, the closed slot keeps
// words 0 to 3 and clears 4 to 7, every function refuses it, and the logs of
// section 7.5 are written: slot-paid, slot-recommitted and slot-closed with
// the forfeited value.
func TestEscrowNativesCloseAndAccounting(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	dest := common.HexToAddress("0x00000000000000000000000000000000d0d0d0d4")
	var salt [ghostpriv.SaltSize]byte
	note := escrowNote(6, ghostpriv.NoteSize)
	logs := len(env.state.Logs())
	balanced := func(step string) {
		slot := env.escrowSlot(s.markerA)
		if !slot.Balanced() || !slot.Out.Eq(uint256.NewInt(1000)) {
			t.Fatalf("%s: slot out of balance: %+v", step, slot)
		}
	}
	if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, payIn(s.markerA, dest, 100)); !ok {
		t.Fatal("pay fails")
	}
	balanced("pay")
	if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, recommitIn(s.markerA, common.Hash{3}, salt, 200, note)); !ok {
		t.Fatal("recommit fails")
	}
	balanced("recommit")
	if err := ghostpriv.DebitEscrowSlot(env.state, escrowBlock, s.a, s.markerA, uint256.NewInt(50)); err != nil {
		t.Fatal(err)
	}
	balanced("action debit")
	if env.escrowSlot(s.markerA).ActionNonce != 1 {
		t.Fatal("the action debit did not spend the nonce")
	}
	ok, data := env.callNative(env.evm(escrowBlock, nil), s.a, closeIn(s.markerA))
	if !ok || !bytes.Equal(data, word(0)) {
		t.Fatalf("close fails: %v %x", ok, data)
	}
	balanced("close")
	slot := env.escrowSlot(s.markerA)
	if slot.Open || !slot.Remaining.IsZero() || !slot.Paid.Eq(uint256.NewInt(100)) || !slot.Recommitted.Eq(uint256.NewInt(200)) ||
		!slot.ActionDebits.Eq(uint256.NewInt(50)) || !slot.Forfeited.Eq(uint256.NewInt(650)) || slot.ActionNonce != 1 || slot.Policy != s.a {
		t.Fatalf("closed slot %+v", slot)
	}
	words := env.slotWordsOf(s.markerA)
	for i := 4; i < ghostpriv.EscrowSlotWords; i++ {
		if words[i] != (common.Hash{}) {
			t.Fatalf("word %d of a closed slot is %x", i, words[i])
		}
	}
	if !ghostpriv.TotalEscrow(env.state).Eq(uint256.NewInt(1000)) {
		t.Fatalf("total escrow %v, want B's 1,000 only", ghostpriv.TotalEscrow(env.state))
	}
	// A closed slot reads with open 0, and refuses every write.
	ok, data = env.callNative(env.evm(escrowBlock, nil), s.a, slotIn(s.markerA))
	if !ok || !bytes.Equal(data[32:64], word(0)) || !bytes.Equal(data[64:96], word(1)) || !bytes.Equal(data[11*32:], make([]byte, 4*32)) {
		t.Fatalf("closed slot reads %x", data)
	}
	for name, in := range map[string][]byte{
		"pay":      payIn(s.markerA, dest, 1),
		"recommit": recommitIn(s.markerA, common.Hash{3}, salt, 1, note),
		"close":    closeIn(s.markerA),
	} {
		before := env.fingerprint()
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, in); ok {
			t.Errorf("%s on a closed slot succeeds", name)
		}
		if env.fingerprint() != before {
			t.Errorf("%s on a closed slot changed the state", name)
		}
	}
	// The logs of section 7.5, in order.
	var escrowLogs []*types.Log
	for _, l := range env.state.Logs()[logs:] {
		if l.Address == ghost.EscrowAccount {
			escrowLogs = append(escrowLogs, l)
		}
	}
	wantLogs := []struct {
		tag  string
		data []byte
	}{
		{ghostpriv.TagSlotPaid, cat(addrWord(dest), word(100))},
		{ghostpriv.TagSlotRecommitted, word(200)},
		{ghostpriv.TagSlotClosed, word(650)},
	}
	if len(escrowLogs) != len(wantLogs) {
		t.Fatalf("%d escrow logs, want %d", len(escrowLogs), len(wantLogs))
	}
	for i, w := range wantLogs {
		l := escrowLogs[i]
		if len(l.Topics) != 2 || l.Topics[0] != ghosttree.K(w.tag) || l.Topics[1] != s.markerA || !bytes.Equal(l.Data, w.data) || l.BlockNumber != escrowBlock {
			t.Errorf("log %d: %+v, want %s", i, l, w.tag)
		}
	}
}

// TestEscrowNativesActionContextOnly checks actionMarker() and
// actionSettle(): outside a policy action both fail; inside one, the
// action's policy gets the marker, and the debit and remaining after it;
// another policy, an ordinary contract and a DELEGATECALL into the policy's
// code from a contract that is not frozen get nothing, and an input with
// arguments does not decode.
func TestEscrowNativesActionContextOnly(t *testing.T) {
	s := newEscrowSetup(t)
	env := s.env
	action := &ActionContext{Marker: s.markerA, Policy: s.a, Debit: uint256.NewInt(123), Remaining: uint256.NewInt(877)}
	for _, in := range [][]byte{ActionMarkerSelector[:], ActionSettleSelector[:]} {
		if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, in); ok {
			t.Errorf("%x outside an action succeeds", in)
		}
	}
	inAction := func(to common.Address, in []byte) (bool, []byte) {
		evm := env.evm(escrowBlock, nil)
		if prev := evm.SetActionContext(action); prev != nil {
			t.Fatal("a fresh EVM runs an action")
		}
		defer evm.SetActionContext(nil)
		if evm.RunningAction() != action {
			t.Fatal("the running action is not the one set")
		}
		return env.callNative(evm, to, in)
	}
	ok, data := inAction(s.a, ActionMarkerSelector[:])
	if !ok || !bytes.Equal(data, s.markerA[:]) {
		t.Fatalf("actionMarker in the action: %v %x", ok, data)
	}
	ok, data = inAction(s.a, ActionSettleSelector[:])
	if !ok || !bytes.Equal(data, cat(word(123), word(877))) {
		t.Fatalf("actionSettle in the action: %v %x", ok, data)
	}
	for _, c := range []struct {
		name string
		to   common.Address
		in   []byte
	}{
		{"another policy, actionMarker", s.b, ActionMarkerSelector[:]},
		{"another policy, actionSettle", s.b, ActionSettleSelector[:]},
		{"ordinary contract", s.x, ActionMarkerSelector[:]},
		{"DELEGATECALL into the policy's code", s.d, ActionMarkerSelector[:]},
		{"DELEGATECALL into the policy's code, settle", s.d, ActionSettleSelector[:]},
		{"arguments", s.a, cat(ActionMarkerSelector[:], word(1))},
	} {
		if ok, data := inAction(c.to, c.in); ok || len(data) != 0 {
			t.Errorf("%s in the action: success %v, %d bytes", c.name, ok, len(data))
		}
	}
	// The action context never reaches another EVM.
	if ok, _ := env.callNative(env.evm(escrowBlock, nil), s.a, ActionMarkerSelector[:]); ok {
		t.Fatal("actionMarker succeeds after the action")
	}
}
