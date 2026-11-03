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
	"encoding/binary"
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

// The values recorded for Guard: a change to its code, init code or salt
// changes them, and must record them again here and in
// docs/ghost-evm-profile.md.
const (
	guardRecordedAddress  = "0xCA99390eEd6c683a6807cC4d74F44a84A3ba0c3c"
	guardRecordedCodeHash = "0xbeae0e084bf5f9d091bff3b25afb2aa8bc0f63e4b0cda06e5def2ea3b25a86d8"
)

// The selectors of Guard's entry points.
var (
	guardReleaseSelector = escrowSelector("release(bytes32)")
	guardCancelSelector  = escrowSelector("cancel(bytes32,bytes16,bytes)")
)

// The block and time a Guard slot of these tests opens in, and the first
// block and time release may pay in.
const (
	guardOpenHeight = 100
	guardOpenTime   = ghost.InternalNetTimestamp + 4_000

	guardFloorHeight = guardOpenHeight + ghost.GuardHoldBlocks
	guardFloorTime   = guardOpenTime + ghost.GuardHoldSeconds
)

func guardReleaseIn(marker common.Hash) []byte { return cat(guardReleaseSelector[:], marker[:]) }

// guardCancelIn is the calldata of cancel(f, salt, note): the selector, f,
// the salt word, the note's offset 0x60 and length, and the note padded to a
// whole word.
func guardCancelIn(f common.Hash, salt [ghostpriv.SaltSize]byte, note []byte) []byte {
	padded := make([]byte, (len(note)+31)/32*32)
	copy(padded, note)
	return cat(guardCancelSelector[:], f[:], common.RightPadBytes(salt[:], 32), word(0x60), word(uint64(len(note))), padded)
}

// guardInstr is the instruction word that pays to dest.
func guardInstr(dest common.Address) common.Hash { return common.BytesToHash(dest[:]) }

// guardEnv is a state on the internal network's configuration with Guard
// created through the factory in block 1.
type guardEnv struct {
	*policyEnv
	guard common.Address
}

func newGuardEnv(t *testing.T) *guardEnv {
	t.Helper()
	env := newPolicyEnv(t)
	addr, err := env.create(1, policySender, ghost.GuardSalt, ghost.GuardInitCode)
	if err != nil {
		t.Fatalf("the factory refuses Guard: %v", err)
	}
	return &guardEnv{policyEnv: env, guard: addr}
}

// open opens the slot of marker for Guard with out and instr, in block
// guardOpenHeight at guardOpenTime.
func (g *guardEnv) open(marker common.Hash, out uint64, instr common.Hash) {
	g.t.Helper()
	err := ghostpriv.OpenEscrowSlot(g.state, marker, &ghostpriv.EscrowSlot{
		Policy:     g.guard,
		Out:        uint256.NewInt(out),
		Height:     guardOpenHeight,
		Timestamp:  guardOpenTime,
		ActionTag:  ghosttree.K("ghost/test-guard-action-tag", marker[:]),
		ActionSalt: ghosttree.K("ghost/test-guard-action-salt", marker[:]),
		Instr:      instr,
	})
	if err != nil {
		g.t.Fatal(err)
	}
}

// at returns an EVM for block number with timestamp time, which the tests
// set apart from the number, running action when it is not nil.
func (g *guardEnv) at(number, time uint64, action *ActionContext, tracer EVMLogger) preparedEVM {
	g.block = func(ctx *BlockContext) { ctx.Time = time }
	defer func() { g.block = nil }()
	evm := g.evm(number, tracer)
	evm.SetActionContext(action)
	return evm
}

// settle takes debit from the slot of marker, as the settlement of a policy
// action does before its call (ghostpriv.SettleAction), and returns the
// action the escrow natives answer for during the call.
func (g *guardEnv) settle(marker common.Hash, debit uint64) *ActionContext {
	g.t.Helper()
	if err := ghostpriv.DebitEscrowSlot(g.state, guardOpenHeight+1, g.guard, marker, uint256.NewInt(debit)); err != nil {
		g.t.Fatalf("action debit: %v", err)
	}
	return &ActionContext{
		Marker:    marker,
		Policy:    g.guard,
		Debit:     uint256.NewInt(debit),
		Remaining: new(uint256.Int).Set(g.escrowSlot(marker).Remaining),
	}
}

// release sends release(marker) from sender in block number at time.
func (g *guardEnv) release(number, time uint64, sender common.Address, marker common.Hash) ([]byte, error) {
	ret, _, err := g.at(number, time, nil, nil).Call(AccountRef(sender), g.guard, guardReleaseIn(marker), policyTestGas, new(uint256.Int))
	return ret, err
}

// cancel runs input as the call of action, from ACTION_CALLER with the
// gas of an action call, in block number at time.
func (g *guardEnv) cancel(number, time uint64, action *ActionContext, input []byte) ([]byte, error) {
	g.tx = &TxContext{Origin: ghost.ActionCallerAddress, GasPrice: new(big.Int)}
	defer func() { g.tx = nil }()
	ret, _, err := g.at(number, time, action, nil).Call(AccountRef(ghost.ActionCallerAddress), g.guard, input, ghostpriv.ActionCallGas, new(uint256.Int))
	return ret, err
}

// refused checks that run fails as a revert with empty data and changes
// nothing.
func (g *guardEnv) refused(what string, run func() ([]byte, error)) {
	g.t.Helper()
	before := g.fingerprint()
	ret, err := run()
	if !errors.Is(err, ErrExecutionReverted) || len(ret) != 0 {
		g.t.Errorf("%s: error %v and %d bytes, want a revert with empty data", what, err, len(ret))
	}
	if g.fingerprint() != before {
		g.t.Errorf("%s changed the state", what)
	}
}

// succeeds checks that run succeeds and returns nothing.
func (g *guardEnv) succeeds(what string, run func() ([]byte, error)) {
	g.t.Helper()
	ret, err := run()
	if err != nil || len(ret) != 0 {
		g.t.Fatalf("%s: error %v and output %x, want success with no output", what, err, ret)
	}
}

func (g *guardEnv) balance(addr common.Address) uint64 { return g.state.GetBalance(addr).Uint64() }

// guardWallet stands in for a wallet restored from its words alone: the
// words give commitment number i a fingerprint F_i, and the note of a coin
// carries its value masked under the words and a check value, so only the
// words read it. A restore reads nothing but the commit receipts.
type guardWallet struct{ words string }

const guardWalletGap = 3

func (w guardWallet) secret(tag string, i int) common.Hash {
	return ghosttree.K(tag, []byte(w.words), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

func (w guardWallet) fingerprint(i int) common.Hash {
	return w.secret("ghost/test-guard-wallet/fingerprint", i)
}

func (w guardWallet) note(i int, v uint64) []byte {
	note := make([]byte, ghostpriv.NoteSize)
	value, mask, check := word(v), w.secret("ghost/test-guard-wallet/note-mask", i), w.secret("ghost/test-guard-wallet/note-check", i)
	for j := range value {
		note[j] = value[j] ^ mask[j]
	}
	copy(note[32:64], check[:])
	return note
}

func (w guardWallet) openNote(i int, note []byte) (*uint256.Int, bool) {
	check := w.secret("ghost/test-guard-wallet/note-check", i)
	if !bytes.Equal(note[32:64], check[:]) {
		return nil, false
	}
	mask := w.secret("ghost/test-guard-wallet/note-mask", i)
	value := make([]byte, 32)
	for j := range value {
		value[j] = note[j] ^ mask[j]
	}
	return new(uint256.Int).SetBytes(value), true
}

// guardCoin is a coin a restore found.
type guardCoin struct {
	index int
	value *uint256.Int
	salt  []byte
}

// restore finds the wallet's coins in the commit receipts of logs: for each
// commitment number, up to a gap of unused ones, a receipt whose note opens
// under the words, whose leaf is the version 2 commitment of F_i and the
// note's value and whose amount is that value.
func (w guardWallet) restore(t *testing.T, logs []*types.Log) []guardCoin {
	t.Helper()
	const receiptSize = 8 + 32 + 32 + ghostpriv.NoteSize + ghostpriv.SaltSize
	var found []guardCoin
	for i, misses := 0, 0; misses < guardWalletGap; i++ {
		var match *guardCoin
		for _, l := range logs {
			if l.Address != ghosttree.TreeAccount(ghosttree.Coin) || l.Topics[0] != ghosttree.K(ghostpriv.TagCommitReceipt) || len(l.Data) != receiptSize {
				continue
			}
			note := l.Data[72 : 72+ghostpriv.NoteSize]
			v, ok := w.openNote(i, note)
			if !ok {
				continue
			}
			if leaf := ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, w.fingerprint(i), v); common.BytesToHash(l.Data[8:40]) != leaf {
				t.Fatalf("the note of commitment %d opens, but the leaf is not its commitment", i)
			}
			if !new(uint256.Int).SetBytes(l.Data[40:72]).Eq(v) {
				t.Fatalf("the receipt of commitment %d has amount %x, the note says %v", i, l.Data[40:72], v)
			}
			match = &guardCoin{index: i, value: v, salt: l.Data[72+ghostpriv.NoteSize:]}
		}
		if match == nil {
			misses++
			continue
		}
		misses = 0
		found = append(found, *match)
	}
	return found
}

// guardTracer records every opcode the Guard frame runs, every frame Guard
// enters and every fault.
type guardTracer struct {
	guard  common.Address
	ops    map[OpCode]bool
	enters []guardEnter
	faults []error
}

type guardEnter struct {
	op    OpCode
	to    common.Address
	value *big.Int
}

func newGuardTracer(guard common.Address) *guardTracer {
	return &guardTracer{guard: guard, ops: make(map[OpCode]bool)}
}

func (g *guardTracer) CaptureTxStart(uint64) {}
func (g *guardTracer) CaptureTxEnd(uint64)   {}
func (g *guardTracer) CaptureStart(*EVM, common.Address, common.Address, bool, []byte, uint64, *big.Int) {
}
func (g *guardTracer) CaptureEnd([]byte, uint64, error) {}
func (g *guardTracer) CaptureEnter(op OpCode, from common.Address, to common.Address, _ []byte, _ uint64, value *big.Int) {
	if from == g.guard {
		g.enters = append(g.enters, guardEnter{op, to, value})
	}
}
func (g *guardTracer) CaptureExit([]byte, uint64, error) {}
func (g *guardTracer) CaptureState(_ uint64, op OpCode, _, _ uint64, scope *ScopeContext, _ []byte, _ int, err error) {
	if scope.Contract.Address() == g.guard {
		if !scope.Contract.Frozen() {
			g.faults = append(g.faults, errors.New("the Guard frame is not frozen"))
		}
		g.ops[op] = true
	}
	if err != nil {
		g.faults = append(g.faults, err)
	}
}
func (g *guardTracer) CaptureFault(_ uint64, _ OpCode, _, _ uint64, _ *ScopeContext, _ int, err error) {
	g.faults = append(g.faults, err)
}

// guardAllowedOpcodes is the opcode set of a frozen context (spec 10,
// section 6.2) that Guard may draw on: arithmetic and comparison, KECCAK256,
// the caller and calldata, the frame's own code, the return data, the chain
// facts, memory, the stack, jumps, GAS, own storage, the logs, CALL and
// STATICCALL to an allowed target, and the ends of a frame.
var guardAllowedOpcodes = func() map[OpCode]bool {
	allowed := make(map[OpCode]bool)
	for _, op := range []OpCode{
		STOP, ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND,
		LT, GT, SLT, SGT, EQ, ISZERO, AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR,
		KECCAK256,
		ADDRESS, ORIGIN, CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, CALLDATACOPY,
		CODESIZE, CODECOPY, GASPRICE, RETURNDATASIZE, RETURNDATACOPY,
		BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, BASEFEE,
		POP, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, JUMP, JUMPI, PC, JUMPDEST, GAS,
		LOG0, LOG1, LOG2, LOG3, LOG4,
		CALL, STATICCALL, RETURN, REVERT, INVALID,
	} {
		allowed[op] = true
	}
	for op := PUSH0; op <= PUSH32; op++ {
		allowed[op] = true
	}
	for op := OpCode(DUP1); op <= DUP16; op++ {
		allowed[op] = true
	}
	for op := OpCode(SWAP1); op <= SWAP16; op++ {
		allowed[op] = true
	}
	return allowed
}()

// guardInstruction is one instruction of a code listing.
type guardInstruction struct {
	pc   int
	op   OpCode
	data []byte
}

// disassemble splits code into instructions; a PUSH that runs past the end
// fails the test.
func disassemble(t *testing.T, code []byte) []guardInstruction {
	t.Helper()
	var out []guardInstruction
	for pc := 0; pc < len(code); {
		op := OpCode(code[pc])
		n := 0
		if op >= PUSH1 && op <= PUSH32 {
			n = int(op-PUSH1) + 1
		}
		if pc+1+n > len(code) {
			t.Fatalf("PUSH at %#x runs past the end of the code", pc)
		}
		out = append(out, guardInstruction{pc: pc, op: op, data: code[pc+1 : pc+1+n]})
		pc += 1 + n
	}
	return out
}

// TestGuardDeploysThroughFactory checks that Guard is created through the
// policy factory: its constructor runs in a frozen context without a fault,
// the factory stores GuardRuntimeCode and registers it, the policy holds no
// balance, any sender in any block gets the same address, and the address
// is never created twice. Any other selector or calldata length reverts.
func TestGuardDeploysThroughFactory(t *testing.T) {
	env := newPolicyEnv(t)
	tracer := &frozenTracer{}
	addr, code, _, err := env.construct(1, ghost.GuardSalt, ghost.GuardInitCode, tracer)
	if err != nil {
		t.Fatalf("the factory refuses Guard: %v", err)
	}
	if len(tracer.faults) != 0 {
		t.Fatalf("the constructor faults: %v", tracer.faults[0].err)
	}
	if len(tracer.frames) == 0 {
		t.Fatal("the constructor did not run")
	}
	for _, f := range tracer.frames {
		if !f.frozen || f.self != addr {
			t.Fatalf("a constructor frame at %v runs frozen %v, want frozen at %v", f.self, f.frozen, addr)
		}
	}
	if want := ghost.PolicyAddress(ghost.GuardSalt, crypto.Keccak256Hash(ghost.GuardInitCode)); addr != want {
		t.Fatalf("Guard at %v, want %v", addr, want)
	}
	if !bytes.Equal(code, ghost.GuardRuntimeCode) {
		t.Fatalf("the factory stored %d bytes, not GuardRuntimeCode (%d bytes)", len(code), len(ghost.GuardRuntimeCode))
	}
	height, codeHash, ok := ghost.PolicyRegistryEntry(env.state, addr)
	if !ok || height != 1 || codeHash != crypto.Keccak256Hash(code) {
		t.Fatalf("registry entry: registered %v, height %d, code hash %x", ok, height, codeHash)
	}
	if !env.state.GetBalance(addr).IsZero() {
		t.Fatal("Guard holds a balance")
	}

	// The same address from another sender in a later block.
	env2 := newPolicyEnv(t)
	addr2, err := env2.create(7, policySender2, ghost.GuardSalt, ghost.GuardInitCode)
	if err != nil || addr2 != addr {
		t.Fatalf("the second creation gives %v, %v; want %v", addr2, err, addr)
	}
	// Never twice at the same address.
	if _, err := env.create(2, policySender2, ghost.GuardSalt, ghost.GuardInitCode); !errors.Is(err, ErrContractAddressCollision) {
		t.Fatalf("a second Guard in the same state: %v, want an address collision", err)
	}

	// Any other selector or calldata length reverts.
	g := &guardEnv{policyEnv: env, guard: addr}
	marker := escrowMarker("guard-dispatch")
	g.open(marker, 1000, guardInstr(common.HexToAddress("0x9a4d000000000000000000000000000000000001")))
	f := ghosttree.K("ghost/test-guard-f")
	var salt [ghostpriv.SaltSize]byte
	note := escrowNote(1, ghostpriv.NoteSize)
	for name, in := range map[string][]byte{
		"empty calldata":           nil,
		"three bytes":              guardReleaseSelector[:3],
		"release selector alone":   guardReleaseSelector[:],
		"another selector":         cat(EscrowSlotSelector[:], marker[:]),
		"release with 516 bytes":   cat(guardReleaseSelector[:], guardCancelIn(f, salt, note)[4:]),
		"cancel with 36 bytes":     cat(guardCancelSelector[:], marker[:]),
		"the escrow pay selector":  cat(EscrowPaySelector[:], guardCancelIn(f, salt, note)[4:]),
		"a selector of zero bytes": make([]byte, 36),
	} {
		g.refused(name, func() ([]byte, error) {
			ret, _, err := g.at(guardFloorHeight, guardFloorTime, nil, nil).Call(AccountRef(policySender), addr, in, policyTestGas, new(uint256.Int))
			return ret, err
		})
	}
	// The slot is still there for a release.
	g.succeeds("release", func() ([]byte, error) { return g.release(guardFloorHeight, guardFloorTime, policySender, marker) })
}

// TestGuardConstantsMatchFactory checks the exports of params/ghost/guard.go
// against what the factory reports for Guard, and against the values
// recorded for it: the address, the registry's code hash, the salt, the two
// floors, and the selectors and floors the code carries.
func TestGuardConstantsMatchFactory(t *testing.T) {
	g := newGuardEnv(t)
	if g.guard != ghost.GuardAddress {
		t.Fatalf("the factory reports %v, GuardAddress is %v", g.guard, ghost.GuardAddress)
	}
	_, codeHash, ok := ghost.PolicyRegistryEntry(g.state, g.guard)
	if !ok || codeHash != ghost.GuardCodeHash || crypto.Keccak256Hash(g.state.GetCode(g.guard)) != ghost.GuardCodeHash {
		t.Fatalf("the registry has code hash %x (registered %v), GuardCodeHash is %x", codeHash, ok, ghost.GuardCodeHash)
	}
	if ghost.GuardAddress != common.HexToAddress(guardRecordedAddress) || ghost.GuardCodeHash != common.HexToHash(guardRecordedCodeHash) {
		t.Fatalf("Guard is at %v with code hash %x, recorded %s and %s", ghost.GuardAddress, ghost.GuardCodeHash, guardRecordedAddress, guardRecordedCodeHash)
	}
	if ghost.GuardSalt != ghosttree.K("ghost/guard-salt/v1") {
		t.Fatalf("GuardSalt is %x", ghost.GuardSalt)
	}
	if ghost.GuardHoldBlocks != 8_640 || ghost.GuardHoldSeconds != 72*3600 || ghost.GuardHoldBlocks*30 != ghost.GuardHoldSeconds {
		t.Fatalf("hold of %d blocks and %d seconds", ghost.GuardHoldBlocks, ghost.GuardHoldSeconds)
	}
	code := ghost.GuardRuntimeCode
	pushes := map[string][]byte{
		"HOLD_BLOCKS":  cat([]byte{byte(PUSH2)}, word(ghost.GuardHoldBlocks)[30:]),
		"HOLD_SECONDS": cat([]byte{byte(PUSH3)}, word(ghost.GuardHoldSeconds)[29:]),
	}
	for name, sel := range map[string][4]byte{
		"release":      guardReleaseSelector,
		"cancel":       guardCancelSelector,
		"slot":         EscrowSlotSelector,
		"pay":          EscrowPaySelector,
		"recommit":     EscrowRecommitSelector,
		"actionMarker": ActionMarkerSelector,
		"actionSettle": ActionSettleSelector,
	} {
		pushes[name] = cat([]byte{byte(PUSH4)}, sel[:])
	}
	for name, push := range pushes {
		if bytes.Count(code, push) != 1 {
			t.Errorf("the code carries the push of %s %d times, want once", name, bytes.Count(code, push))
		}
	}
	initCode := ghost.GuardInitCode
	if !bytes.Equal(initCode[12:], code) || int(initCode[1])<<8|int(initCode[2]) != len(code) || initCode[5] != 12 {
		t.Fatal("the init code does not copy out GuardRuntimeCode")
	}
}

// TestGuardUsesOnlyAllowedOpcodes checks the code itself: the init code and
// the runtime code use only opcodes a frozen context allows, every jump goes
// to a JUMPDEST, and every CALL and STATICCALL goes to the escrow natives at
// 0x60, a CALL with value zero. It then runs release and cancel, through
// success and failure, and checks the Guard frame ran only allowed opcodes,
// frozen, without a fault, and entered no frame but 0x60.
func TestGuardUsesOnlyAllowedOpcodes(t *testing.T) {
	forbidden := make(map[OpCode]bool)
	for _, op := range FrozenOpcodes {
		forbidden[op] = true
	}
	for _, op := range FrozenExtcodeOpcodes {
		forbidden[op] = true
	}
	for name, code := range map[string][]byte{"init code": ghost.GuardInitCode[:12], "runtime code": ghost.GuardRuntimeCode} {
		listing := disassemble(t, code)
		dests := make(map[int]bool)
		for _, in := range listing {
			if in.op == JUMPDEST {
				dests[in.pc] = true
			}
		}
		for i, in := range listing {
			if !guardAllowedOpcodes[in.op] || forbidden[in.op] {
				t.Errorf("%s: %v at %#x", name, in.op, in.pc)
			}
			switch in.op {
			case JUMP, JUMPI:
				prev := listing[i-1]
				if prev.op != PUSH2 || !dests[int(prev.data[0])<<8|int(prev.data[1])] {
					t.Errorf("%s: %v at %#x does not jump to a JUMPDEST", name, in.op, in.pc)
				}
			case CALL, STATICCALL:
				gas, target := listing[i-1], listing[i-2]
				if gas.op != GAS || target.op != PUSH1 || target.data[0] != 0x60 {
					t.Errorf("%s: %v at %#x is not a call to 0x60", name, in.op, in.pc)
				}
				if value := listing[i-3]; in.op == CALL && (value.op != PUSH1 || value.data[0] != 0) {
					t.Errorf("%s: CALL at %#x carries value", name, in.pc)
				}
			}
		}
		if last := listing[len(listing)-1].op; last != STOP && last != RETURN {
			t.Errorf("%s ends with %v", name, last)
		}
	}

	// Every path, run.
	g := newGuardEnv(t)
	dest := common.HexToAddress("0x9a4d000000000000000000000000000000000002")
	f := ghosttree.K("ghost/test-guard-f")
	var salt [ghostpriv.SaltSize]byte
	note := escrowNote(2, ghostpriv.NoteSize)
	paid, cancelled := escrowMarker("guard-ops-release"), escrowMarker("guard-ops-cancel")
	g.open(paid, 1000, guardInstr(dest))
	g.open(cancelled, 1000, guardInstr(dest))
	action := g.settle(cancelled, 10)
	tracer := newGuardTracer(g.guard)
	run := func(number, time uint64, action *ActionContext, in []byte) error {
		_, _, err := g.at(number, time, action, tracer).Call(AccountRef(policySender), g.guard, in, policyTestGas, new(uint256.Int))
		return err
	}
	for _, c := range []struct {
		name         string
		number, time uint64
		action       *ActionContext
		in           []byte
		ok           bool
	}{
		{"release before the floors", guardOpenHeight + 1, guardOpenTime + 30, nil, guardReleaseIn(paid), false},
		{"release", guardFloorHeight, guardFloorTime, nil, guardReleaseIn(paid), true},
		{"cancel outside an action", guardOpenHeight + 1, guardOpenTime + 30, nil, guardCancelIn(f, salt, note), false},
		{"cancel", guardOpenHeight + 1, guardOpenTime + 30, action, guardCancelIn(f, salt, note), true},
		{"bad selector", guardOpenHeight + 1, guardOpenTime + 30, nil, []byte{1, 2, 3, 4}, false},
	} {
		if err := run(c.number, c.time, c.action, c.in); (err == nil) != c.ok {
			t.Fatalf("%s: error %v, want success %v", c.name, err, c.ok)
		}
	}
	if !g.escrowSlot(paid).Paid.Eq(uint256.NewInt(1000)) || !g.escrowSlot(cancelled).Recommitted.Eq(uint256.NewInt(990)) {
		t.Fatal("the runs did not pay and recommit")
	}
	for _, err := range tracer.faults {
		if !errors.Is(err, ErrExecutionReverted) {
			t.Errorf("fault while Guard runs: %v", err)
		}
	}
	if len(tracer.ops) == 0 {
		t.Fatal("no opcode of the Guard frame traced")
	}
	for op := range tracer.ops {
		if !guardAllowedOpcodes[op] || forbidden[op] {
			t.Errorf("Guard ran %v", op)
		}
	}
	if len(tracer.enters) == 0 {
		t.Fatal("Guard entered no frame")
	}
	for _, e := range tracer.enters {
		if e.to != ghost.EscrowNativeAddress || (e.op != CALL && e.op != STATICCALL) || (e.value != nil && e.value.Sign() != 0) {
			t.Errorf("Guard entered %v at %v with value %v", e.op, e.to, e.value)
		}
	}
}

// TestGuardRP25ReleaseFloors checks RP-25's floors: release fails while
// either floor is not reached, the block floor height + 8,640 or the time
// floor timestamp + 72 hours, however far past the other one the block is,
// and changes nothing; at both floors exactly it pays.
func TestGuardRP25ReleaseFloors(t *testing.T) {
	g := newGuardEnv(t)
	dest := common.HexToAddress("0x9a4d000000000000000000000000000000000003")
	marker := escrowMarker("guard-floors")
	g.open(marker, 1000, guardInstr(dest))
	for _, c := range []struct {
		name         string
		number, time uint64
	}{
		{"the opening block", guardOpenHeight, guardOpenTime},
		{"one block short", guardFloorHeight - 1, guardFloorTime},
		{"one second short", guardFloorHeight, guardFloorTime - 1},
		{"one block and one second short", guardFloorHeight - 1, guardFloorTime - 1},
		{"far past the block floor, one second short", guardFloorHeight + 1_000_000, guardFloorTime - 1},
		{"far past the time floor, one block short", guardFloorHeight - 1, guardFloorTime + 100*ghost.GuardHoldSeconds},
		{"the time floor at the opening height", guardOpenHeight, guardFloorTime},
		{"the block floor at the opening time", guardFloorHeight, guardOpenTime},
	} {
		g.refused(c.name, func() ([]byte, error) { return g.release(c.number, c.time, policySender, marker) })
	}
	if g.balance(dest) != 0 || !g.escrowSlot(marker).Open {
		t.Fatal("a refused release paid")
	}
	g.succeeds("release at both floors", func() ([]byte, error) {
		return g.release(guardFloorHeight, guardFloorTime, policySender, marker)
	})
	if g.balance(dest) != 1000 {
		t.Fatalf("dest has %d, want 1000", g.balance(dest))
	}
}

// TestGuardRP25ReleasePaysAfterFloors checks RP-25's payment: after both
// floors, release from anyone, an account that is not the depositor or an
// ordinary contract, pays all of remaining, after an action's debit too, to
// the address in instr, closes the slot and pays the sender nothing; a
// release with any other calldata length reverts, and a second release of
// the closed slot fails.
func TestGuardRP25ReleasePaysAfterFloors(t *testing.T) {
	g := newGuardEnv(t)
	dest1 := common.HexToAddress("0x9a4d000000000000000000000000000000000004")
	dest2 := common.HexToAddress("0x9a4d000000000000000000000000000000000005")
	m1, m2 := escrowMarker("guard-pay-1"), escrowMarker("guard-pay-2")
	g.open(m1, 1000, guardInstr(dest1))
	g.open(m2, 2500, guardInstr(dest2))
	g.settle(m2, 300)

	for name, in := range map[string][]byte{
		"35 bytes":    guardReleaseIn(m1)[:35],
		"37 bytes":    cat(guardReleaseIn(m1), []byte{0}),
		"68 bytes":    cat(guardReleaseIn(m1), word(0)),
		"the marker":  m1[:],
		"no selector": cat([]byte{0, 0, 0, 0}, m1[:]),
	} {
		g.refused(name, func() ([]byte, error) {
			ret, _, err := g.at(guardFloorHeight, guardFloorTime, nil, nil).Call(AccountRef(policySender2), g.guard, in, policyTestGas, new(uint256.Int))
			return ret, err
		})
	}

	escrowBefore := ghostpriv.TotalEscrow(g.state).Uint64()
	sender1, sender2 := g.balance(policySender), g.balance(policySender2)
	logs := len(g.state.Logs())
	g.succeeds("release by another account", func() ([]byte, error) {
		return g.release(guardFloorHeight, guardFloorTime, policySender2, m1)
	})
	slot := g.escrowSlot(m1)
	if g.balance(dest1) != 1000 || slot.Open || !slot.Remaining.IsZero() || !slot.Paid.Eq(uint256.NewInt(1000)) || !slot.Balanced() {
		t.Fatalf("after release dest has %d and the slot is %+v", g.balance(dest1), slot)
	}
	if g.balance(policySender) != sender1 || g.balance(policySender2) != sender2 || g.balance(g.guard) != 0 {
		t.Fatal("release moved value to the sender or to Guard")
	}
	if got := ghostpriv.TotalEscrow(g.state).Uint64(); got != escrowBefore-1000 {
		t.Fatalf("total escrow %d, want %d", got, escrowBefore-1000)
	}
	var paidLog *types.Log
	for _, l := range g.state.Logs()[logs:] {
		if l.Address == ghost.EscrowAccount && l.Topics[0] == ghosttree.K(ghostpriv.TagSlotPaid) {
			paidLog = l
		}
	}
	if paidLog == nil || paidLog.Topics[1] != m1 || !bytes.Equal(paidLog.Data, cat(addrWord(dest1), word(1000))) {
		t.Fatalf("slot-paid log %+v", paidLog)
	}

	// From an ordinary contract, later: all of remaining, not out.
	relay := common.HexToAddress("0x0bad0000000000000000000000000000000000e1")
	g.setContract(relay, forwarderCode(g.guard))
	if _, _, err := g.at(guardFloorHeight+50, guardFloorTime+5_000, nil, nil).Call(AccountRef(policySender), relay, guardReleaseIn(m2), policyTestGas, new(uint256.Int)); err != nil {
		t.Fatal(err)
	}
	if g.slot(relay, 1).Sign() == 0 {
		t.Fatal("release through an ordinary contract fails")
	}
	if g.balance(dest2) != 2200 || g.balance(relay) != 0 || !g.escrowSlot(m2).Paid.Eq(uint256.NewInt(2200)) {
		t.Fatalf("dest has %d after the debit of 300 from 2,500", g.balance(dest2))
	}

	g.refused("a second release", func() ([]byte, error) {
		return g.release(guardFloorHeight+100, guardFloorTime+10_000, policySender, m1)
	})
}

// TestGuardRP25ReleaseRefusesDirtyInstr checks that release fails, after
// both floors, when any of the top 12 bytes of instr is not zero, and pays
// the same low 20 bytes once they are.
func TestGuardRP25ReleaseRefusesDirtyInstr(t *testing.T) {
	g := newGuardEnv(t)
	dest := common.HexToAddress("0x9a4d000000000000000000000000000000000006")
	dirty := map[string]common.Hash{}
	for _, i := range []int{0, 5, 11} {
		instr := guardInstr(dest)
		instr[i] = 0x01
		dirty[fmt.Sprintf("byte %d", i)] = instr
	}
	all := guardInstr(dest)
	for i := 0; i < 12; i++ {
		all[i] = 0xff
	}
	dirty["all twelve"] = all
	for name, instr := range dirty {
		marker := escrowMarker("guard-dirty-" + name)
		g.open(marker, 1000, instr)
		tracer := newGuardTracer(g.guard)
		g.refused("instr with "+name+" set", func() ([]byte, error) {
			ret, _, err := g.at(guardFloorHeight+10, guardFloorTime+10, nil, tracer).Call(AccountRef(policySender), g.guard, guardReleaseIn(marker), policyTestGas, new(uint256.Int))
			return ret, err
		})
		if !g.escrowSlot(marker).Open {
			t.Fatalf("instr with %s set: the slot closed", name)
		}
		// Guard refuses it itself: it reads the slot and never calls pay.
		if len(tracer.enters) != 1 || tracer.enters[0].op != STATICCALL {
			t.Fatalf("instr with %s set: Guard entered %+v, want the slot read alone", name, tracer.enters)
		}
	}
	if g.balance(dest) != 0 {
		t.Fatal("a dirty instr paid")
	}
	clean := escrowMarker("guard-clean")
	g.open(clean, 1000, guardInstr(dest))
	g.succeeds("clean instr", func() ([]byte, error) {
		return g.release(guardFloorHeight+10, guardFloorTime+10, policySender, clean)
	})
	if g.balance(dest) != 1000 {
		t.Fatalf("dest has %d", g.balance(dest))
	}
}

// guardCancelSetup is a Guard slot of 1,000 wei, a wallet and the input of
// a cancel to its commitment 1 of value.
type guardCancelSetup struct {
	*guardEnv
	marker common.Hash
	dest   common.Address
	wallet guardWallet
	salt   [ghostpriv.SaltSize]byte
}

func newGuardCancelSetup(t *testing.T) *guardCancelSetup {
	g := newGuardEnv(t)
	s := &guardCancelSetup{
		guardEnv: g,
		marker:   escrowMarker("guard-cancel"),
		dest:     common.HexToAddress("0x9a4d000000000000000000000000000000000007"),
		wallet:   guardWallet{words: "synthetic guard test words"},
		salt:     [ghostpriv.SaltSize]byte{0x5a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}
	g.open(s.marker, 1000, guardInstr(s.dest))
	return s
}

// input is the cancel to commitment 1 of the wallet with value.
func (s *guardCancelSetup) input(value uint64) []byte {
	return guardCancelIn(s.wallet.fingerprint(1), s.salt, s.wallet.note(1, value))
}

// TestGuardRP26CancelRecommits checks RP-26's cancel: a policy action whose
// call is cancel(F_new, salt_new, note_new), before the floors, re-commits
// remaining - debit to F_new as a version 2 coin with the note and salt,
// closes the slot, and a restore from the wallet's words alone finds the
// new coin. A cancel with any other calldata length, or with another note
// offset or length, reverts.
func TestGuardRP26CancelRecommits(t *testing.T) {
	s := newGuardCancelSetup(t)
	action := s.settle(s.marker, 150)
	if coins := s.wallet.restore(t, s.state.Logs()); len(coins) != 0 {
		t.Fatalf("the wallet has %d coins before the cancel", len(coins))
	}
	at := func(in []byte) func() ([]byte, error) {
		return func() ([]byte, error) { return s.cancel(guardOpenHeight+1, guardOpenTime+30, action, in) }
	}
	good := s.input(850)
	badOffset := common.CopyBytes(good)
	badOffset[4+2*32+31] = 0x80
	badLength := common.CopyBytes(good)
	badLength[4+3*32+31]++
	for name, in := range map[string][]byte{
		"515 bytes":        good[:515],
		"517 bytes":        cat(good, []byte{0}),
		"548 bytes":        cat(good, word(0)),
		"release selector": cat(guardReleaseSelector[:], good[4:]),
		"note offset 0x80": badOffset,
		"note length 381":  badLength,
		"note of 379":      guardCancelIn(s.wallet.fingerprint(1), s.salt, s.wallet.note(1, 850)[:379]),
	} {
		s.refused(name, at(in))
	}

	leaves := coinLeaves(s.policyEnv)
	inBefore, _ := ghostpriv.Totals(s.state)
	s.succeeds("cancel", at(good))
	slot := s.escrowSlot(s.marker)
	if slot.Open || !slot.Remaining.IsZero() || !slot.Recommitted.Eq(uint256.NewInt(850)) || !slot.ActionDebits.Eq(uint256.NewInt(150)) || !slot.Paid.IsZero() || !slot.Balanced() {
		t.Fatalf("slot after cancel %+v", slot)
	}
	if coinLeaves(s.policyEnv) != leaves+1 {
		t.Fatalf("the coin tree has %d leaves, want %d", coinLeaves(s.policyEnv), leaves+1)
	}
	inAfter, _ := ghostpriv.Totals(s.state)
	if new(uint256.Int).Sub(inAfter, inBefore).Uint64() != 850 {
		t.Fatalf("total in rose by %v, want 850", new(uint256.Int).Sub(inAfter, inBefore))
	}
	coins := s.wallet.restore(t, s.state.Logs())
	if len(coins) != 1 || coins[0].index != 1 || !coins[0].value.Eq(uint256.NewInt(850)) || !bytes.Equal(coins[0].salt, s.salt[:]) {
		t.Fatalf("the restore finds %+v, want commitment 1 of 850 with the salt", coins)
	}
	if other := (guardWallet{words: "other synthetic test words"}).restore(t, s.state.Logs()); len(other) != 0 {
		t.Fatal("another wallet's words find the coin")
	}
	if s.balance(s.dest) != 0 {
		t.Fatal("the cancel paid dest")
	}
}

// TestGuardRP26ReleaseAfterCancelFails checks that once a cancel closed the
// slot, a release fails after both floors and pays nothing.
func TestGuardRP26ReleaseAfterCancelFails(t *testing.T) {
	s := newGuardCancelSetup(t)
	action := s.settle(s.marker, 100)
	s.succeeds("cancel", func() ([]byte, error) {
		return s.cancel(guardOpenHeight+1, guardOpenTime+30, action, s.input(900))
	})
	for _, c := range []struct{ number, time uint64 }{
		{guardFloorHeight, guardFloorTime},
		{guardFloorHeight + 10_000, guardFloorTime + 1_000_000},
	} {
		s.refused("release after cancel", func() ([]byte, error) { return s.release(c.number, c.time, policySender, s.marker) })
	}
	if s.balance(s.dest) != 0 || !s.escrowSlot(s.marker).Paid.IsZero() {
		t.Fatal("release after cancel paid")
	}
}

// TestGuardCancelAfterReleaseFails checks that once a release closed the
// slot, no action can settle on it, and a cancel run as if one had, with
// the remaining the slot had before, fails and commits nothing.
func TestGuardCancelAfterReleaseFails(t *testing.T) {
	s := newGuardCancelSetup(t)
	s.succeeds("release", func() ([]byte, error) {
		return s.release(guardFloorHeight, guardFloorTime, policySender, s.marker)
	})
	if err := ghostpriv.DebitEscrowSlot(s.state, guardFloorHeight+1, s.guard, s.marker, new(uint256.Int)); !errors.Is(err, ghostpriv.ErrEscrowSlotClosed) {
		t.Fatalf("an action settles on the released slot: %v", err)
	}
	stale := &ActionContext{Marker: s.marker, Policy: s.guard, Debit: new(uint256.Int), Remaining: uint256.NewInt(1000)}
	leaves := coinLeaves(s.policyEnv)
	s.refused("cancel after release", func() ([]byte, error) {
		return s.cancel(guardFloorHeight+1, guardFloorTime+30, stale, s.input(1000))
	})
	if coinLeaves(s.policyEnv) != leaves || !s.escrowSlot(s.marker).Recommitted.IsZero() {
		t.Fatal("cancel after release committed a coin")
	}
	if len(s.wallet.restore(t, s.state.Logs())) != 0 {
		t.Fatal("the wallet finds a coin")
	}
}

// TestGuardCancelNeedsAction checks that cancel fails outside a policy
// action, sent as an ordinary transaction or by ACTION_CALLER, and in an
// action of another policy, changing nothing; in the slot's own action it
// recommits.
func TestGuardCancelNeedsAction(t *testing.T) {
	s := newGuardCancelSetup(t)
	in := s.input(1000)
	s.refused("cancel in an ordinary transaction", func() ([]byte, error) {
		ret, _, err := s.at(guardOpenHeight+1, guardOpenTime+30, nil, nil).Call(AccountRef(policySender), s.guard, in, policyTestGas, new(uint256.Int))
		return ret, err
	})
	s.refused("cancel from ACTION_CALLER without an action", func() ([]byte, error) {
		return s.cancel(guardOpenHeight+1, guardOpenTime+30, nil, in)
	})
	s.refused("cancel after both floors without an action", func() ([]byte, error) {
		return s.cancel(guardFloorHeight, guardFloorTime, nil, in)
	})
	other := &ActionContext{Marker: s.marker, Policy: common.HexToAddress("0x9a4d0000000000000000000000000000000000ff"), Debit: new(uint256.Int), Remaining: uint256.NewInt(1000)}
	s.refused("cancel in another policy's action", func() ([]byte, error) {
		return s.cancel(guardOpenHeight+1, guardOpenTime+30, other, in)
	})
	if !s.escrowSlot(s.marker).Open {
		t.Fatal("the slot closed")
	}
	action := s.settle(s.marker, 0)
	s.succeeds("cancel in the slot's action", func() ([]byte, error) {
		return s.cancel(guardOpenHeight+1, guardOpenTime+30, action, in)
	})
	if !s.escrowSlot(s.marker).Recommitted.Eq(uint256.NewInt(1000)) {
		t.Fatal("cancel did not recommit")
	}
}

// TestGuardCancelDebitEqualsRemaining checks that an action whose debit is
// all of remaining leaves nothing to re-commit: its cancel fails and no coin
// is committed. A debit one below remaining re-commits the one wei left.
func TestGuardCancelDebitEqualsRemaining(t *testing.T) {
	s := newGuardCancelSetup(t)
	action := s.settle(s.marker, 1000)
	if !action.Remaining.IsZero() {
		t.Fatalf("remaining %v after a debit of all of it", action.Remaining)
	}
	leaves := coinLeaves(s.policyEnv)
	inBefore, _ := ghostpriv.Totals(s.state)
	s.refused("cancel with debit equal to remaining", func() ([]byte, error) {
		return s.cancel(guardOpenHeight+1, guardOpenTime+30, action, s.input(0))
	})
	inAfter, _ := ghostpriv.Totals(s.state)
	slot := s.escrowSlot(s.marker)
	if coinLeaves(s.policyEnv) != leaves || !inAfter.Eq(inBefore) || !slot.Recommitted.IsZero() || !slot.ActionDebits.Eq(uint256.NewInt(1000)) {
		t.Fatalf("something was re-committed: slot %+v", slot)
	}
	if len(s.wallet.restore(t, s.state.Logs())) != 0 {
		t.Fatal("the wallet finds a coin")
	}

	one := escrowMarker("guard-cancel-one-left")
	s.open(one, 1000, guardInstr(s.dest))
	action = s.settle(one, 999)
	s.succeeds("cancel with one wei left", func() ([]byte, error) {
		return s.cancel(guardOpenHeight+1, guardOpenTime+30, action, s.input(1))
	})
	if !s.escrowSlot(one).Recommitted.Eq(uint256.NewInt(1)) {
		t.Fatal("the one wei left was not re-committed")
	}
	if coins := s.wallet.restore(t, s.state.Logs()); len(coins) != 1 || !coins[0].value.Eq(uint256.NewInt(1)) {
		t.Fatalf("the restore finds %+v", coins)
	}
}
