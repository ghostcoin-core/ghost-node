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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The escrow natives at 0x60 (spec 10, sections 7.2 and 7.4). A frozen
// policy reads and changes its own escrow slots through them: slot, pay,
// recommit and close, and, inside a policy action, actionMarker and
// actionSettle. The input is the function's 4-byte selector, the first four
// bytes of the Keccak-256 of its signature, followed by its arguments in the
// strict ABI encoding: every word in place and nothing after the last.
//
// Every function charges a flat gas, whatever it does or whether it fails.
// A failure is revert-style: the call returns failure with empty return
// data, its flat gas is spent, the rest of the call's gas goes back to the
// caller, and nothing it did is kept. A function fails when:
//
//   - the native is reached other than by CALL or STATICCALL, or a CALL
//     carries value, or the input does not decode;
//   - the caller, the executing account (ADDRESS of the frame that made the
//     call, never ORIGIN), is not a frame in a frozen context, or is not the
//     policy the slot belongs to; a DELEGATECALL into a policy from a
//     contract that is not frozen runs as that contract, so it reaches no
//     slot of the policy;
//   - pay, recommit or close runs in a static context (the static-context
//     rule): slot, actionMarker and actionSettle only read and run in one;
//   - the slot change itself fails (core/ghostpriv/escrow.go).
//
// An input that names no function fails the same way, for the smallest flat
// gas, EscrowActionMarkerGas.

// The flat gas of each function. None is below the sum rule of section 7.2,
// the cold storage reads and the stores and new account the function may
// make; actionMarker and actionSettle read no storage, only the running
// action.
const (
	EscrowSlotGas         uint64 = 16_900
	EscrowPayGas          uint64 = 56_000
	EscrowRecommitGas     uint64 = 31_000
	EscrowCloseGas        uint64 = 20_000
	EscrowActionMarkerGas uint64 = 200
	EscrowActionSettleGas uint64 = 200
)

// The selectors of the escrow natives.
var (
	EscrowSlotSelector     = escrowSelector("slot(bytes32)")
	EscrowPaySelector      = escrowSelector("pay(bytes32,address,uint256)")
	EscrowRecommitSelector = escrowSelector("recommit(bytes32,bytes32,bytes16,uint256,bytes)")
	EscrowCloseSelector    = escrowSelector("close(bytes32)")
	ActionMarkerSelector   = escrowSelector("actionMarker()")
	ActionSettleSelector   = escrowSelector("actionSettle()")
)

func escrowSelector(sig string) [4]byte {
	var s [4]byte
	copy(s[:], crypto.Keccak256([]byte(sig)))
	return s
}

// EscrowSlotWordCount is the number of 32-byte words slot() returns: the
// fifteen fields of the slot in the order of the slot's storage words.
const EscrowSlotWordCount = 15

// The input lengths of the functions.
const (
	escrowMarkerInputSize   = 4 + 32
	escrowPayInputSize      = 4 + 3*32
	escrowRecommitHeadWords = 5
	escrowRecommitNoteWords = (ghostpriv.NoteSize + 31) / 32
	escrowRecommitInputSize = 4 + escrowRecommitHeadWords*32 + 32 + escrowRecommitNoteWords*32
)

var (
	// ErrEscrowAccountCall is returned for any call from inside the EVM to
	// one of the escrow's native accounts, ESCROW_ACCOUNT, POLICY_REGISTRY
	// and ACTION_CALLER, which, like the commit entry addresses, uses up the
	// gas it was given.
	ErrEscrowAccountCall = errors.New("call to an escrow native account")

	// errEscrowInput is the reason for an input that does not decode.
	errEscrowInput = errors.New("escrow native: input does not decode")

	// errEscrowCaller is the reason for a caller that is not the frozen
	// policy the slot or the action belongs to.
	errEscrowCaller = errors.New("escrow native: caller is not the slot's frozen policy")

	// errEscrowStatic is the reason for a write in a static context.
	errEscrowStatic = errors.New("escrow native: write in a static context")

	// errEscrowCallKind is the reason for a CALLCODE or DELEGATECALL, or a
	// CALL with value, to the native.
	errEscrowCallKind = errors.New("escrow native: reached other than by CALL or STATICCALL without value")

	// errNoAction is the reason for actionMarker or actionSettle outside a
	// policy action.
	errNoAction = errors.New("escrow native: no policy action running")
)

// ActionContext is what the escrow natives know of the policy action that
// runs: the marker of its slot, the slot's policy, its debit and the slot's
// remaining after it. core.ApplyPolicyAction sets it on the EVM for the
// policy call only.
type ActionContext struct {
	Marker    common.Hash
	Policy    common.Address
	Debit     *uint256.Int
	Remaining *uint256.Int
}

// SetActionContext sets the running policy action, nil for none, and
// returns the one before.
func (evm *EVM) SetActionContext(a *ActionContext) *ActionContext {
	prev := evm.action
	evm.action = a
	return prev
}

// RunningAction returns the running policy action, nil outside one.
func (evm *EVM) RunningAction() *ActionContext { return evm.action }

// escrowNativeGas is the flat gas of the function input names, the smallest
// flat gas for an input that names none.
func escrowNativeGas(input []byte) uint64 {
	if len(input) < 4 {
		return EscrowActionMarkerGas
	}
	switch [4]byte(input[:4]) {
	case EscrowSlotSelector:
		return EscrowSlotGas
	case EscrowPaySelector:
		return EscrowPayGas
	case EscrowRecommitSelector:
		return EscrowRecommitGas
	case EscrowCloseSelector:
		return EscrowCloseGas
	case ActionMarkerSelector:
		return EscrowActionMarkerGas
	case ActionSettleSelector:
		return EscrowActionSettleGas
	}
	return EscrowActionMarkerGas
}

// isStatic reports whether the EVM runs in a static context.
func (evm *EVM) isStatic() bool {
	in, ok := evm.interpreter.(*EVMInterpreter)
	return ok && in.readOnly
}

// callEscrowNative runs a call of kind op (CALL, CALLCODE, DELEGATECALL or
// STATICCALL) from caller to the escrow natives at 0x60.
func (evm *EVM) callEscrowNative(op OpCode, caller ContractRef, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	if tracer := evm.Config.Tracer; tracer != nil {
		var v *big.Int
		if value != nil && op != STATICCALL && op != DELEGATECALL {
			v = value.ToBig()
		}
		if evm.depth == 0 {
			tracer.CaptureStart(evm, caller.Address(), ghost.EscrowNativeAddress, false, input, gas, v)
			defer func(startGas uint64) {
				tracer.CaptureEnd(ret, startGas-leftOverGas, err)
			}(gas)
		} else {
			tracer.CaptureEnter(op, caller.Address(), ghost.EscrowNativeAddress, input, gas, v)
			defer func(startGas uint64) {
				tracer.CaptureExit(ret, startGas-leftOverGas, err)
			}(gas)
		}
	}
	cost := escrowNativeGas(input)
	if gas < cost {
		return nil, 0, ErrOutOfGas
	}
	gas -= cost
	static := op == STATICCALL || evm.isStatic()
	if op != CALL && op != STATICCALL || value != nil && !value.IsZero() {
		return nil, gas, ErrExecutionReverted
	}
	snapshot := evm.StateDB.Snapshot()
	out, ferr := evm.runEscrowNative(caller, input, static)
	if ferr != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		return nil, gas, ErrExecutionReverted
	}
	return out, gas, nil
}

// frozenCaller returns the address of caller when it is a frame in a frozen
// context, the executing account of the call, and false otherwise.
func frozenCaller(caller ContractRef) (common.Address, bool) {
	c, ok := caller.(*Contract)
	if !ok || !c.frozen {
		return common.Address{}, false
	}
	return c.Address(), true
}

// runEscrowNative decodes input and runs the function it names for caller.
func (evm *EVM) runEscrowNative(caller ContractRef, input []byte, static bool) ([]byte, error) {
	if len(input) < 4 {
		return nil, errEscrowInput
	}
	self, ok := frozenCaller(caller)
	if !ok {
		return nil, errEscrowCaller
	}
	height := evm.Context.BlockNumber.Uint64()
	args := input[4:]
	switch [4]byte(input[:4]) {
	case EscrowSlotSelector:
		if len(input) != escrowMarkerInputSize {
			return nil, errEscrowInput
		}
		marker := common.BytesToHash(args)
		slot, ok := ghostpriv.ReadEscrowSlot(evm.StateDB, marker)
		if !ok || slot.Policy != self {
			return nil, errEscrowCaller
		}
		return EscrowSlotWords(slot), nil

	case EscrowPaySelector:
		if len(input) != escrowPayInputSize {
			return nil, errEscrowInput
		}
		if static {
			return nil, errEscrowStatic
		}
		marker := common.BytesToHash(args[:32])
		dest, ok := addressWord(args[32:64])
		if !ok {
			return nil, errEscrowInput
		}
		amount, ok := amountArg(args[64:96])
		if !ok {
			return nil, errEscrowInput
		}
		if err := ghostpriv.PayEscrowSlot(evm.StateDB, height, self, marker, dest, amount); err != nil {
			return nil, err
		}
		return evm.remainingWord(marker), nil

	case EscrowRecommitSelector:
		if static {
			return nil, errEscrowStatic
		}
		marker, f, salt, amount, note, err := decodeRecommit(args)
		if err != nil {
			return nil, err
		}
		if err := ghostpriv.RecommitEscrowSlot(evm.StateDB, height, self, marker, f, salt, amount, note); err != nil {
			return nil, err
		}
		return evm.remainingWord(marker), nil

	case EscrowCloseSelector:
		if len(input) != escrowMarkerInputSize {
			return nil, errEscrowInput
		}
		if static {
			return nil, errEscrowStatic
		}
		marker := common.BytesToHash(args)
		if err := ghostpriv.CloseEscrowSlot(evm.StateDB, height, self, marker); err != nil {
			return nil, err
		}
		return evm.remainingWord(marker), nil

	case ActionMarkerSelector:
		a, err := evm.actionOf(self, input)
		if err != nil {
			return nil, err
		}
		return common.CopyBytes(a.Marker[:]), nil

	case ActionSettleSelector:
		a, err := evm.actionOf(self, input)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, 64)
		out = append(out, amountWordOf(a.Debit)...)
		out = append(out, amountWordOf(a.Remaining)...)
		return out, nil
	}
	return nil, errEscrowInput
}

// actionOf returns the running action when the input is a bare selector and
// self is the action's policy.
func (evm *EVM) actionOf(self common.Address, input []byte) (*ActionContext, error) {
	if len(input) != 4 {
		return nil, errEscrowInput
	}
	if evm.action == nil {
		return nil, errNoAction
	}
	if evm.action.Policy != self {
		return nil, errEscrowCaller
	}
	return evm.action, nil
}

// remainingWord returns the remaining of the slot of marker as a word.
func (evm *EVM) remainingWord(marker common.Hash) []byte {
	slot, ok := ghostpriv.ReadEscrowSlot(evm.StateDB, marker)
	if !ok {
		return make([]byte, 32)
	}
	return amountWordOf(slot.Remaining)
}

// EscrowSlotWords returns the fifteen 32-byte words slot() returns for a
// slot, in the order of the slot's storage words: the policy address, open
// (1 or 0), the action nonce, remaining, out, the opening height and
// timestamp, paid, recommitted, the action debits, forfeited, the
// parameters hash, the action tag, the action salt and the instruction.
// Integers are right-aligned and the address in the last 20 bytes.
func EscrowSlotWords(s *ghostpriv.EscrowSlot) []byte {
	out := make([]byte, 0, EscrowSlotWordCount*32)
	open := uint64(0)
	if s.Open {
		open = 1
	}
	out = append(out, common.LeftPadBytes(s.Policy[:], 32)...)
	out = append(out, uintWord(open)...)
	out = append(out, uintWord(s.ActionNonce)...)
	out = append(out, amountWordOf(s.Remaining)...)
	out = append(out, amountWordOf(s.Out)...)
	out = append(out, uintWord(s.Height)...)
	out = append(out, uintWord(s.Timestamp)...)
	out = append(out, amountWordOf(s.Paid)...)
	out = append(out, amountWordOf(s.Recommitted)...)
	out = append(out, amountWordOf(s.ActionDebits)...)
	out = append(out, amountWordOf(s.Forfeited)...)
	out = append(out, s.ParamsHash[:]...)
	out = append(out, s.ActionTag[:]...)
	out = append(out, s.ActionSalt[:]...)
	out = append(out, s.Instr[:]...)
	return out
}

func uintWord(v uint64) []byte {
	w := make([]byte, 32)
	binary.BigEndian.PutUint64(w[24:], v)
	return w
}

func amountWordOf(v *uint256.Int) []byte {
	if v == nil {
		return make([]byte, 32)
	}
	w := v.Bytes32()
	return w[:]
}

// addressWord decodes an ABI address word: twelve zero bytes, then the
// address.
func addressWord(w []byte) (common.Address, bool) {
	if !isZeroBytes(w[:12]) {
		return common.Address{}, false
	}
	return common.BytesToAddress(w[12:32]), true
}

// amountArg decodes an amount word, valid only below 2^96.
func amountArg(w []byte) (*uint256.Int, bool) {
	if !isZeroBytes(w[:20]) {
		return nil, false
	}
	return new(uint256.Int).SetBytes(w[:32]), true
}

func isZeroBytes(b []byte) bool {
	return len(bytes.TrimLeft(b, "\x00")) == 0
}

// decodeRecommit decodes the arguments of recommit(bytes32 marker, bytes32
// f, bytes16 salt, uint256 amount, bytes note): five head words, the note's
// offset 0xa0, its length, which must be the 380 bytes of a note, and the
// note padded with zeros to a whole word, and nothing more.
func decodeRecommit(args []byte) (marker, f common.Hash, salt [ghostpriv.SaltSize]byte, amount *uint256.Int, note [ghostpriv.NoteSize]byte, err error) {
	const head = escrowRecommitHeadWords * 32
	if len(args) < head+32 {
		err = errEscrowInput
		return
	}
	marker = common.BytesToHash(args[0:32])
	f = common.BytesToHash(args[32:64])
	if !isZeroBytes(args[64+ghostpriv.SaltSize : 96]) {
		err = errEscrowInput
		return
	}
	copy(salt[:], args[64:64+ghostpriv.SaltSize])
	var ok bool
	if amount, ok = amountArg(args[96:128]); !ok {
		err = errEscrowInput
		return
	}
	offset := new(uint256.Int).SetBytes(args[128:160])
	if !offset.IsUint64() || offset.Uint64() != head {
		err = errEscrowInput
		return
	}
	length := new(uint256.Int).SetBytes(args[head : head+32])
	if !length.IsUint64() || length.Uint64() != ghostpriv.NoteSize || len(args)+4 != escrowRecommitInputSize {
		err = errEscrowInput
		return
	}
	body := args[head+32:]
	if !isZeroBytes(body[ghostpriv.NoteSize:]) {
		err = errEscrowInput
		return
	}
	copy(note[:], body[:ghostpriv.NoteSize])
	return
}
