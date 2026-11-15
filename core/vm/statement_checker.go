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
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// The statement checker at 0x61 (spec 10, section 9.3). A frozen policy
// calls it, by CALL without value or by STATICCALL, to check a proof of the
// KNOW_PREIMAGE_v1 statement made for it: the input is the statement code
// 0x06, y (32 bytes), the context (64 bytes) and the proof field
// (ghostpriv.ActionProofSize bytes), exactly ghostpriv.PreimageInputSize
// bytes. The checker builds the binding itself, with the calling policy (the
// executing account of the frame that made the call), the chain id of the
// EVM's chain configuration and the genesis hash of the block context, and
// returns a 32-byte word: 1 when the active verifier accepts the proof, 0
// when it rejects it.
//
// A node that cannot verify the statement (a build without the proof
// verifier, or a verifier with no proof system for it) gives no answer: an
// answer of 0 there would differ from a linked node's 1 for the same valid
// proof, and the two would split with neither reporting an invalid proof.
// The call fails with no return data and all its gas spent, and the EVM
// records ErrStatementUnverifiable, which TakeUnverifiable hands to the
// transaction's processing: the transaction, and with it the block, is
// invalid on that node, as for a reveal it cannot verify.
//
// Every call is charged StatementCheckerGas of its input before anything is
// checked, whatever the answer. A call fails revert-style, with empty return
// data, its gas spent and the rest of the call's gas back to the caller,
// when:
//
//   - it is reached other than by CALL or STATICCALL, or a CALL carries
//     value;
//   - the caller is not a frame in a frozen context;
//   - the input is not ghostpriv.PreimageInputSize bytes or its statement
//     code is not 0x06;
//   - the block context has no genesis hash or the chain no chain id (a
//     context built without a chain): the check fails closed.
//
// The checker reads and changes no state.

// StatementCheckerGas returns the gas of a call to the statement checker
// with an input of n bytes: PREIMAGE_VERIFY_GAS plus 3 per 32-byte word.
func StatementCheckerGas(n int) uint64 {
	words := toWordSize(uint64(n))
	if words > (math.MaxUint64-ghost.PreimageVerifyGas)/ghost.StatementCheckerWordGas {
		return math.MaxUint64
	}
	return ghost.PreimageVerifyGas + ghost.StatementCheckerWordGas*words
}

// callStatementChecker runs a call of kind op (CALL, CALLCODE, DELEGATECALL
// or STATICCALL) from caller to the statement checker at 0x61.
func (evm *EVM) callStatementChecker(op OpCode, caller ContractRef, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	if tracer := evm.Config.Tracer; tracer != nil {
		var v *big.Int
		if value != nil && op != STATICCALL && op != DELEGATECALL {
			v = value.ToBig()
		}
		if evm.depth == 0 {
			tracer.CaptureStart(evm, caller.Address(), ghost.StatementCheckerAddress, false, input, gas, v)
			defer func(startGas uint64) {
				tracer.CaptureEnd(ret, startGas-leftOverGas, err)
			}(gas)
		} else {
			tracer.CaptureEnter(op, caller.Address(), ghost.StatementCheckerAddress, input, gas, v)
			defer func(startGas uint64) {
				tracer.CaptureExit(ret, startGas-leftOverGas, err)
			}(gas)
		}
	}
	cost := StatementCheckerGas(len(input))
	if gas < cost {
		return nil, 0, ErrOutOfGas
	}
	gas -= cost
	if op != CALL && op != STATICCALL || value != nil && !value.IsZero() {
		return nil, gas, ErrExecutionReverted
	}
	policy, ok := frozenCaller(caller)
	if !ok {
		return nil, gas, ErrExecutionReverted
	}
	chainID := evm.ChainConfig().GetChainID()
	if chainID == nil || !chainID.IsUint64() || chainID.Sign() == 0 {
		return nil, gas, ErrExecutionReverted
	}
	verr := ghostpriv.VerifyPreimage(nil, chainID.Uint64(), evm.Context.Genesis, policy, input)
	switch {
	case verr == nil:
		return uintWord(1), gas, nil
	case errors.Is(verr, ghostpriv.ErrPreimageInput), errors.Is(verr, ghostpriv.ErrPreimageDomain):
		return nil, gas, ErrExecutionReverted
	case errors.Is(verr, ghostpriv.ErrNoVerifier), errors.Is(verr, ghostpriv.ErrStatementUnsupported):
		// Fail closed: no answer, and the transaction is invalid here.
		if evm.unverifiable == nil {
			evm.unverifiable = fmt.Errorf("%w: %w", ErrStatementUnverifiable, verr)
		}
		return nil, 0, ErrExecutionReverted
	default:
		// A proof the verifier rejects is answered 0.
		return uintWord(0), gas, nil
	}
}

// TakeUnverifiable returns the ErrStatementUnverifiable the statement checker
// recorded since the last call, nil when it recorded none, and clears it.
// Whatever runs a transaction or a policy call through the EVM calls it after
// the call and treats an error as an invalid transaction.
func (evm *EVM) TakeUnverifiable() error {
	err := evm.unverifiable
	evm.unverifiable = nil
	return err
}
