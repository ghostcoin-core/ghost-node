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
// otherwise.
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
	default:
		// A proof the verifier rejects, and a statement the node cannot
		// verify, are both answered 0.
		return uintWord(0), gas, nil
	}
}
