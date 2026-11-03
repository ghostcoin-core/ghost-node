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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// Frozen policies (spec 10, section 6; docs/ghost-evm-profile.md).
//
// A frame runs in a frozen context when its own address, the one whose
// storage and balance it would use, is a registered policy, or when it is
// the constructor of a policy the factory is creating. The flag is computed
// once when the frame is set up and kept on the Contract, so the
// interpreter reads the registry only for the opcodes whose target it
// checks.
//
// A frozen frame halts on every opcode of frozenOpcodes and on EXTCODESIZE,
// EXTCODECOPY and EXTCODEHASH of an address that is not a registered
// policy, and its CALL and STATICCALL halt unless the target is on the
// allowlist (ghost.IsFrozenCallTarget) or a policy created in an earlier
// block. A policy never holds a balance: a CALL with value to it fails, a
// SELFDESTRUCT that would credit it halts, and the factory burns a balance
// sent to the address ahead of the creation.

var (
	// ErrFrozenCallTarget is returned by a CALL or STATICCALL from a
	// frozen context to a target it may not call.
	ErrFrozenCallTarget = errors.New("frozen context: call target not allowed")

	// ErrPolicyValue is returned for a CALL with value to a registered
	// policy and for a SELFDESTRUCT whose beneficiary is one. Nothing moves.
	ErrPolicyValue = errors.New("value sent to a frozen policy")

	// ErrPolicyFactoryCall is returned for a STATICCALL, CALLCODE or
	// DELEGATECALL to the policy factory: only a CALL creates a policy.
	ErrPolicyFactoryCall = errors.New("policy factory reached without CALL")

	// ErrPolicyFactoryValue is returned for a CALL with value to the policy
	// factory. Nothing moves.
	ErrPolicyFactoryValue = errors.New("value sent to the policy factory")

	// ErrPolicyFactoryInput is returned for a factory input shorter than
	// its 32-byte salt.
	ErrPolicyFactoryInput = errors.New("policy factory: input shorter than the salt")

	// ErrPolicyReservedAddress is returned when the policy address is a
	// reserved address.
	ErrPolicyReservedAddress = errors.New("policy factory: reserved address")
)

// ErrFrozenOpcode is returned when a frozen context runs an opcode the frozen
// context forbids.
type ErrFrozenOpcode struct {
	opcode OpCode
}

func (e *ErrFrozenOpcode) Error() string {
	return fmt.Sprintf("frozen context: opcode %s not allowed", e.opcode)
}

// Opcode returns the forbidden opcode.
func (e *ErrFrozenOpcode) Opcode() OpCode { return e.opcode }

// FrozenOpcodes lists the opcodes a frozen context may never run (spec 10,
// section 6.2): the balance reads, every way to create, delegate or
// self-destruct, and the blob opcodes, which are invalid on Ghost anyway.
// The chain facts, the caller, origin, gas price and remaining gas, the
// frame's own storage and transient storage, and the logs are allowed; the
// writes among them fail in a static frame as the base client has it. A
// frozen frame is never a CALLCODE or DELEGATECALL frame, so the storage it
// reaches is its own account's.
var FrozenOpcodes = []OpCode{
	BALANCE, SELFBALANCE,
	CALLCODE, DELEGATECALL,
	CREATE, CREATE2,
	SELFDESTRUCT,
	BLOBHASH, BLOBBASEFEE,
}

// frozenOpcodes is FrozenOpcodes as a lookup table for the interpreter.
var frozenOpcodes = func() (table [256]bool) {
	for _, op := range FrozenOpcodes {
		table[op] = true
	}
	return table
}()

// FrozenExtcodeOpcodes lists the opcodes a frozen context may run only on
// the address of a frozen policy. The address is the top stack item; on any
// other address, a precompile or a native included, the frame halts with
// ErrFrozenOpcode.
var FrozenExtcodeOpcodes = []OpCode{EXTCODESIZE, EXTCODECOPY, EXTCODEHASH}

// frozenExtcodeOpcodes is FrozenExtcodeOpcodes as a lookup table for the
// interpreter.
var frozenExtcodeOpcodes = func() (table [256]bool) {
	for _, op := range FrozenExtcodeOpcodes {
		table[op] = true
	}
	return table
}()

// frozenExtcodeAllowed reports whether a frozen context may read the code of
// addr: only when addr is a registered policy.
func (evm *EVM) frozenExtcodeAllowed(addr common.Address) bool {
	return ghost.IsRegisteredPolicy(evm.StateDB, addr)
}

// Frozen reports whether the contract runs in a frozen context. The natives
// a frozen context may call look at it on their caller; a DELEGATECALL into
// a policy from a contract that is not frozen runs in that contract's
// context, so it is not frozen and has no such access.
func (c *Contract) Frozen() bool { return c.frozen }

// callerFrozen reports whether caller is a frame in a frozen context; a
// CALLCODE or DELEGATECALL frame runs in its caller's context and takes its
// flag. A frozen context cannot run either opcode, so in practice this is
// false.
func callerFrozen(caller ContractRef) bool {
	parent, ok := caller.(*Contract)
	return ok && parent.frozen
}

// checkPolicyBeneficiary refuses a SELFDESTRUCT that would credit a non-zero
// balance to a registered policy: the frame halts and nothing moves.
func checkPolicyBeneficiary(evm *EVM, beneficiary common.Address, balance *uint256.Int) error {
	if !balance.IsZero() && ghost.IsRegisteredPolicy(evm.StateDB, beneficiary) {
		return ErrPolicyValue
	}
	return nil
}

// frozenCallAllowed reports whether a frozen context may CALL or STATICCALL
// addr.
func (evm *EVM) frozenCallAllowed(addr common.Address) bool {
	if ghost.IsFrozenCallTarget(addr) {
		return true
	}
	return ghost.IsCallablePolicy(evm.StateDB, addr, evm.Context.BlockNumber.Uint64())
}

// eip3860 reports whether the initcode limit and metering of EIP-3860 apply.
func (evm *EVM) eip3860() bool {
	rules := evm.ChainConfig()
	return rules.IsEnabledByTime(rules.GetEIP3860TransitionTime, &evm.Context.Time) ||
		rules.IsEnabled(rules.GetEIP3860Transition, evm.Context.BlockNumber)
}

// PolicyFactoryGas is the gas a factory call charges before it runs the
// constructor: the gas of a CREATE2 of initCodeSize bytes (Create2Gas, the
// Keccak-256 word gas of the init code and, under EIP-3860, its init code
// word gas) plus ghost.PolicyRegistryGas for the registry entry. The
// constructor's gas and the code deposit come on top, as for CREATE2.
func PolicyFactoryGas(initCodeSize uint64, eip3860 bool) uint64 {
	words := toWordSize(initCodeSize)
	wordGas := vars.Keccak256WordGas
	if eip3860 {
		wordGas += vars.InitCodeWordGas
	}
	return vars.Create2Gas + words*wordGas + ghost.PolicyRegistryGas
}

// callPolicyFactory runs a CALL to the policy factory. The input is a
// 32-byte salt followed by the init code; the output is the policy address
// as a 32-byte word. The constructor runs in a frozen context at
// ghost.PolicyAddress(salt, keccak256(initCode)), whoever the caller is.
func (evm *EVM) callPolicyFactory(caller ContractRef, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	if value != nil && !value.IsZero() {
		return nil, gas, ErrPolicyFactoryValue
	}
	if in, ok := evm.interpreter.(*EVMInterpreter); ok && in.readOnly {
		return nil, 0, ErrWriteProtection
	}
	if tracer := evm.Config.Tracer; tracer != nil {
		if evm.depth == 0 {
			tracer.CaptureStart(evm, caller.Address(), ghost.PolicyFactoryAddress, false, input, gas, nil)
			defer func(startGas uint64) {
				tracer.CaptureEnd(ret, startGas-leftOverGas, err)
			}(gas)
		} else {
			tracer.CaptureEnter(CALL, caller.Address(), ghost.PolicyFactoryAddress, input, gas, nil)
			defer func(startGas uint64) {
				tracer.CaptureExit(ret, startGas-leftOverGas, err)
			}(gas)
		}
	}
	if len(input) < common.HashLength {
		return nil, 0, ErrPolicyFactoryInput
	}
	var (
		salt     = common.BytesToHash(input[:common.HashLength])
		initCode = common.CopyBytes(input[common.HashLength:])
		eip3860  = evm.eip3860()
	)
	if eip3860 && uint64(len(initCode)) > vars.MaxInitCodeSize {
		return nil, 0, ErrMaxInitCodeSizeExceeded
	}
	cost := PolicyFactoryGas(uint64(len(initCode)), eip3860)
	if gas < cost {
		return nil, 0, ErrOutOfGas
	}
	gas -= cost

	code := &codeAndHash{code: initCode}
	address := ghost.PolicyAddress(salt, code.Hash())
	if ghost.IsReservedAddress(address) {
		return nil, 0, ErrPolicyReservedAddress
	}
	ret, leftOverGas, err = evm.createPolicy(code, gas, address)
	if err != nil {
		return ret, leftOverGas, err
	}
	return common.LeftPadBytes(address.Bytes(), common.HashLength), leftOverGas, nil
}

// createPolicy runs the constructor of a policy at address in a frozen
// context, stores its code and writes its registry entry. A failed
// constructor leaves nothing, no account, no code and no registry entry. A
// balance the address already holds is burned.
func (evm *EVM) createPolicy(code *codeAndHash, gas uint64, address common.Address) ([]byte, uint64, error) {
	if evm.depth > int(vars.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	if evm.ChainConfig().IsEnabled(evm.chainConfig.GetEIP2929Transition, evm.Context.BlockNumber) {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// A policy address is never reused: not for a second creation with the
	// same code and salt, and not over an account that has a nonce or code.
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash) {
		return nil, 0, ErrContractAddressCollision
	}
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	// A balance sent to the address before the policy exists is burned: a
	// policy never holds one, and the creation does not fail for it.
	if balance := evm.StateDB.GetBalance(address); !balance.IsZero() {
		evm.StateDB.SubBalance(address, new(uint256.Int).Set(balance))
	}
	if evm.ChainConfig().IsEnabled(evm.chainConfig.GetEIP161abcTransition, evm.Context.BlockNumber) {
		evm.StateDB.SetNonce(address, 1)
	}
	factory := AccountRef(ghost.PolicyFactoryAddress)
	contract := NewContract(factory, AccountRef(address), new(uint256.Int), gas)
	contract.SetCodeOptionalHash(&address, code)
	contract.frozen = true

	if tracer := evm.Config.Tracer; tracer != nil {
		tracer.CaptureEnter(CREATE2, factory.Address(), address, code.code, gas, nil)
	}
	ret, err := run(evm, contract, nil, false)

	if err == nil && evm.ChainConfig().IsEnabled(evm.chainConfig.GetEIP170Transition, evm.Context.BlockNumber) && uint64(len(ret)) > vars.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.ChainConfig().IsEnabled(evm.chainConfig.GetEIP3541Transition, evm.Context.BlockNumber) {
		err = ErrInvalidCode
	}
	if err == nil {
		if contract.UseGas(uint64(len(ret)) * vars.CreateDataGas) {
			evm.StateDB.SetCode(address, ret)
			ghost.RegisterPolicy(evm.StateDB, address, evm.Context.BlockNumber.Uint64(), crypto.Keccak256Hash(ret))
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	if tracer := evm.Config.Tracer; tracer != nil {
		tracer.CaptureExit(ret, gas-contract.Gas, err)
	}
	return ret, contract.Gas, err
}
