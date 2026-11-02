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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// policyTestGas is the gas of the top-level calls of these tests.
const policyTestGas = 10_000_000

var (
	policySender  = common.HexToAddress("0x5e4de2000000000000000000000000000000aaaa")
	policySender2 = common.HexToAddress("0x5e4de2000000000000000000000000000000bbbb")
)

// cat joins pieces of bytecode.
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func pushAddr(a common.Address) []byte {
	return append([]byte{byte(PUSH20)}, a.Bytes()...)
}

// zeros pushes n zero words, enough stack for any opcode that follows.
func zeros(n int) []byte {
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, byte(PUSH1), 0)
	}
	return out
}

// deployCode returns init code that runs prefix, then copies runtime out of
// itself and returns it as the code to store.
func deployCode(prefix, runtime []byte) []byte {
	n := len(runtime)
	off := len(prefix) + 15
	return cat(prefix,
		[]byte{byte(PUSH2), byte(n >> 8), byte(n)},
		[]byte{byte(PUSH2), byte(off >> 8), byte(off)},
		[]byte{byte(PUSH1), 0, byte(CODECOPY)},
		[]byte{byte(PUSH2), byte(n >> 8), byte(n)},
		[]byte{byte(PUSH1), 0, byte(RETURN)},
		runtime,
	)
}

// returnOneCode returns the word 1.
var returnOneCode = []byte{
	byte(PUSH1), 1, byte(PUSH1), 0, byte(MSTORE),
	byte(PUSH1), 32, byte(PUSH1), 0, byte(RETURN),
}

// forwarderCode is an ordinary contract: it CALLs target with its calldata,
// all its gas and no value, and stores the success flag in slot 1 and the
// first word of the output in slot 0.
func forwarderCode(target common.Address) []byte {
	return cat(
		[]byte{byte(CALLDATASIZE), byte(PUSH1), 0, byte(PUSH1), 0, byte(CALLDATACOPY)},
		[]byte{byte(PUSH1), 32, byte(PUSH1), 0x40, byte(CALLDATASIZE), byte(PUSH1), 0, byte(PUSH1), 0},
		pushAddr(target),
		[]byte{byte(GAS), byte(CALL)},
		[]byte{byte(PUSH1), 1, byte(SSTORE)},
		[]byte{byte(PUSH1), 0x40, byte(MLOAD), byte(PUSH1), 0, byte(SSTORE), byte(STOP)},
	)
}

// targetCallerCode calls the address in the first calldata word with op
// (CALL with no value, or STATICCALL), no input and 1,000,000 gas, and
// returns the success flag. It uses no opcode a frozen context forbids, so
// it runs as a policy too.
func targetCallerCode(op OpCode) []byte {
	code := []byte{byte(PUSH1), 32, byte(PUSH1), 0, byte(PUSH1), 0, byte(PUSH1), 0}
	if op == CALL {
		code = append(code, byte(PUSH1), 0)
	}
	code = append(code, byte(PUSH1), 0, byte(CALLDATALOAD))
	code = append(code, byte(PUSH3), 0x0f, 0x42, 0x40, byte(op))
	return cat(code, []byte{byte(PUSH1), 0, byte(MSTORE), byte(PUSH1), 32, byte(PUSH1), 0, byte(RETURN)})
}

func addrWord(a common.Address) []byte { return common.LeftPadBytes(a.Bytes(), 32) }

func saltOf(i int) common.Hash { return common.BigToHash(big.NewInt(int64(i) + 1)) }

func factoryInput(salt common.Hash, initCode []byte) []byte {
	return append(salt.Bytes(), initCode...)
}

// frozenTracer records the faults and the frames the interpreter reports.
type frozenTracer struct {
	faults []tracedFault
	frames []tracedFrame
}

type tracedFault struct {
	depth int
	err   error
}

type tracedFrame struct {
	code, self common.Address
	frozen     bool
}

func (f *frozenTracer) CaptureTxStart(uint64) {}
func (f *frozenTracer) CaptureTxEnd(uint64)   {}
func (f *frozenTracer) CaptureStart(*EVM, common.Address, common.Address, bool, []byte, uint64, *big.Int) {
}
func (f *frozenTracer) CaptureEnd([]byte, uint64, error) {}
func (f *frozenTracer) CaptureEnter(OpCode, common.Address, common.Address, []byte, uint64, *big.Int) {
}
func (f *frozenTracer) CaptureExit([]byte, uint64, error) {}

func (f *frozenTracer) CaptureState(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		f.faults = append(f.faults, tracedFault{depth, err})
	}
	var code common.Address
	if scope.Contract.CodeAddr != nil {
		code = *scope.Contract.CodeAddr
	}
	f.frames = append(f.frames, tracedFrame{code, scope.Contract.Address(), scope.Contract.Frozen()})
}

func (f *frozenTracer) CaptureFault(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error) {
	f.faults = append(f.faults, tracedFault{depth, err})
}

// frozenOpcodeFault returns the depth of the first frozen-opcode fault of
// op, or -1.
func (f *frozenTracer) frozenOpcodeFault(op OpCode) int {
	for _, fault := range f.faults {
		var fe *ErrFrozenOpcode
		if errors.As(fault.err, &fe) && fe.Opcode() == op {
			return fault.depth
		}
	}
	return -1
}

func (f *frozenTracer) hasFault(target error) bool {
	for _, fault := range f.faults {
		if errors.Is(fault.err, target) {
			return true
		}
	}
	return false
}

// policyEnv is a state on the internal network's configuration that the
// tests run blocks of EVM calls against.
type policyEnv struct {
	t     *testing.T
	state *state.StateDB
}

func newPolicyEnv(t *testing.T) *policyEnv {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(policySender, uint256.NewInt(1_000_000_000))
	statedb.SetBalance(policySender2, uint256.NewInt(1_000_000_000))
	return &policyEnv{t: t, state: statedb}
}

// preparedEVM prepares the access list of a transaction from the caller to
// the target before each top-level Call, as the state transition does.
type preparedEVM struct {
	*EVM
	state *state.StateDB
}

func (p preparedEVM) Call(caller ContractRef, to common.Address, input []byte, gas uint64, value *uint256.Int) ([]byte, uint64, error) {
	p.state.Prepare(true, true, caller.Address(), common.Address{}, &to, p.ActivePrecompiles(), nil)
	return p.EVM.Call(caller, to, input, gas, value)
}

// evm returns an EVM for block number, with tracer if it is not nil.
func (e *policyEnv) evm(number uint64, tracer EVMLogger) preparedEVM {
	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, from, to common.Address, amount *uint256.Int) {
			db.SubBalance(from, amount)
			db.AddBalance(to, amount)
		},
		BlockNumber: new(big.Int).SetUint64(number),
		Time:        ghost.InternalNetTimestamp + number,
		Difficulty:  big.NewInt(1),
		GasLimit:    30_000_000,
		BaseFee:     new(big.Int),
		BlobBaseFee: new(big.Int),
	}
	cfg := Config{}
	if tracer != nil {
		cfg.Tracer = tracer
	}
	evm := NewEVM(ctx, TxContext{GasPrice: new(big.Int)}, e.state, ghost.InternalNetGenesis().Config, cfg)
	return preparedEVM{EVM: evm, state: e.state}
}

// create runs the factory from sender in block number and returns the
// policy address it reports.
func (e *policyEnv) create(number uint64, sender common.Address, salt common.Hash, initCode []byte) (common.Address, error) {
	ret, _, err := e.evm(number, nil).Call(AccountRef(sender), ghost.PolicyFactoryAddress, factoryInput(salt, initCode), policyTestGas, new(uint256.Int))
	if err != nil {
		return common.Address{}, err
	}
	if len(ret) != 32 {
		e.t.Fatalf("the factory returns %d bytes, want 32", len(ret))
	}
	return common.BytesToAddress(ret), nil
}

// mustCreatePolicy creates a policy with runtime code in block number.
func (e *policyEnv) mustCreatePolicy(number uint64, salt common.Hash, runtime []byte) common.Address {
	e.t.Helper()
	initCode := deployCode(nil, runtime)
	addr, err := e.create(number, policySender, salt, initCode)
	if err != nil {
		e.t.Fatalf("policy creation fails: %v", err)
	}
	if want := ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode)); addr != want {
		e.t.Fatalf("the factory reports %v, want %v", addr, want)
	}
	if !ghost.IsRegisteredPolicy(e.state, addr) {
		e.t.Fatalf("policy %v is not registered", addr)
	}
	return addr
}

// setContract puts an ordinary contract with code at addr.
func (e *policyEnv) setContract(addr common.Address, code []byte) {
	e.state.CreateAccount(addr)
	e.state.SetCode(addr, code)
	e.state.SetNonce(addr, 1)
}

func (e *policyEnv) slot(addr common.Address, i int64) *big.Int {
	return e.state.GetState(addr, common.BigToHash(big.NewInt(i))).Big()
}

// TestFrozenPolicyOpcodes checks RP-10 for the opcode table: every opcode a
// frozen context forbids halts the policy's constructor, which then leaves
// no policy, and halts a policy running at call depth 3 (an ordinary
// contract at depth 1 calls a policy, which calls the policy at depth 3),
// whose caller sees the failure. The same code without the opcode passes.
func TestFrozenPolicyOpcodes(t *testing.T) {
	forbidden := []OpCode{
		BALANCE, ORIGIN, CALLER, GASPRICE, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH,
		BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID,
		SELFBALANCE, BASEFEE, BLOBHASH, BLOBBASEFEE,
		SLOAD, SSTORE, GAS, TLOAD, TSTORE,
		LOG0, LOG1, LOG2, LOG3, LOG4,
		CREATE, CALLCODE, DELEGATECALL, CREATE2, SELFDESTRUCT,
	}
	// The table is exactly this list: no other opcode is refused.
	want := make(map[OpCode]bool)
	for _, op := range forbidden {
		want[op] = true
	}
	for b := 0; b < 256; b++ {
		if frozenOpcodes[b] != want[OpCode(b)] {
			t.Errorf("opcode %v: frozen %v, want %v", OpCode(b), frozenOpcodes[b], want[OpCode(b)])
		}
	}
	t.Run("constructor", func(t *testing.T) {
		for i, op := range append([]OpCode{JUMPDEST}, forbidden...) {
			env := newPolicyEnv(t)
			initCode := deployCode(cat(zeros(7), []byte{byte(op)}), []byte{byte(STOP)})
			want := ghost.PolicyAddress(saltOf(i), crypto.Keccak256Hash(initCode))
			tracer := new(frozenTracer)
			_, _, err := env.evm(1, tracer).Call(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(saltOf(i), initCode), policyTestGas, new(uint256.Int))
			if op == JUMPDEST {
				// The harness without a forbidden opcode creates the policy.
				if err != nil || !ghost.IsRegisteredPolicy(env.state, want) {
					t.Fatalf("the control constructor fails: %v", err)
				}
				continue
			}
			var fe *ErrFrozenOpcode
			if !errors.As(err, &fe) || fe.Opcode() != op {
				t.Errorf("%v in the constructor: error %v, want a frozen opcode error", op, err)
			}
			if d := tracer.frozenOpcodeFault(op); d != 1 {
				t.Errorf("%v in the constructor: halted at depth %d, want 1", op, d)
			}
			if ghost.IsRegisteredPolicy(env.state, want) || len(env.state.GetCode(want)) != 0 {
				t.Errorf("%v in the constructor: the policy exists", op)
			}
		}
	})
	t.Run("depth 3", func(t *testing.T) {
		env := newPolicyEnv(t)
		middle := env.mustCreatePolicy(1, saltOf(1000), targetCallerCode(STATICCALL))
		caller := common.HexToAddress("0xc0de")
		env.setContract(caller, forwarderCode(middle))
		for i, op := range append([]OpCode{JUMPDEST}, forbidden...) {
			inner := env.mustCreatePolicy(1, saltOf(i), cat(zeros(7), []byte{byte(op)}, returnOneCode))
			tracer := new(frozenTracer)
			if _, _, err := env.evm(2, tracer).Call(AccountRef(policySender), caller, addrWord(inner), policyTestGas, new(uint256.Int)); err != nil {
				t.Fatalf("%v: the ordinary caller fails: %v", op, err)
			}
			if env.slot(caller, 1).Sign() == 0 {
				t.Fatalf("%v: the policy at depth 2 fails", op)
			}
			innerOK := env.slot(caller, 0).Sign() != 0
			if op == JUMPDEST {
				if !innerOK {
					t.Fatal("the control policy at depth 3 fails")
				}
				continue
			}
			if innerOK {
				t.Errorf("%v at depth 3 does not halt the frame", op)
			}
			if d := tracer.frozenOpcodeFault(op); d != 3 {
				t.Errorf("%v: frozen opcode fault at depth %d, want 3", op, d)
			}
		}
	})
}

// TestFrozenPolicyCallTargets checks RP-10 for the call-target allowlist: a
// CALL or STATICCALL from a policy to SHA256, RIPEMD160, IDENTITY, 0x51,
// 0x60, 0x61 or a policy of an earlier block runs, and one to MODEXP,
// BLAKE2F, a removed precompile, the factory, an ordinary contract or a
// policy created in the same block halts the policy. An ordinary contract
// reaches the same targets.
func TestFrozenPolicyCallTargets(t *testing.T) {
	env := newPolicyEnv(t)
	staticPolicy := env.mustCreatePolicy(1, saltOf(1), targetCallerCode(STATICCALL))
	callPolicy := env.mustCreatePolicy(1, saltOf(2), targetCallerCode(CALL))
	older := env.mustCreatePolicy(1, saltOf(3), returnOneCode)
	ordinary := common.HexToAddress("0xbeef")
	env.setContract(ordinary, returnOneCode)
	sameBlock := env.mustCreatePolicy(2, saltOf(4), returnOneCode)

	type target struct {
		name    string
		addr    common.Address
		allowed bool
		innerOK bool // whether the target itself succeeds on empty input
	}
	at := func(b byte) common.Address { return common.BytesToAddress([]byte{b}) }
	targets := []target{
		{"sha256", at(0x02), true, true},
		{"ripemd160", at(0x03), true, true},
		{"identity", at(0x04), true, true},
		{"signature verify", at(0x51), true, false},
		{"0x60", at(0x60), true, true},
		{"0x61", at(0x61), true, true},
		{"older policy", older, true, true},
		{"ecrecover", at(0x01), false, false},
		{"modexp", at(0x05), false, true},
		{"blake2f", at(0x09), false, false},
		{"factory", ghost.PolicyFactoryAddress, false, false},
		{"ordinary contract", ordinary, false, true},
		{"same-block policy", sameBlock, false, true},
	}
	for _, kind := range []struct {
		name   string
		policy common.Address
		op     OpCode
	}{{"STATICCALL", staticPolicy, STATICCALL}, {"CALL", callPolicy, CALL}} {
		caller := common.BytesToAddress(append([]byte{0xc0, 0xde}, byte(kind.op)))
		env.setContract(caller, forwarderCode(kind.policy))
		for _, tg := range targets {
			tracer := new(frozenTracer)
			if _, _, err := env.evm(2, tracer).Call(AccountRef(policySender), caller, addrWord(tg.addr), policyTestGas, new(uint256.Int)); err != nil {
				t.Fatalf("%s %s: the ordinary caller fails: %v", kind.name, tg.name, err)
			}
			policyOK := env.slot(caller, 1).Sign() != 0
			innerOK := env.slot(caller, 0).Sign() != 0
			refused := tracer.hasFault(ErrFrozenCallTarget)
			if tg.allowed {
				if !policyOK || refused {
					t.Errorf("%s to %s from a policy: halted (%v)", kind.name, tg.name, tracer.faults)
				}
				if innerOK != tg.innerOK {
					t.Errorf("%s to %s from a policy: inner success %v, want %v", kind.name, tg.name, innerOK, tg.innerOK)
				}
				continue
			}
			if policyOK || !refused {
				t.Errorf("%s to %s from a policy: the policy runs on (refused %v)", kind.name, tg.name, refused)
			}
		}
	}
	// An ordinary contract calls the targets the policy may not.
	plain := common.HexToAddress("0x0bad")
	env.setContract(plain, targetCallerCode(STATICCALL))
	for _, tg := range targets {
		if tg.allowed || !tg.innerOK {
			continue
		}
		ret, _, err := env.evm(2, nil).Call(AccountRef(policySender), plain, addrWord(tg.addr), policyTestGas, new(uint256.Int))
		if err != nil || new(big.Int).SetBytes(ret).Sign() == 0 {
			t.Errorf("STATICCALL to %s from an ordinary contract fails: %v", tg.name, err)
		}
	}
}

// TestFrozenPolicyFactoryAddress checks that the same code and salt give the
// same address whoever sends them, an EOA or a contract, that the address is
// ghost.PolicyAddress, and that a second creation there fails.
func TestFrozenPolicyFactoryAddress(t *testing.T) {
	runtime := returnOneCode
	initCode := deployCode(nil, runtime)
	salt := saltOf(7)
	want := ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode))
	if want == (common.Address{}) || ghost.IsReservedAddress(want) {
		t.Fatalf("policy address %v", want)
	}

	first := newPolicyEnv(t)
	got, err := first.create(1, policySender, salt, initCode)
	if err != nil || got != want {
		t.Fatalf("sender 1: address %v, error %v, want %v", got, err, want)
	}
	if code := first.state.GetCode(want); string(code) != string(runtime) {
		t.Errorf("stored code %x, want %x", code, runtime)
	}
	height, codeHash, ok := ghost.PolicyRegistryEntry(first.state, want)
	if !ok || height != 1 || codeHash != crypto.Keccak256Hash(runtime) {
		t.Errorf("registry entry: registered %v, height %d, code hash %x", ok, height, codeHash)
	}
	if first.state.GetNonce(ghost.PolicyRegistryAccount) != 1 {
		t.Error("the registry account has no nonce, so EIP-161 could delete it")
	}

	second := newPolicyEnv(t)
	got, err = second.create(5, policySender2, salt, initCode)
	if err != nil || got != want {
		t.Fatalf("sender 2: address %v, error %v, want %v", got, err, want)
	}
	// Through a contract, in a third state.
	third := newPolicyEnv(t)
	via := common.HexToAddress("0xfac7")
	third.setContract(via, forwarderCode(ghost.PolicyFactoryAddress))
	if _, _, err := third.evm(1, nil).Call(AccountRef(policySender2), via, factoryInput(salt, initCode), policyTestGas, new(uint256.Int)); err != nil {
		t.Fatal(err)
	}
	if third.slot(via, 1).Sign() == 0 || common.BigToAddress(third.slot(via, 0)) != want {
		t.Errorf("a contract sender gets %x, want %v", third.slot(via, 0), want)
	}

	// The address is taken: a second creation fails and changes nothing.
	if _, err := first.create(2, policySender2, salt, initCode); !errors.Is(err, ErrContractAddressCollision) {
		t.Errorf("second creation: error %v, want %v", err, ErrContractAddressCollision)
	}
	if height, _, _ := ghost.PolicyRegistryEntry(first.state, want); height != 1 {
		t.Errorf("the second creation moved the registry height to %d", height)
	}
	// Another salt or other code gives another address.
	if other, err := first.create(2, policySender, saltOf(8), initCode); err != nil || other == want {
		t.Errorf("another salt: address %v, error %v", other, err)
	}
	if other, err := first.create(2, policySender, salt, deployCode(nil, []byte{byte(STOP)})); err != nil || other == want {
		t.Errorf("other code: address %v, error %v", other, err)
	}
}

// TestFrozenPolicyPrefunded checks RP-11 for a balance sent ahead: a policy
// created at an address that already holds 1 wei is created, and its
// balance is zero.
func TestFrozenPolicyPrefunded(t *testing.T) {
	env := newPolicyEnv(t)
	initCode := deployCode(nil, returnOneCode)
	salt := saltOf(1)
	addr := ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode))
	env.state.AddBalance(addr, uint256.NewInt(1))

	got, err := env.create(1, policySender, salt, initCode)
	if err != nil || got != addr {
		t.Fatalf("creation at a pre-funded address: address %v, error %v", got, err)
	}
	if bal := env.state.GetBalance(addr); !bal.IsZero() {
		t.Errorf("policy balance %v, want 0", bal)
	}
	if !ghost.IsRegisteredPolicy(env.state, addr) || len(env.state.GetCode(addr)) == 0 {
		t.Error("the policy is not created")
	}
	// It still runs as a policy.
	ret, _, err := env.evm(2, nil).Call(AccountRef(policySender), addr, nil, policyTestGas, new(uint256.Int))
	if err != nil || new(big.Int).SetBytes(ret).Cmp(common.Big1) != 0 {
		t.Errorf("call to the policy: %x, %v", ret, err)
	}
}

// TestFrozenPolicyFailedConstructor checks that a constructor that fails
// leaves no registry entry, no code, no nonce, and the balance of the
// address untouched.
func TestFrozenPolicyFailedConstructor(t *testing.T) {
	cases := []struct {
		name     string
		initCode []byte
		gas      uint64
	}{
		{"revert", []byte{byte(PUSH1), 0, byte(PUSH1), 0, byte(REVERT)}, policyTestGas},
		{"invalid opcode", []byte{byte(INVALID)}, policyTestGas},
		{"forbidden opcode", deployCode([]byte{byte(PUSH1), 0, byte(SLOAD)}, returnOneCode), policyTestGas},
		{"code starting with 0xef", deployCode(nil, []byte{0xef, 0x00}), policyTestGas},
		{"code deposit out of gas", deployCode(nil, make([]byte, 1000)), PolicyFactoryGas(1015, true) + 1000},
	}
	for i, c := range cases {
		env := newPolicyEnv(t)
		salt := saltOf(i)
		addr := ghost.PolicyAddress(salt, crypto.Keccak256Hash(c.initCode))
		env.state.AddBalance(addr, uint256.NewInt(1))
		_, _, err := env.evm(1, nil).Call(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(salt, c.initCode), c.gas, new(uint256.Int))
		if err == nil {
			t.Errorf("%s: the factory succeeds", c.name)
			continue
		}
		if ghost.IsRegisteredPolicy(env.state, addr) {
			t.Errorf("%s: the policy is registered", c.name)
		}
		for _, word := range []byte{ghost.PolicyRegistryFlagWord, ghost.PolicyRegistryCodeHashWord} {
			if v := env.state.GetState(ghost.PolicyRegistryAccount, ghost.PolicyRegistryKey(addr, word)); v != (common.Hash{}) {
				t.Errorf("%s: registry word %d is %x", c.name, word, v)
			}
		}
		if len(env.state.GetCode(addr)) != 0 || env.state.GetNonce(addr) != 0 {
			t.Errorf("%s: the account has code or a nonce", c.name)
		}
		if bal := env.state.GetBalance(addr); bal.Uint64() != 1 {
			t.Errorf("%s: the balance sent ahead is %v after the failure, want 1", c.name, bal)
		}
	}
}

// TestFrozenPolicyNoBalance checks RP-11 inside the EVM: a CALL with value
// to a policy fails like a call without the balance and moves nothing,
// while a CALL without value runs; a SELFDESTRUCT with a policy as
// beneficiary halts and moves nothing.
func TestFrozenPolicyNoBalance(t *testing.T) {
	env := newPolicyEnv(t)
	policy := env.mustCreatePolicy(1, saltOf(1), returnOneCode)
	ordinary := common.HexToAddress("0x0000000000000000000000000000000000beef01")
	env.setContract(ordinary, []byte{byte(STOP)})

	// A top-level call with value fails with its gas back.
	before := env.state.GetBalance(policySender).Clone()
	_, left, err := env.evm(2, nil).Call(AccountRef(policySender), policy, nil, 100_000, uint256.NewInt(1))
	if !errors.Is(err, ErrPolicyValue) || left != 100_000 {
		t.Errorf("call with value: error %v, gas left %d, want %v with all gas", err, left, ErrPolicyValue)
	}
	if !env.state.GetBalance(policySender).Eq(before) {
		t.Error("the call with value moved the sender's balance")
	}
	// Without value it runs.
	if ret, _, err := env.evm(2, nil).Call(AccountRef(policySender), policy, nil, 100_000, new(uint256.Int)); err != nil || len(ret) != 32 {
		t.Errorf("call without value: %x, %v", ret, err)
	}

	// From a contract: CALL with value 1, success flag in slot 0.
	valueCaller := func(target common.Address) []byte {
		return cat(zeros(4), []byte{byte(PUSH1), 1}, pushAddr(target),
			[]byte{byte(GAS), byte(CALL), byte(PUSH1), 0, byte(SSTORE), byte(STOP)})
	}
	for _, c := range []struct {
		name   string
		target common.Address
		ok     bool
	}{{"policy", policy, false}, {"ordinary", ordinary, true}} {
		sender := common.BytesToAddress([]byte{0xca, 0x11, byte(len(c.name))})
		env.setContract(sender, valueCaller(c.target))
		env.state.SetBalance(sender, uint256.NewInt(10))
		targetBefore := env.state.GetBalance(c.target).Uint64()
		if _, _, err := env.evm(2, nil).Call(AccountRef(policySender), sender, nil, policyTestGas, new(uint256.Int)); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := env.slot(sender, 0).Sign() != 0; got != c.ok {
			t.Errorf("CALL with value to the %s: success %v, want %v", c.name, got, c.ok)
		}
		moved := uint64(0)
		if c.ok {
			moved = 1
		}
		if got := env.state.GetBalance(sender).Uint64(); got != 10-moved {
			t.Errorf("CALL with value to the %s: caller balance %d, want %d", c.name, got, 10-moved)
		}
		if got := env.state.GetBalance(c.target).Uint64(); got != targetBefore+moved {
			t.Errorf("CALL with value to the %s: target balance %d", c.name, got)
		}
	}

	// SELFDESTRUCT with a policy as the beneficiary.
	for _, c := range []struct {
		name        string
		beneficiary common.Address
		ok          bool
	}{{"policy", policy, false}, {"ordinary", ordinary, true}} {
		destructor := common.BytesToAddress([]byte{0xde, 0xad, byte(len(c.name))})
		env.setContract(destructor, cat(pushAddr(c.beneficiary), []byte{byte(SELFDESTRUCT)}))
		env.state.SetBalance(destructor, uint256.NewInt(5))
		before := env.state.GetBalance(c.beneficiary).Uint64()
		_, _, err := env.evm(2, nil).Call(AccountRef(policySender), destructor, nil, policyTestGas, new(uint256.Int))
		if c.ok {
			if err != nil || env.state.GetBalance(c.beneficiary).Uint64() != before+5 {
				t.Errorf("SELFDESTRUCT to the %s: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrPolicyValue) {
			t.Errorf("SELFDESTRUCT to the %s: error %v, want %v", c.name, err, ErrPolicyValue)
		}
		if got := env.state.GetBalance(destructor).Uint64(); got != 5 {
			t.Errorf("SELFDESTRUCT to the %s: the contract keeps %d, want 5", c.name, got)
		}
	}
	if bal := env.state.GetBalance(policy); !bal.IsZero() {
		t.Errorf("policy balance %v, want 0", bal)
	}
}

// TestFrozenPolicyDelegatecall checks that a DELEGATECALL from an ordinary
// contract into a policy runs the policy's code in the contract's context,
// which is not frozen: the frame has no frozen flag (and so no access to
// the natives of a frozen context), and an opcode the policy could not run
// itself runs there. A direct call into the same policy halts on it.
func TestFrozenPolicyDelegatecall(t *testing.T) {
	env := newPolicyEnv(t)
	policyCode := []byte{byte(PUSH1), 0x2a, byte(PUSH1), 0, byte(SSTORE), byte(STOP)}
	policy := env.mustCreatePolicy(1, saltOf(1), policyCode)
	delegator := common.HexToAddress("0xde1e")
	env.setContract(delegator, cat(zeros(4), pushAddr(policy),
		[]byte{byte(GAS), byte(DELEGATECALL), byte(PUSH1), 1, byte(SSTORE), byte(STOP)}))

	tracer := new(frozenTracer)
	if _, _, err := env.evm(2, tracer).Call(AccountRef(policySender), delegator, nil, policyTestGas, new(uint256.Int)); err != nil {
		t.Fatal(err)
	}
	if env.slot(delegator, 1).Sign() == 0 || env.slot(delegator, 0).Uint64() != 0x2a {
		t.Fatalf("the DELEGATECALL into the policy fails: success %v, slot 0 %v", env.slot(delegator, 1), env.slot(delegator, 0))
	}
	seen := false
	for _, f := range tracer.frames {
		if f.code != policy {
			continue
		}
		seen = true
		if f.frozen || f.self != delegator {
			t.Fatalf("the policy code runs with frozen %v in the context of %v", f.frozen, f.self)
		}
	}
	if !seen {
		t.Fatal("the policy code did not run")
	}
	if v := env.state.GetState(policy, common.Hash{}); v != (common.Hash{}) {
		t.Errorf("the policy's own storage changed: %x", v)
	}

	// Called directly, the same code is frozen and halts on SSTORE.
	tracer = new(frozenTracer)
	_, _, err := env.evm(2, tracer).Call(AccountRef(policySender), policy, nil, policyTestGas, new(uint256.Int))
	var fe *ErrFrozenOpcode
	if !errors.As(err, &fe) || fe.Opcode() != SSTORE {
		t.Errorf("direct call: error %v, want a frozen SSTORE", err)
	}
	for _, f := range tracer.frames {
		if f.code == policy && !f.frozen {
			t.Error("a direct call into the policy is not frozen")
		}
	}
}

// TestFrozenPolicyFactoryGas checks the gas of a factory call: the gas of a
// CREATE2 of the init code (32,000 and 8 gas per word under EIP-3860),
// REGISTRY_GAS 40,000, the constructor's own gas and the code deposit.
func TestFrozenPolicyFactoryGas(t *testing.T) {
	if ghost.PolicyRegistryGas != 40_000 {
		t.Fatalf("REGISTRY_GAS is %d, want 40,000", ghost.PolicyRegistryGas)
	}
	runtime := make([]byte, 40)
	for i := range runtime {
		runtime[i] = byte(JUMPDEST)
	}
	initCode := deployCode(nil, runtime)
	var (
		words        = uint64(len(initCode)+31) / 32
		runtimeWords = uint64(len(runtime)+31) / 32
		create2      = 32_000 + (6+2)*words
		// PUSH2, PUSH2, PUSH1, CODECOPY (3, copy and memory), PUSH2, PUSH1, RETURN.
		constructor = 3*5 + 3 + 3*runtimeWords + (3*runtimeWords + runtimeWords*runtimeWords/512)
		deposit     = vars.CreateDataGas * uint64(len(runtime))
		want        = create2 + 40_000 + constructor + deposit
	)
	if got := PolicyFactoryGas(uint64(len(initCode)), true); got != create2+40_000 {
		t.Errorf("PolicyFactoryGas %d, want %d", got, create2+40_000)
	}
	for i, c := range []struct {
		gas  uint64
		ok   bool
		left uint64
	}{{want + 1000, true, 1000}, {want, true, 0}, {want - 1, false, 0}} {
		env := newPolicyEnv(t)
		_, left, err := env.evm(1, nil).Call(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(saltOf(i), initCode), c.gas, new(uint256.Int))
		if (err == nil) != c.ok || left != c.left {
			t.Errorf("gas %d: error %v, left %d; want success %v, left %d (expected use %d)", c.gas, err, left, c.ok, c.left, want)
		}
	}
	// Gas below the fixed part fails before the constructor runs.
	env := newPolicyEnv(t)
	if _, _, err := env.evm(1, nil).Call(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(saltOf(9), initCode), create2+40_000-1, new(uint256.Int)); !errors.Is(err, ErrOutOfGas) {
		t.Errorf("below the fixed gas: error %v, want %v", err, ErrOutOfGas)
	}
	// Value to the factory, and the factory reached by STATICCALL or
	// DELEGATECALL, fail and create nothing.
	salt := saltOf(10)
	addr := ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode))
	evm := env.evm(1, nil)
	if _, left, err := evm.Call(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(salt, initCode), 1_000_000, uint256.NewInt(1)); !errors.Is(err, ErrPolicyFactoryValue) || left != 1_000_000 {
		t.Errorf("value to the factory: error %v, left %d", err, left)
	}
	if _, _, err := evm.StaticCall(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(salt, initCode), 1_000_000); !errors.Is(err, ErrPolicyFactoryCall) {
		t.Errorf("STATICCALL to the factory: error %v", err)
	}
	if ghost.IsRegisteredPolicy(env.state, addr) {
		t.Error("a refused factory call created a policy")
	}
}
