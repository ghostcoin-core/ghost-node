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

// frozenTracer records the faults and the frames the interpreter reports,
// and the gas each entered frame got and used.
type frozenTracer struct {
	faults []tracedFault
	frames []tracedFrame
	open   []uint64
	exits  []tracedExit
}

type tracedExit struct {
	gas, used uint64
	err       error
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
func (f *frozenTracer) CaptureEnter(_ OpCode, _ common.Address, _ common.Address, _ []byte, gas uint64, _ *big.Int) {
	f.open = append(f.open, gas)
}

func (f *frozenTracer) CaptureExit(_ []byte, used uint64, err error) {
	var gas uint64
	if n := len(f.open); n > 0 {
		gas, f.open = f.open[n-1], f.open[:n-1]
	}
	f.exits = append(f.exits, tracedExit{gas, used, err})
}

// frozenHaltUsedAllGas reports whether the entered frame that halted on op
// as a frozen opcode used all the gas it got.
func (f *frozenTracer) frozenHaltUsedAllGas(op OpCode) bool {
	for _, x := range f.exits {
		var fe *ErrFrozenOpcode
		if errors.As(x.err, &fe) && fe.Opcode() == op {
			return x.gas > 0 && x.used == x.gas
		}
	}
	return false
}

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
	block func(*BlockContext) // when set, changes the block context of each EVM
	tx    *TxContext          // when set, the transaction context of each EVM
}

// testBlockHash is the hash the tests' block contexts give for block n.
func testBlockHash(n uint64) common.Hash {
	return common.BigToHash(new(big.Int).SetUint64(0xb10c_0000 + n))
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
		GetHash:     testBlockHash,
		BlockNumber: new(big.Int).SetUint64(number),
		Time:        ghost.InternalNetTimestamp + number,
		Difficulty:  big.NewInt(1),
		GasLimit:    30_000_000,
		BaseFee:     new(big.Int),
		BlobBaseFee: new(big.Int),
	}
	if e.block != nil {
		e.block(&ctx)
	}
	txCtx := TxContext{GasPrice: new(big.Int)}
	if e.tx != nil {
		txCtx = *e.tx
	}
	cfg := Config{}
	if tracer != nil {
		cfg.Tracer = tracer
	}
	evm := NewEVM(ctx, txCtx, e.state, ghost.InternalNetGenesis().Config, cfg)
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

// valuesCode runs each snippet, which pushes one word, and returns the
// words in order. As init code it stores the words as the policy's code.
func valuesCode(snippets ...[]byte) []byte {
	var code []byte
	for i, s := range snippets {
		off := i * 32
		code = cat(code, s, []byte{byte(PUSH2), byte(off >> 8), byte(off), byte(MSTORE)})
	}
	n := len(snippets) * 32
	return cat(code, []byte{byte(PUSH2), byte(n >> 8), byte(n), byte(PUSH1), 0, byte(RETURN)})
}

// ops makes one snippet of each opcode.
func ops(list ...OpCode) [][]byte {
	out := make([][]byte, len(list))
	for i, op := range list {
		out[i] = []byte{byte(op)}
	}
	return out
}

// words splits b into 32-byte words.
func words(b []byte) []*big.Int {
	var out []*big.Int
	for len(b) >= 32 {
		out = append(out, new(big.Int).SetBytes(b[:32]))
		b = b[32:]
	}
	return out
}

func addrBig(a common.Address) *big.Int { return new(big.Int).SetBytes(a.Bytes()) }

// The gas the relays of a depth-3 run pass on.
const (
	relayTopGas    = 5_000_000
	relayMiddleGas = 3_000_000
)

// depthRelayCode calls the address in its first calldata word with op (CALL
// with no value, or STATICCALL), the rest of its calldata as input and gas
// gas, and returns the success flag as a word followed by the call's return
// data. It runs as a policy too.
func depthRelayCode(op OpCode, gas uint32) []byte {
	code := []byte{
		byte(PUSH1), 32, byte(CALLDATASIZE), byte(SUB),
		byte(PUSH1), 32, byte(PUSH1), 0, byte(CALLDATACOPY),
		byte(PUSH1), 0, byte(PUSH1), 0,
		byte(PUSH1), 32, byte(CALLDATASIZE), byte(SUB),
		byte(PUSH1), 0,
	}
	if op == CALL {
		code = append(code, byte(PUSH1), 0)
	}
	code = append(code, byte(PUSH1), 0, byte(CALLDATALOAD))
	code = append(code, byte(PUSH4), byte(gas>>24), byte(gas>>16), byte(gas>>8), byte(gas), byte(op))
	return cat(code, []byte{
		byte(PUSH1), 0, byte(MSTORE),
		byte(RETURNDATASIZE), byte(PUSH1), 0, byte(PUSH1), 32, byte(RETURNDATACOPY),
		byte(RETURNDATASIZE), byte(PUSH1), 32, byte(ADD), byte(PUSH1), 0, byte(RETURN),
	})
}

// depth3 runs a policy at call depth 3: an ordinary contract at depth 1
// calls a policy at depth 2, which calls the policy under test with CALL or,
// for a static frozen frame, STATICCALL.
type depth3 struct {
	env         *policyEnv
	top, middle common.Address
}

// newDepth3 creates the middle policy in block 1 with salt.
func (e *policyEnv) newDepth3(salt int, static bool) depth3 {
	e.t.Helper()
	op := CALL
	if static {
		op = STATICCALL
	}
	middle := e.mustCreatePolicy(1, saltOf(salt), depthRelayCode(op, relayMiddleGas))
	top := common.BytesToAddress([]byte{0xc0, 0xde, byte(op)})
	e.setContract(top, depthRelayCode(CALL, relayTopGas))
	return depth3{env: e, top: top, middle: middle}
}

// run calls inner at depth 3 with input in block number and returns whether
// the frame at depth 3 succeeded and its output.
func (d depth3) run(number uint64, tracer *frozenTracer, inner common.Address, input []byte) (bool, []byte) {
	t := d.env.t
	t.Helper()
	ret, _, err := d.env.evm(number, tracer).Call(AccountRef(policySender), d.top, cat(addrWord(d.middle), addrWord(inner), input), policyTestGas, new(uint256.Int))
	if err != nil || len(ret) < 64 {
		t.Fatalf("the ordinary caller fails: %v (output %x)", err, ret)
	}
	if new(big.Int).SetBytes(ret[:32]).Sign() == 0 {
		t.Fatal("the policy at depth 2 fails")
	}
	return new(big.Int).SetBytes(ret[32:64]).Sign() != 0, ret[64:]
}

// construct runs initCode as the constructor of a policy in block number
// and returns the policy address, the gas the factory call leaves, its
// error and, when it succeeds, the code the constructor returned.
func (e *policyEnv) construct(number uint64, salt common.Hash, initCode []byte, tracer *frozenTracer) (common.Address, []byte, uint64, error) {
	addr := ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode))
	_, left, err := e.evm(number, tracer).Call(AccountRef(policySender), ghost.PolicyFactoryAddress, factoryInput(salt, initCode), policyTestGas, new(uint256.Int))
	if err != nil {
		return addr, nil, left, err
	}
	return addr, e.state.GetCode(addr), left, nil
}

// plain runs code as an ordinary contract at addr, at depth 1 in block
// number, and returns its output.
func (e *policyEnv) plain(number uint64, addr common.Address, code, input []byte) []byte {
	e.t.Helper()
	e.setContract(addr, code)
	ret, _, err := e.evm(number, nil).Call(AccountRef(policySender), addr, input, policyTestGas, new(uint256.Int))
	if err != nil {
		e.t.Fatalf("the ordinary contract fails: %v", err)
	}
	return ret
}

// TestFrozenPolicyOpcodes checks RP-10 for the opcode table: every opcode a
// frozen context forbids halts the policy's constructor, which then leaves
// no policy, and halts a policy running at call depth 3 (an ordinary
// contract at depth 1 calls a policy, which calls the policy at depth 3),
// whose caller sees the failure. The same code without the opcode passes,
// and so does the code with an opcode spec 10, section 6.2 allows.
func TestFrozenPolicyOpcodes(t *testing.T) {
	forbidden := []OpCode{
		BALANCE, SELFBALANCE,
		CALLCODE, DELEGATECALL,
		CREATE, CREATE2,
		SELFDESTRUCT,
		BLOBHASH, BLOBBASEFEE,
	}
	// The table is exactly this list: no other opcode is refused by the
	// per-opcode check.
	want := make(map[OpCode]bool)
	for _, op := range forbidden {
		want[op] = true
	}
	for b := 0; b < 256; b++ {
		if frozenOpcodes[b] != want[OpCode(b)] {
			t.Errorf("opcode %v: frozen %v, want %v", OpCode(b), frozenOpcodes[b], want[OpCode(b)])
		}
	}
	// EXTCODESIZE, EXTCODECOPY and EXTCODEHASH, and only they, are checked
	// per address.
	for b := 0; b < 256; b++ {
		op := OpCode(b)
		wantExt := op == EXTCODESIZE || op == EXTCODECOPY || op == EXTCODEHASH
		if frozenExtcodeOpcodes[b] != wantExt {
			t.Errorf("opcode %v: checked per address %v, want %v", op, frozenExtcodeOpcodes[b], wantExt)
		}
	}
	// The opcodes the node refused before spec 10, section 6.2 and that
	// the spec allows.
	allowed := []OpCode{
		ORIGIN, CALLER, GASPRICE, CALLVALUE, GAS,
		BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, BASEFEE,
		SLOAD, SSTORE, TLOAD, TSTORE,
		LOG0, LOG1, LOG2, LOG3, LOG4,
	}
	t.Run("allowed", func(t *testing.T) {
		for i, op := range allowed {
			env := newPolicyEnv(t)
			initCode := deployCode(cat(zeros(7), []byte{byte(op)}), []byte{byte(STOP)})
			if addr, _, _, err := env.construct(1, saltOf(i), initCode, new(frozenTracer)); err != nil || !ghost.IsRegisteredPolicy(env.state, addr) {
				t.Errorf("%v in the constructor: %v", op, err)
			}
			d := env.newDepth3(1000, false)
			inner := env.mustCreatePolicy(1, saltOf(100+i), cat(zeros(7), []byte{byte(op)}, returnOneCode))
			tracer := new(frozenTracer)
			if ok, out := d.run(2, tracer, inner, nil); !ok || new(big.Int).SetBytes(out).Cmp(common.Big1) != 0 {
				t.Errorf("%v at depth 3 fails: %v", op, tracer.faults)
			}
		}
	})
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

// checkWords compares the words of out with want, one label per word.
func checkWords(t *testing.T, what string, labels []string, out []byte, want []*big.Int) {
	t.Helper()
	got := words(out)
	if len(got) != len(want) || len(out) != 32*len(want) {
		t.Errorf("%s: %d bytes of output, want %d words", what, len(out), len(want))
		return
	}
	for i := range want {
		if got[i].Cmp(want[i]) != 0 {
			t.Errorf("%s: %s is %#x, want %#x", what, labels[i], got[i], want[i])
		}
	}
}

// TestFrozenPolicyChainFacts checks that BLOCKHASH, COINBASE, TIMESTAMP,
// NUMBER, DIFFICULTY, GASLIMIT, CHAINID and BASEFEE run in a frozen frame,
// in the constructor and at depth 3, and push the values an ordinary
// contract gets in the same block.
func TestFrozenPolicyChainFacts(t *testing.T) {
	env := newPolicyEnv(t)
	coinbase := common.HexToAddress("0xc014ba5e00000000000000000000000000000001")
	env.block = func(ctx *BlockContext) {
		ctx.Coinbase = coinbase
		ctx.Difficulty = big.NewInt(0x1234)
		ctx.BaseFee = big.NewInt(7)
	}
	labels := []string{"BLOCKHASH(1)", "COINBASE", "TIMESTAMP", "NUMBER", "DIFFICULTY", "GASLIMIT", "CHAINID", "BASEFEE"}
	code := valuesCode(append([][]byte{{byte(PUSH1), 1, byte(BLOCKHASH)}},
		ops(COINBASE, TIMESTAMP, NUMBER, DIFFICULTY, GASLIMIT, CHAINID, BASEFEE)...)...)
	want := []*big.Int{
		testBlockHash(1).Big(),
		addrBig(coinbase),
		new(big.Int).SetUint64(ghost.InternalNetTimestamp + 2),
		big.NewInt(2),
		big.NewInt(0x1234),
		big.NewInt(30_000_000),
		ghost.InternalNetGenesis().Config.GetChainID(),
		big.NewInt(7),
	}
	if want[6] == nil || want[6].Sign() == 0 {
		t.Fatal("the internal network has no chain id")
	}

	// The base VM: an ordinary contract in block 2.
	base := env.plain(2, common.HexToAddress("0xba5e"), code, nil)
	checkWords(t, "ordinary contract", labels, base, want)

	// The constructor of a policy in block 2 returns the words as its code.
	tracer := new(frozenTracer)
	addr, out, _, err := env.construct(2, saltOf(1), code, tracer)
	if err != nil || !ghost.IsRegisteredPolicy(env.state, addr) {
		t.Fatalf("the constructor fails: %v (faults %v)", err, tracer.faults)
	}
	checkWords(t, "constructor", labels, out, want)

	// A policy at depth 3 in block 2.
	inner := env.mustCreatePolicy(1, saltOf(2), code)
	d := env.newDepth3(1000, false)
	tracer = new(frozenTracer)
	ok, out := d.run(2, tracer, inner, nil)
	if !ok {
		t.Fatalf("the policy at depth 3 fails: %v", tracer.faults)
	}
	checkWords(t, "depth 3", labels, out, want)
}

// TestFrozenPolicyCallerOriginGas checks that CALLER, ORIGIN, GASPRICE, GAS
// and CALLVALUE run in a frozen frame. In the constructor CALLER is the
// factory, at depth 3 it is the calling policy, and ORIGIN and GASPRICE are
// the transaction's; in a policy action, called from ACTION_CALLER with the
// transaction context core.ApplyPolicyAction gives it, ORIGIN is
// ACTION_CALLER and GASPRICE is zero. CALLVALUE is zero throughout.
func TestFrozenPolicyCallerOriginGas(t *testing.T) {
	env := newPolicyEnv(t)
	env.tx = &TxContext{Origin: policySender, GasPrice: big.NewInt(9)}
	code := valuesCode(ops(CALLER, ORIGIN, GASPRICE, GAS, CALLVALUE)...)
	check := func(what string, out []byte, caller, origin common.Address, gasPrice int64, gasBelow uint64) {
		t.Helper()
		w := words(out)
		if len(w) != 5 {
			t.Fatalf("%s: %d bytes of output", what, len(out))
		}
		if w[0].Cmp(addrBig(caller)) != 0 {
			t.Errorf("%s: CALLER %#x, want %v", what, w[0], caller)
		}
		if w[1].Cmp(addrBig(origin)) != 0 {
			t.Errorf("%s: ORIGIN %#x, want %v", what, w[1], origin)
		}
		if w[2].Cmp(big.NewInt(gasPrice)) != 0 {
			t.Errorf("%s: GASPRICE %v, want %d", what, w[2], gasPrice)
		}
		if w[3].Sign() == 0 || w[3].Cmp(new(big.Int).SetUint64(gasBelow)) >= 0 {
			t.Errorf("%s: GAS %v, want between 0 and %d", what, w[3], gasBelow)
		}
		if w[4].Sign() != 0 {
			t.Errorf("%s: CALLVALUE %v, want 0", what, w[4])
		}
	}

	tracer := new(frozenTracer)
	_, out, _, err := env.construct(2, saltOf(1), code, tracer)
	if err != nil {
		t.Fatalf("the constructor fails: %v (faults %v)", err, tracer.faults)
	}
	check("constructor", out, ghost.PolicyFactoryAddress, policySender, 9, policyTestGas)

	inner := env.mustCreatePolicy(1, saltOf(2), code)
	d := env.newDepth3(1000, false)
	tracer = new(frozenTracer)
	ok, out := d.run(2, tracer, inner, nil)
	if !ok {
		t.Fatalf("the policy at depth 3 fails: %v", tracer.faults)
	}
	check("depth 3", out, d.middle, policySender, 9, relayMiddleGas)

	// A policy action: the call core.ApplyPolicyAction makes.
	env.tx = &TxContext{Origin: ghost.ActionCallerAddress, GasPrice: new(big.Int)}
	ret, _, err := env.evm(2, nil).Call(AccountRef(ghost.ActionCallerAddress), inner, nil, 1_000_000, new(uint256.Int))
	if err != nil {
		t.Fatalf("the policy action's call fails: %v", err)
	}
	check("policy action", ret, ghost.ActionCallerAddress, ghost.ActionCallerAddress, 0, 1_000_000)
}

// TestFrozenPolicyOwnStorage checks that SLOAD, SSTORE, TLOAD and TSTORE
// run in a frozen frame and act on the frame's own account only: a value a
// policy writes lands in the policy's storage and not in its callers', and
// a read returns the policy's own value.
func TestFrozenPolicyOwnStorage(t *testing.T) {
	env := newPolicyEnv(t)
	code := cat(
		[]byte{byte(PUSH1), 0x2a, byte(PUSH1), 0, byte(SSTORE)},
		[]byte{byte(PUSH1), 0x2b, byte(PUSH1), 0, byte(TSTORE)},
		valuesCode(
			[]byte{byte(PUSH1), 1, byte(SLOAD)},
			[]byte{byte(PUSH1), 0, byte(SLOAD)},
			[]byte{byte(PUSH1), 0, byte(TLOAD)},
		),
	)
	labels := []string{"SLOAD(1)", "SLOAD(0)", "TLOAD(0)"}
	key0, key1 := common.Hash{}, common.BigToHash(common.Big1)
	transient := func(addr common.Address) *big.Int { return env.state.GetTransientState(addr, key0).Big() }

	// The constructor.
	tracer := new(frozenTracer)
	addr, out, _, err := env.construct(2, saltOf(1), code, tracer)
	if err != nil {
		t.Fatalf("the constructor fails: %v (faults %v)", err, tracer.faults)
	}
	checkWords(t, "constructor", labels, out, []*big.Int{big.NewInt(0), big.NewInt(0x2a), big.NewInt(0x2b)})
	if got := env.slot(addr, 0); got.Int64() != 0x2a {
		t.Errorf("constructor: the policy's slot 0 is %v, want 0x2a", got)
	}
	if got := transient(addr); got.Int64() != 0x2b {
		t.Errorf("constructor: the policy's transient slot 0 is %v, want 0x2b", got)
	}
	for _, other := range []common.Address{ghost.PolicyFactoryAddress, policySender} {
		if env.slot(other, 0).Sign() != 0 || transient(other).Sign() != 0 {
			t.Errorf("constructor: %v's storage changed", other)
		}
	}

	// At depth 3, each account has its own value in slot 1.
	inner := env.mustCreatePolicy(1, saltOf(2), code)
	d := env.newDepth3(1000, false)
	env.state.SetState(inner, key1, common.BigToHash(big.NewInt(0x77)))
	env.state.SetState(d.middle, key1, common.BigToHash(big.NewInt(0x66)))
	env.state.SetState(d.top, key1, common.BigToHash(big.NewInt(0x55)))
	tracer = new(frozenTracer)
	ok, out := d.run(2, tracer, inner, nil)
	if !ok {
		t.Fatalf("the policy at depth 3 fails: %v", tracer.faults)
	}
	checkWords(t, "depth 3", labels, out, []*big.Int{big.NewInt(0x77), big.NewInt(0x2a), big.NewInt(0x2b)})
	if got := env.slot(inner, 0); got.Int64() != 0x2a {
		t.Errorf("depth 3: the policy's slot 0 is %v, want 0x2a", got)
	}
	if got := transient(inner); got.Int64() != 0x2b {
		t.Errorf("depth 3: the policy's transient slot 0 is %v, want 0x2b", got)
	}
	for name, c := range map[string]struct {
		addr  common.Address
		slot1 int64
	}{"the calling policy": {d.middle, 0x66}, "the ordinary caller": {d.top, 0x55}} {
		if env.slot(c.addr, 0).Sign() != 0 || transient(c.addr).Sign() != 0 {
			t.Errorf("depth 3: the write landed in %s", name)
		}
		if got := env.slot(c.addr, 1); got.Int64() != c.slot1 {
			t.Errorf("depth 3: %s's slot 1 is %v, want %#x", name, got, c.slot1)
		}
	}
}

// TestFrozenPolicyStaticWrites checks that SSTORE and TSTORE fail with
// ErrWriteProtection, not a frozen opcode error, in a static frozen frame (a
// policy at depth 3 reached by STATICCALL, and a STATICCALL straight into
// the policy), and that SLOAD and TLOAD still run there.
func TestFrozenPolicyStaticWrites(t *testing.T) {
	env := newPolicyEnv(t)
	static := env.newDepth3(1000, true)
	writer := map[OpCode]common.Address{}
	for i, op := range []OpCode{SSTORE, TSTORE} {
		writer[op] = env.mustCreatePolicy(1, saltOf(i), cat([]byte{byte(PUSH1), 0x2a, byte(PUSH1), 0, byte(op)}, returnOneCode))
	}
	sload := env.mustCreatePolicy(1, saltOf(10), valuesCode([]byte{byte(PUSH1), 0, byte(SLOAD)}))
	tload := env.mustCreatePolicy(1, saltOf(11), valuesCode([]byte{byte(PUSH1), 0, byte(TLOAD)}))
	env.state.SetState(sload, common.Hash{}, common.BigToHash(big.NewInt(0x77)))

	for _, op := range []OpCode{SSTORE, TSTORE} {
		tracer := new(frozenTracer)
		if ok, _ := static.run(2, tracer, writer[op], nil); ok {
			t.Errorf("%v in a static frozen frame succeeds", op)
		}
		if !tracer.hasFault(ErrWriteProtection) {
			t.Errorf("%v in a static frozen frame: faults %v, want %v", op, tracer.faults, ErrWriteProtection)
		}
		if d := tracer.frozenOpcodeFault(op); d != -1 {
			t.Errorf("%v in a static frozen frame: frozen opcode fault at depth %d", op, d)
		}
		if env.slot(writer[op], 0).Sign() != 0 || env.state.GetTransientState(writer[op], common.Hash{}) != (common.Hash{}) {
			t.Errorf("%v in a static frozen frame wrote", op)
		}
		_, _, err := env.evm(2, nil).StaticCall(AccountRef(policySender), writer[op], nil, 1_000_000)
		if !errors.Is(err, ErrWriteProtection) {
			t.Errorf("%v under a STATICCALL into the policy: error %v, want %v", op, err, ErrWriteProtection)
		}
	}
	// The same writers run under CALL.
	plainCall := env.newDepth3(1001, false)
	for _, op := range []OpCode{SSTORE, TSTORE} {
		tracer := new(frozenTracer)
		if ok, _ := plainCall.run(2, tracer, writer[op], nil); !ok {
			t.Errorf("%v in a frozen frame under CALL fails: %v", op, tracer.faults)
		}
	}
	if got := env.slot(writer[SSTORE], 0); got.Int64() != 0x2a {
		t.Errorf("SSTORE under CALL: slot 0 is %v, want 0x2a", got)
	}

	for _, c := range []struct {
		op   OpCode
		addr common.Address
		want int64
	}{{SLOAD, sload, 0x77}, {TLOAD, tload, 0}} {
		tracer := new(frozenTracer)
		ok, out := static.run(2, tracer, c.addr, nil)
		if !ok {
			t.Errorf("%v in a static frozen frame fails: %v", c.op, tracer.faults)
			continue
		}
		checkWords(t, c.op.String()+" in a static frozen frame", []string{c.op.String()}, out, []*big.Int{big.NewInt(c.want)})
	}
}

// logCode emits LOGn of the word 0xab with topics 1 to n.
func logCode(n int) []byte {
	code := []byte{byte(PUSH1), 0xab, byte(PUSH1), 0, byte(MSTORE)}
	for j := n; j >= 1; j-- {
		code = append(code, byte(PUSH1), byte(j))
	}
	return append(code, byte(PUSH1), 32, byte(PUSH1), 0, byte(LOG0)+byte(n))
}

// TestFrozenPolicyLogs checks that LOG0 to LOG4 run in a frozen frame, in
// the constructor and at depth 3, and that the log names the policy as its
// emitter; in a static frozen frame they fail with ErrWriteProtection and
// leave no log.
func TestFrozenPolicyLogs(t *testing.T) {
	env := newPolicyEnv(t)
	d := env.newDepth3(1000, false)
	static := env.newDepth3(1001, true)
	checkLog := func(what string, before int, emitter common.Address, n int) {
		t.Helper()
		logs := env.state.Logs()
		if len(logs) != before+1 {
			t.Errorf("%s: %d new logs, want 1", what, len(logs)-before)
			return
		}
		l := logs[len(logs)-1]
		if l.Address != emitter {
			t.Errorf("%s: emitter %v, want %v", what, l.Address, emitter)
		}
		if len(l.Topics) != n {
			t.Errorf("%s: %d topics, want %d", what, len(l.Topics), n)
		}
		for j, topic := range l.Topics {
			if topic != common.BigToHash(big.NewInt(int64(j+1))) {
				t.Errorf("%s: topic %d is %x", what, j, topic)
			}
		}
		if string(l.Data) != string(common.LeftPadBytes([]byte{0xab}, 32)) {
			t.Errorf("%s: data %x", what, l.Data)
		}
	}
	for n := 0; n <= 4; n++ {
		op := OpCode(byte(LOG0) + byte(n))

		before := len(env.state.Logs())
		tracer := new(frozenTracer)
		addr, _, _, err := env.construct(2, saltOf(10+n), deployCode(logCode(n), []byte{byte(STOP)}), tracer)
		if err != nil {
			t.Errorf("%v in the constructor fails: %v (faults %v)", op, err, tracer.faults)
		} else {
			checkLog(op.String()+" in the constructor", before, addr, n)
		}

		inner := env.mustCreatePolicy(1, saltOf(20+n), cat(logCode(n), returnOneCode))
		before = len(env.state.Logs())
		tracer = new(frozenTracer)
		if ok, _ := d.run(2, tracer, inner, nil); !ok {
			t.Errorf("%v at depth 3 fails: %v", op, tracer.faults)
		} else {
			checkLog(op.String()+" at depth 3", before, inner, n)
		}

		before = len(env.state.Logs())
		tracer = new(frozenTracer)
		if ok, _ := static.run(2, tracer, inner, nil); ok {
			t.Errorf("%v in a static frozen frame succeeds", op)
		}
		if !tracer.hasFault(ErrWriteProtection) || tracer.frozenOpcodeFault(op) != -1 {
			t.Errorf("%v in a static frozen frame: faults %v, want %v", op, tracer.faults, ErrWriteProtection)
		}
		if got := len(env.state.Logs()); got != before {
			t.Errorf("%v in a static frozen frame left %d logs", op, got-before)
		}
	}
}

// extcodeSnippet pushes the word op gives for the address target pushes:
// the code size, the code hash, or the first 32 bytes of the code.
func extcodeSnippet(op OpCode, target []byte) []byte {
	if op == EXTCODECOPY {
		return cat([]byte{byte(PUSH1), 32, byte(PUSH1), 0, byte(PUSH2), 0x10, 0x00}, target,
			[]byte{byte(EXTCODECOPY), byte(PUSH2), 0x10, 0x00, byte(MLOAD)})
	}
	return cat(target, []byte{byte(op)})
}

// extcodeWant is the word extcodeSnippet pushes for an account with code.
func extcodeWant(op OpCode, code []byte) *big.Int {
	switch op {
	case EXTCODESIZE:
		return big.NewInt(int64(len(code)))
	case EXTCODEHASH:
		return crypto.Keccak256Hash(code).Big()
	}
	head := code
	if len(head) > 32 {
		head = head[:32]
	}
	return new(big.Int).SetBytes(common.RightPadBytes(head, 32))
}

// TestFrozenPolicyExtcodeOnlyPolicies checks that EXTCODESIZE, EXTCODECOPY
// and EXTCODEHASH in a frozen frame give the code size, code and code hash of
// another policy and of the frame's own policy, and that on any other
// address (an ordinary contract, an empty account, a precompile, the natives
// 0x60 and 0x61, the factory) they halt the frame with a frozen opcode error
// that uses all its gas, in the constructor and at depth 3.
func TestFrozenPolicyExtcodeOnlyPolicies(t *testing.T) {
	env := newPolicyEnv(t)
	other := env.mustCreatePolicy(1, saltOf(1), returnOneCode)
	ordinary := common.HexToAddress("0xbeef")
	env.setContract(ordinary, returnOneCode)
	d := env.newDepth3(1000, false)
	at := func(b byte) common.Address { return common.BytesToAddress([]byte{b}) }
	type target struct {
		name string
		addr common.Address
	}
	refused := []target{
		{"an ordinary contract", ordinary},
		{"an empty account", common.HexToAddress("0x00000000000000000000000000000000000e0e01")},
		{"the precompile 0x02", at(0x02)},
		{"the native 0x60", at(0x60)},
		{"the native 0x61", at(0x61)},
		{"the factory", ghost.PolicyFactoryAddress},
	}
	for i, op := range []OpCode{EXTCODESIZE, EXTCODECOPY, EXTCODEHASH} {
		runtime := valuesCode([]byte{byte(PUSH1), 0}, extcodeSnippet(op, []byte{byte(PUSH1), 0, byte(CALLDATALOAD)}))
		inner := env.mustCreatePolicy(1, saltOf(10+i), runtime)

		// At depth 3.
		for _, tg := range []target{{"another policy", other}, {"its own address", inner}} {
			tracer := new(frozenTracer)
			ok, out := d.run(2, tracer, inner, addrWord(tg.addr))
			if !ok {
				t.Errorf("%v of %s at depth 3 fails: %v", op, tg.name, tracer.faults)
				continue
			}
			if w := words(out); len(w) != 2 || w[1].Cmp(extcodeWant(op, env.state.GetCode(tg.addr))) != 0 {
				t.Errorf("%v of %s at depth 3: output %x", op, tg.name, out)
			}
		}
		for _, tg := range refused {
			tracer := new(frozenTracer)
			if ok, _ := d.run(2, tracer, inner, addrWord(tg.addr)); ok {
				t.Errorf("%v of %s at depth 3 runs", op, tg.name)
			}
			if dep := tracer.frozenOpcodeFault(op); dep != 3 {
				t.Errorf("%v of %s: frozen opcode fault at depth %d, want 3", op, tg.name, dep)
			}
			if !tracer.frozenHaltUsedAllGas(op) {
				t.Errorf("%v of %s at depth 3 does not use all its gas", op, tg.name)
			}
		}

		// In the constructor.
		tracer := new(frozenTracer)
		_, out, _, err := env.construct(2, saltOf(20+i), valuesCode([]byte{byte(PUSH1), 0}, extcodeSnippet(op, pushAddr(other))), tracer)
		if err != nil {
			t.Errorf("%v of another policy in the constructor fails: %v", op, err)
		} else if w := words(out); len(w) != 2 || w[1].Cmp(extcodeWant(op, returnOneCode)) != 0 {
			t.Errorf("%v of another policy in the constructor: output %x", op, out)
		}
		for j, tg := range refused {
			tracer := new(frozenTracer)
			initCode := valuesCode([]byte{byte(PUSH1), 0}, extcodeSnippet(op, pushAddr(tg.addr)))
			addr, _, left, err := env.construct(2, saltOf(100+10*i+j), initCode, tracer)
			var fe *ErrFrozenOpcode
			if !errors.As(err, &fe) || fe.Opcode() != op {
				t.Errorf("%v of %s in the constructor: error %v, want a frozen opcode error", op, tg.name, err)
			}
			if left != 0 || !tracer.frozenHaltUsedAllGas(op) {
				t.Errorf("%v of %s in the constructor: %d gas left", op, tg.name, left)
			}
			if dep := tracer.frozenOpcodeFault(op); dep != 1 {
				t.Errorf("%v of %s in the constructor: halted at depth %d, want 1", op, tg.name, dep)
			}
			if ghost.IsRegisteredPolicy(env.state, addr) {
				t.Errorf("%v of %s in the constructor: the policy exists", op, tg.name)
			}
		}

		// An ordinary contract reads any address.
		out = env.plain(2, common.BytesToAddress([]byte{0x0b, 0xad, byte(op)}), runtime, addrWord(ordinary))
		if w := words(out); len(w) != 2 || w[1].Cmp(extcodeWant(op, returnOneCode)) != 0 {
			t.Errorf("%v of an ordinary contract from an ordinary contract: output %x", op, out)
		}
	}
}

// TestFrozenPolicyStillForbidden checks RP-10 for what a frozen context may
// still not do: BALANCE, SELFBALANCE, CALLCODE, DELEGATECALL, CREATE,
// CREATE2, SELFDESTRUCT, BLOBHASH and BLOBBASEFEE halt the frame with a
// frozen opcode error that uses all its gas, in the constructor, at depth 3
// and called directly; BLOBHASH and BLOBBASEFEE are invalid in any frame on
// Ghost; and a call to 0x05 or 0x09 halts the frozen frame.
func TestFrozenPolicyStillForbidden(t *testing.T) {
	forbidden := []OpCode{BALANCE, SELFBALANCE, CALLCODE, DELEGATECALL, CREATE, CREATE2, SELFDESTRUCT, BLOBHASH, BLOBBASEFEE}
	env := newPolicyEnv(t)
	d := env.newDepth3(1000, false)
	for i, op := range forbidden {
		tracer := new(frozenTracer)
		addr, _, left, err := env.construct(2, saltOf(i), deployCode(cat(zeros(7), []byte{byte(op)}), []byte{byte(STOP)}), tracer)
		var fe *ErrFrozenOpcode
		if !errors.As(err, &fe) || fe.Opcode() != op {
			t.Errorf("%v in the constructor: error %v, want a frozen opcode error", op, err)
		}
		if left != 0 || !tracer.frozenHaltUsedAllGas(op) {
			t.Errorf("%v in the constructor: %d gas left", op, left)
		}
		if dep := tracer.frozenOpcodeFault(op); dep != 1 {
			t.Errorf("%v in the constructor: halted at depth %d, want 1", op, dep)
		}
		if ghost.IsRegisteredPolicy(env.state, addr) {
			t.Errorf("%v in the constructor: the policy exists", op)
		}

		inner := env.mustCreatePolicy(1, saltOf(100+i), cat(zeros(7), []byte{byte(op)}, returnOneCode))
		tracer = new(frozenTracer)
		if ok, _ := d.run(2, tracer, inner, nil); ok {
			t.Errorf("%v at depth 3 does not halt the frame", op)
		}
		if dep := tracer.frozenOpcodeFault(op); dep != 3 {
			t.Errorf("%v: frozen opcode fault at depth %d, want 3", op, dep)
		}
		if !tracer.frozenHaltUsedAllGas(op) {
			t.Errorf("%v at depth 3 does not use all its gas", op)
		}

		_, left, err = env.evm(2, nil).Call(AccountRef(policySender), inner, nil, 1_000_000, new(uint256.Int))
		if !errors.As(err, &fe) || fe.Opcode() != op || left != 0 {
			t.Errorf("%v called directly: error %v, %d gas left", op, err, left)
		}
	}
	// BLOBHASH and BLOBBASEFEE are invalid opcodes on Ghost.
	for _, op := range []OpCode{BLOBHASH, BLOBBASEFEE} {
		addr := common.BytesToAddress([]byte{0x0b, 0x10, byte(op)})
		env.setContract(addr, cat(zeros(1), []byte{byte(op), byte(STOP)}))
		_, _, err := env.evm(2, nil).Call(AccountRef(policySender), addr, nil, 1_000_000, new(uint256.Int))
		var ie *ErrInvalidOpCode
		if !errors.As(err, &ie) {
			t.Errorf("%v in an ordinary contract: error %v, want an invalid opcode", op, err)
		}
	}
	// Calls to MODEXP and BLAKE2F from a frozen context.
	caller := env.mustCreatePolicy(1, saltOf(200), targetCallerCode(STATICCALL))
	for j, target := range []common.Address{common.BytesToAddress([]byte{0x05}), common.BytesToAddress([]byte{0x09})} {
		tracer := new(frozenTracer)
		if ok, _ := d.run(2, tracer, caller, addrWord(target)); ok || !tracer.hasFault(ErrFrozenCallTarget) {
			t.Errorf("STATICCALL to %v at depth 3: not refused (faults %v)", target, tracer.faults)
		}
		initCode := deployCode(cat(zeros(4), pushAddr(target), []byte{byte(PUSH3), 0x0f, 0x42, 0x40, byte(STATICCALL), byte(POP)}), []byte{byte(STOP)})
		addr, _, _, err := env.construct(2, saltOf(300+j), initCode, new(frozenTracer))
		if !errors.Is(err, ErrFrozenCallTarget) || ghost.IsRegisteredPolicy(env.state, addr) {
			t.Errorf("STATICCALL to %v in the constructor: error %v", target, err)
		}
	}
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
		// The escrow natives run; an empty input names no function and
		// fails revert-style.
		{"0x60", at(0x60), true, false},
		// The statement checker runs; an empty input is not a statement
		// and fails revert-style.
		{"0x61", at(0x61), true, false},
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
		{"forbidden opcode", deployCode([]byte{byte(PUSH1), 0, byte(BALANCE)}, returnOneCode), policyTestGas},
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
	policyCode := []byte{byte(SELFBALANCE), byte(POP), byte(PUSH1), 0x2a, byte(PUSH1), 0, byte(SSTORE), byte(STOP)}
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

	// Called directly, the same code is frozen and halts on SELFBALANCE.
	tracer = new(frozenTracer)
	_, _, err := env.evm(2, tracer).Call(AccountRef(policySender), policy, nil, policyTestGas, new(uint256.Int))
	var fe *ErrFrozenOpcode
	if !errors.As(err, &fe) || fe.Opcode() != SELFBALANCE {
		t.Errorf("direct call: error %v, want a frozen SELFBALANCE", err)
	}
	if v := env.state.GetState(policy, common.Hash{}); v != (common.Hash{}) {
		t.Errorf("the halted direct call wrote the policy's storage: %x", v)
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
