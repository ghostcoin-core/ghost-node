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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// checkerGenesis is the genesis hash the tests' block contexts carry.
var checkerGenesis = common.HexToHash("0x9e6e515e000000000000000000000000000000000000000000000000000000aa")

// checkerFullGas is the gas of a call with an input of 917,601 bytes:
// 110,000 plus 3 for each of its 28,676 words.
const checkerFullGas = 196_028

// useStubVerifier makes the stub verifier the active one for the test.
func useStubVerifier(t *testing.T) {
	t.Helper()
	t.Cleanup(ghostpriv.SetVerifier(ghostprivtest.Verifier{}))
}

// checkerChainID is the chain id of the configuration the tests' EVMs run.
func checkerChainID(t *testing.T) uint64 {
	t.Helper()
	id := ghost.InternalNetGenesis().Config.GetChainID()
	if id == nil || id.Sign() == 0 {
		t.Fatal("the test configuration has no chain id")
	}
	return id.Uint64()
}

// checkerEVM returns an EVM for block number whose context carries genesis.
func (e *policyEnv) checkerEVM(number uint64, genesis common.Hash) preparedEVM {
	p := e.evm(number, nil)
	p.EVM.Context.Genesis = genesis
	return p
}

// statementInput returns a checker input over y and a context of seed, with
// the stub proof of the statement made for policy on the chain of chainID
// and genesis.
func statementInput(t *testing.T, chainID uint64, genesis common.Hash, policy common.Address, seed byte) []byte {
	t.Helper()
	p := &ghostpriv.Preimage{Y: ghostpriv.PreimageY(common.Hash{seed})}
	for i := range p.Context {
		p.Context[i] = seed + byte(i)
	}
	p.Proof = ghostprivtest.PreimageProof(p.BindingDigest(chainID, genesis, policy))
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// checkerPolicyCode passes its whole calldata to the statement checker with
// op (CALL with no value, or STATICCALL) and 1,000,000 gas, and returns
// three words: the call's success flag, the first word of its return data
// and the return data's size. It uses no opcode a frozen context forbids.
func checkerPolicyCode(op OpCode) []byte {
	code := []byte{byte(CALLDATASIZE), byte(PUSH1), 0, byte(PUSH1), 0, byte(CALLDATACOPY)}
	code = append(code, byte(PUSH1), 0x20, byte(PUSH1), 0x20, byte(CALLDATASIZE), byte(PUSH1), 0)
	if op == CALL {
		code = append(code, byte(PUSH1), 0)
	}
	code = append(code, pushAddr(ghost.StatementCheckerAddress)...)
	code = append(code, byte(PUSH3), 0x0f, 0x42, 0x40, byte(op))
	code = append(code, byte(PUSH1), 0, byte(MSTORE))
	code = append(code, byte(RETURNDATASIZE), byte(PUSH1), 0x40, byte(MSTORE))
	return append(code, byte(PUSH1), 0x60, byte(PUSH1), 0, byte(RETURN))
}

// checkerResult is what a checker policy reports of its call.
type checkerResult struct {
	ok   bool   // the call to 0x61 succeeded
	size uint64 // the size of its return data
	word uint64 // its first word
}

// callChecker calls the checker policy at policy with input in block 2 and
// returns what it reports.
func (e *policyEnv) callChecker(t *testing.T, policy common.Address, genesis common.Hash, input []byte) checkerResult {
	t.Helper()
	ret, _, err := e.checkerEVM(2, genesis).Call(AccountRef(policySender), policy, input, policyTestGas, new(uint256.Int))
	if err != nil {
		t.Fatalf("the checker policy fails: %v", err)
	}
	if len(ret) != 96 {
		t.Fatalf("the checker policy returns %d bytes", len(ret))
	}
	r := checkerResult{
		ok:   new(big.Int).SetBytes(ret[:32]).Sign() != 0,
		size: new(big.Int).SetBytes(ret[64:96]).Uint64(),
	}
	if r.size == 32 {
		r.word = new(big.Int).SetBytes(ret[32:64]).Uint64()
	}
	return r
}

// frozenFrame is a frame of the policy at addr running in a frozen context.
func frozenFrame(addr common.Address) *Contract {
	c := NewContract(AccountRef(policySender), AccountRef(addr), new(uint256.Int), 0)
	c.frozen = true
	return c
}

// TestStatementCheckerValidProofReturnsOne checks that a frozen policy of an
// earlier block that passes a valid statement made for it to 0x61, by
// STATICCALL or by CALL, gets the word 1.
func TestStatementCheckerValidProofReturnsOne(t *testing.T) {
	useStubVerifier(t)
	env := newPolicyEnv(t)
	chainID := checkerChainID(t)
	for i, op := range []OpCode{STATICCALL, CALL} {
		policy := env.mustCreatePolicy(1, saltOf(100+i), checkerPolicyCode(op))
		input := statementInput(t, chainID, checkerGenesis, policy, 7)
		if r := env.callChecker(t, policy, checkerGenesis, input); !r.ok || r.size != 32 || r.word != 1 {
			t.Errorf("%v: result %+v, want success and the word 1", op, r)
		}
	}
	// The same through the checker directly, from a frozen frame.
	policy := common.HexToAddress("0x00000000000000000000000000000000c0ffee01")
	input := statementInput(t, chainID, checkerGenesis, policy, 9)
	ret, left, err := env.checkerEVM(2, checkerGenesis).StaticCall(frozenFrame(policy), ghost.StatementCheckerAddress, input, 1_000_000)
	if err != nil || !bytes.Equal(ret, common.LeftPadBytes([]byte{1}, 32)) || left != 1_000_000-checkerFullGas {
		t.Fatalf("direct call: ret %x, gas left %d, err %v", ret, left, err)
	}
}

// TestStatementCheckerInvalidProofReturnsZero checks that a proof that does
// not verify, and any proof on a node whose verifier cannot verify the
// statement, is answered with the word 0 and a successful call.
func TestStatementCheckerInvalidProofReturnsZero(t *testing.T) {
	useStubVerifier(t)
	env := newPolicyEnv(t)
	chainID := checkerChainID(t)
	policy := env.mustCreatePolicy(1, saltOf(200), checkerPolicyCode(STATICCALL))
	valid := statementInput(t, chainID, checkerGenesis, policy, 3)

	tamper := func(at int) []byte {
		in := append([]byte(nil), valid...)
		in[at] ^= 0x01
		return in
	}
	cases := map[string][]byte{
		"proof tag":     tamper(1 + 32 + 64),
		"proof padding": tamper(len(valid) - 1),
		"y":             tamper(1),
		"context":       tamper(1 + 32 + 63),
		"other chain":   statementInput(t, chainID+1, checkerGenesis, policy, 3),
		"other genesis": statementInput(t, chainID, common.Hash{0x01}, policy, 3),
		"zero proof":    append(append([]byte(nil), valid[:97]...), make([]byte, ghostpriv.ActionProofSize)...),
		"other binding": append(append([]byte(nil), valid[:97]...), ghostprivtest.PreimageProof(common.Hash{0x01})...),
	}
	for name, input := range cases {
		if r := env.callChecker(t, policy, checkerGenesis, input); !r.ok || r.size != 32 || r.word != 0 {
			t.Errorf("%s: result %+v, want success and the word 0", name, r)
		}
	}
	// The control: the valid input gives 1.
	if r := env.callChecker(t, policy, checkerGenesis, valid); r.word != 1 {
		t.Fatalf("valid input: result %+v", r)
	}
	// A node whose verifier has no proof system for the statement, as the
	// linked verifier, answers 0 to every proof, the valid one included.
	restore := ghostpriv.SetVerifier(nil)
	defer restore()
	if r := env.callChecker(t, policy, checkerGenesis, valid); !r.ok || r.size != 32 || r.word != 0 {
		t.Errorf("default verifier: result %+v, want success and the word 0", r)
	}
}

// TestStatementCheckerRefusesBadCalls checks that the checker fails
// revert-style, with no return data and its gas spent, for a caller that is
// not a frozen frame, a CALLCODE or DELEGATECALL, a CALL with value, an
// input of any other length, a statement code other than 0x06, and a block
// context without a genesis hash.
func TestStatementCheckerRefusesBadCalls(t *testing.T) {
	useStubVerifier(t)
	env := newPolicyEnv(t)
	chainID := checkerChainID(t)
	policy := common.HexToAddress("0x00000000000000000000000000000000c0ffee02")
	valid := statementInput(t, chainID, checkerGenesis, policy, 5)
	const gas = 1_000_000

	type call struct {
		name    string
		genesis common.Hash
		run     func(evm *EVM) ([]byte, uint64, error)
		input   []byte
	}
	frozen := frozenFrame(policy)
	static := func(caller ContractRef, input []byte) func(*EVM) ([]byte, uint64, error) {
		return func(evm *EVM) ([]byte, uint64, error) {
			return evm.StaticCall(caller, ghost.StatementCheckerAddress, input, gas)
		}
	}
	calls := []call{
		{"short input", checkerGenesis, static(frozen, valid[:len(valid)-1]), valid[:len(valid)-1]},
		{"long input", checkerGenesis, static(frozen, append(append([]byte(nil), valid...), 0)), append(append([]byte(nil), valid...), 0)},
		{"empty input", checkerGenesis, static(frozen, nil), nil},
		{"statement 0x05", checkerGenesis, static(frozen, append([]byte{0x05}, valid[1:]...)), valid},
		{"not frozen", checkerGenesis, static(AccountRef(policy), valid), valid},
		{"ordinary contract frame", checkerGenesis, static(NewContract(AccountRef(policySender), AccountRef(policy), new(uint256.Int), 0), valid), valid},
		{"zero genesis", common.Hash{}, static(frozen, valid), valid},
		{"callcode", checkerGenesis, func(evm *EVM) ([]byte, uint64, error) {
			return evm.CallCode(frozen, ghost.StatementCheckerAddress, valid, gas, new(uint256.Int))
		}, valid},
		{"delegatecall", checkerGenesis, func(evm *EVM) ([]byte, uint64, error) {
			return evm.DelegateCall(frozen, ghost.StatementCheckerAddress, valid, gas)
		}, valid},
		{"call with value", checkerGenesis, func(evm *EVM) ([]byte, uint64, error) {
			return evm.Call(frozen, ghost.StatementCheckerAddress, valid, gas, uint256.NewInt(1))
		}, valid},
	}
	for _, c := range calls {
		evm := env.checkerEVM(2, c.genesis).EVM
		ret, left, err := c.run(evm)
		if err != ErrExecutionReverted || len(ret) != 0 {
			t.Errorf("%s: ret %x, err %v, want a revert-style failure", c.name, ret, err)
		}
		if want := gas - StatementCheckerGas(len(c.input)); left != want {
			t.Errorf("%s: gas left %d, want %d", c.name, left, want)
		}
	}
	// The control: the same frame and input succeed.
	ret, _, err := env.checkerEVM(2, checkerGenesis).StaticCall(frozen, ghost.StatementCheckerAddress, valid, gas)
	if err != nil || len(ret) != 32 || ret[31] != 1 {
		t.Fatalf("control call: ret %x, err %v", ret, err)
	}
	// From the EVM: an ordinary contract with the policy's code is refused,
	// and the policy itself is answered.
	ordinary := common.HexToAddress("0x0bad")
	env.setContract(ordinary, checkerPolicyCode(STATICCALL))
	if r := env.callChecker(t, ordinary, checkerGenesis, statementInput(t, chainID, checkerGenesis, ordinary, 5)); r.ok || r.size != 0 {
		t.Errorf("ordinary contract: result %+v, want a failed call", r)
	}
}

// TestStatementCheckerGas checks the gas of spec 10, section 9.3: 110,000
// plus 3 per 32-byte word of the input, charged before the proof is checked,
// the same for a proof that verifies and one that does not, 196,028 for the
// input of 917,601 bytes; with less gas the call runs out of gas.
func TestStatementCheckerGas(t *testing.T) {
	useStubVerifier(t)
	if ghost.PreimageVerifyGas != 110_000 || ghost.StatementCheckerWordGas != 3 {
		t.Fatalf("PREIMAGE_VERIFY_GAS %d, word gas %d", ghost.PreimageVerifyGas, ghost.StatementCheckerWordGas)
	}
	for n, want := range map[int]uint64{0: 110_000, 1: 110_003, 32: 110_003, 33: 110_006, 917_601: checkerFullGas} {
		if got := StatementCheckerGas(n); got != want {
			t.Errorf("gas of %d bytes: %d, want %d", n, got, want)
		}
	}
	env := newPolicyEnv(t)
	chainID := checkerChainID(t)
	policy := common.HexToAddress("0x00000000000000000000000000000000c0ffee03")
	valid := statementInput(t, chainID, checkerGenesis, policy, 1)
	invalid := append([]byte(nil), valid...)
	invalid[200] ^= 0x01
	frozen := frozenFrame(policy)
	for name, c := range map[string]struct {
		input []byte
		word  byte
	}{"valid": {valid, 1}, "invalid": {invalid, 0}} {
		ret, left, err := env.checkerEVM(2, checkerGenesis).StaticCall(frozen, ghost.StatementCheckerAddress, c.input, 500_000)
		if err != nil || len(ret) != 32 || ret[31] != c.word {
			t.Fatalf("%s: ret %x, err %v", name, ret, err)
		}
		if used := 500_000 - left; used != checkerFullGas {
			t.Errorf("%s proof: gas used %d, want %d", name, used, checkerFullGas)
		}
	}
	// The exact gas suffices; one less runs out of gas and spends it all.
	if _, left, err := env.checkerEVM(2, checkerGenesis).StaticCall(frozen, ghost.StatementCheckerAddress, valid, checkerFullGas); err != nil || left != 0 {
		t.Errorf("exact gas: left %d, err %v", left, err)
	}
	if _, left, err := env.checkerEVM(2, checkerGenesis).StaticCall(frozen, ghost.StatementCheckerAddress, valid, checkerFullGas-1); err != ErrOutOfGas || left != 0 {
		t.Errorf("one gas short: left %d, err %v, want out of gas", left, err)
	}
	// Through a policy, the whole run costs the same whether the proof
	// verifies or not.
	p := env.mustCreatePolicy(1, saltOf(300), checkerPolicyCode(STATICCALL))
	in := statementInput(t, chainID, checkerGenesis, p, 1)
	_, leftValid, err := env.checkerEVM(2, checkerGenesis).Call(AccountRef(policySender), p, in, policyTestGas, new(uint256.Int))
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), in...)
	bad[300] ^= 0x01
	_, leftInvalid, err := env.checkerEVM(2, checkerGenesis).Call(AccountRef(policySender), p, bad, policyTestGas, new(uint256.Int))
	if err != nil {
		t.Fatal(err)
	}
	if leftValid != leftInvalid {
		t.Errorf("through a policy: valid proof leaves %d gas, invalid %d; the charge must not depend on the answer", leftValid, leftInvalid)
	}
}

// TestStatementCheckerBindsCallingPolicy checks that the checker binds the
// statement to the calling policy: a proof made for one policy is answered
// 1 for it and 0 for another policy with the same code that passes the same
// input.
func TestStatementCheckerBindsCallingPolicy(t *testing.T) {
	useStubVerifier(t)
	env := newPolicyEnv(t)
	chainID := checkerChainID(t)
	a := env.mustCreatePolicy(1, saltOf(400), checkerPolicyCode(STATICCALL))
	b := env.mustCreatePolicy(1, saltOf(401), checkerPolicyCode(STATICCALL))
	if a == b {
		t.Fatal("the two policies share an address")
	}
	forA := statementInput(t, chainID, checkerGenesis, a, 11)
	forB := statementInput(t, chainID, checkerGenesis, b, 11)
	for _, c := range []struct {
		name   string
		policy common.Address
		input  []byte
		word   uint64
	}{
		{"A with A's proof", a, forA, 1},
		{"B with A's proof", b, forA, 0},
		{"B with B's proof", b, forB, 1},
		{"A with B's proof", a, forB, 0},
	} {
		if r := env.callChecker(t, c.policy, checkerGenesis, c.input); !r.ok || r.size != 32 || r.word != c.word {
			t.Errorf("%s: result %+v, want the word %d", c.name, r, c.word)
		}
	}
}
