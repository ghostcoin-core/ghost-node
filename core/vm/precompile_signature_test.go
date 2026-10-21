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
	"math"
	"math/big"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/holiman/uint256"
)

// removedAddresses are the precompiles Ghost removes (spec 09, section 7).
var removedAddresses = []common.Address{
	common.BytesToAddress([]byte{0x01}), // ECRECOVER
	common.BytesToAddress([]byte{0x06}), // BN254 ADD
	common.BytesToAddress([]byte{0x07}), // BN254 MUL
	common.BytesToAddress([]byte{0x08}), // BN254 PAIRING
	common.BytesToAddress([]byte{0x0a}), // POINT EVALUATION
}

// sigTestContext is the context string of the test signatures.
const sigTestContext = "example/app/v1"

// precompileTestConfigs are configurations from Frontier to everything the
// node's code can switch on: the removed precompiles fail and the
// signature-verify precompile runs in each.
func precompileTestConfigs(t *testing.T) map[string]ctypes.ChainConfigurator {
	t.Helper()
	everything := ghost.InternalNetGenesis().Config
	zero := uint64(0)
	for _, set := range []func(*uint64) error{everything.SetEIP2537Transition, everything.SetEIP4844Transition, everything.SetEIP4844TransitionTime} {
		n := zero
		if err := set(&n); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]ctypes.ChainConfigurator{
		"frontier":         &coregeth.CoreGethChainConfig{ChainID: big.NewInt(1), Ethash: new(ctypes.EthashConfig)},
		"all ethash":       params.AllEthashProtocolChanges,
		"internal network": ghost.InternalNetGenesis().Config,
		"everything":       everything,
	}
}

func newPrecompileTestEVM(t *testing.T, config ctypes.ChainConfigurator) (*EVM, *state.StateDB) {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := BlockContext{
		CanTransfer: func(db StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, from, to common.Address, amount *uint256.Int) {
			db.SubBalance(from, amount)
			db.AddBalance(to, amount)
		},
		BlockNumber: big.NewInt(1),
		Time:        ghost.InternalNetTimestamp + 1,
		Difficulty:  big.NewInt(1),
		GasLimit:    30_000_000,
		BaseFee:     new(big.Int),
		BlobBaseFee: new(big.Int),
	}
	return NewEVM(ctx, TxContext{GasPrice: new(big.Int)}, statedb, config, Config{}), statedb
}

// sigTestKey returns a deterministic ML-DSA-44 key pair.
func sigTestKey(i byte) (*mldsa44.PublicKey, *mldsa44.PrivateKey) {
	var seed [mldsa44.SeedSize]byte
	seed[0] = i
	copy(seed[1:], "signature verify precompile")
	return mldsa44.NewKeyFromSeed(&seed)
}

func sigTestSign(t testing.TB, sk *mldsa44.PrivateKey, ctx string, msg []byte) []byte {
	t.Helper()
	sig := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(sk, msg, []byte(ctx), false, sig); err != nil {
		t.Fatal(err)
	}
	return sig
}

// sigVerifyInput encodes scheme || ctx_len || ctx || public_key || signature || message.
func sigVerifyInput(scheme uint16, ctx string, publicKey, signature, message []byte) []byte {
	in := []byte{byte(scheme >> 8), byte(scheme), byte(len(ctx))}
	in = append(in, ctx...)
	in = append(in, publicKey...)
	in = append(in, signature...)
	return append(in, message...)
}

// validSigInput returns a valid ML-DSA-44 input over msg.
func validSigInput(t testing.TB, ctx string, msg []byte) []byte {
	t.Helper()
	pk, sk := sigTestKey(1)
	return sigVerifyInput(types.GhostSchemeMLDSA44, ctx, pk.Bytes(), sigTestSign(t, sk, ctx, msg), msg)
}

// callerCode is a contract that passes its calldata to target with a CALL
// (which every configuration has) of innerGas gas and no value, and returns
// the first 32 bytes of the output followed by the success flag of the call.
func callerCode(target common.Address, innerGas uint32) []byte {
	code := []byte{
		byte(CALLDATASIZE), byte(PUSH1), 0, byte(PUSH1), 0, byte(CALLDATACOPY),
		byte(PUSH1), 0x20,  // retSize
		byte(PUSH1), 0x00,  // retOffset
		byte(CALLDATASIZE), // argsSize
		byte(PUSH1), 0x00,  // argsOffset
		byte(PUSH1), 0x00,  // value
		byte(PUSH20),
	}
	code = append(code, target.Bytes()...)
	code = append(code, byte(PUSH4), byte(innerGas>>24), byte(innerGas>>16), byte(innerGas>>8), byte(innerGas))
	return append(code,
		byte(CALL),
		byte(PUSH1), 0x20, byte(MSTORE),
		byte(PUSH1), 0x40, byte(PUSH1), 0x00, byte(RETURN),
	)
}

// callThroughContract runs input with gas through a contract that calls
// target with half of it, and returns the output word, whether the inner call
// succeeded and the gas the outer call left.
func callThroughContract(t *testing.T, config ctypes.ChainConfigurator, target common.Address, input []byte, gas uint64) (out []byte, ok bool, left uint64) {
	t.Helper()
	evm, statedb := newPrecompileTestEVM(t, config)
	contract := common.HexToAddress("0xc0de")
	statedb.CreateAccount(contract)
	statedb.SetCode(contract, callerCode(target, uint32(gas/2)))
	caller := common.HexToAddress("0xca11e5")
	statedb.Prepare(true, true, caller, common.Address{}, &contract, evm.ActivePrecompiles(), nil)
	ret, left, err := evm.Call(AccountRef(caller), contract, input, gas, new(uint256.Int))
	if err != nil {
		t.Fatalf("the calling contract fails: %v", err)
	}
	if len(ret) != 64 {
		t.Fatalf("the calling contract returns %d bytes, want 64", len(ret))
	}
	return ret[:32], new(big.Int).SetBytes(ret[32:]).Sign() != 0, left
}

// TestRemovedPrecompilesFail checks the removed precompiles 0x01, 0x06,
// 0x07, 0x08 and 0x0a in every configuration (QS-6): a call fails with an
// error that is not a revert and uses all the gas given to it, a call with
// value fails and moves no value, and the address stays a warm precompile.
// The BLS12-381 addresses 0x0b to 0x11 and P-256 at 0x0100 are not
// precompiles.
func TestRemovedPrecompilesFail(t *testing.T) {
	const gas = 100_000
	for name, config := range precompileTestConfigs(t) {
		t.Run(name, func(t *testing.T) {
			evm, statedb := newPrecompileTestEVM(t, config)
			active := make(map[common.Address]bool)
			for _, a := range evm.ActivePrecompiles() {
				active[a] = true
			}
			caller := common.HexToAddress("0xca11e5")
			statedb.SetBalance(caller, uint256.NewInt(1_000_000))
			statedb.Prepare(true, true, caller, common.Address{}, nil, evm.ActivePrecompiles(), nil)
			for _, addr := range removedAddresses {
				if !active[addr] {
					t.Errorf("%x is not in the precompile set; it must stay there, warm", addr)
				}
				if !statedb.AddressInAccessList(addr) {
					t.Errorf("%x is not warm at the start of a transaction", addr)
				}
				inputs := [][]byte{nil, make([]byte, 128), bytes.Repeat([]byte{0xff}, 192)}
				for _, in := range inputs {
					ret, left, err := evm.Call(AccountRef(caller), addr, in, gas, new(uint256.Int))
					if !errors.Is(err, ErrPrecompileRemoved) || errors.Is(err, ErrExecutionReverted) {
						t.Errorf("CALL %x with %d bytes: error %v, want %v", addr, len(in), err, ErrPrecompileRemoved)
					}
					if left != 0 || ret != nil {
						t.Errorf("CALL %x with %d bytes: %d gas left and %x returned, want all gas used and nothing returned", addr, len(in), left, ret)
					}
				}
				for kind, call := range map[string]func() (uint64, error){
					"STATICCALL": func() (uint64, error) {
						_, left, err := evm.StaticCall(AccountRef(caller), addr, nil, gas)
						return left, err
					},
					"DELEGATECALL": func() (uint64, error) {
						contract := NewContract(AccountRef(caller), AccountRef(caller), new(uint256.Int), 0)
						_, left, err := evm.DelegateCall(contract, addr, nil, gas)
						return left, err
					},
					"CALLCODE": func() (uint64, error) {
						_, left, err := evm.CallCode(AccountRef(caller), addr, nil, gas, new(uint256.Int))
						return left, err
					},
				} {
					if left, err := call(); !errors.Is(err, ErrPrecompileRemoved) || left != 0 {
						t.Errorf("%s %x: %d gas left, error %v; want all gas used and %v", kind, addr, left, err, ErrPrecompileRemoved)
					}
				}
				// A call with value fails and the value stays with the caller.
				before := statedb.GetBalance(caller).Clone()
				_, left, err := evm.Call(AccountRef(caller), addr, nil, gas, uint256.NewInt(7))
				if !errors.Is(err, ErrPrecompileRemoved) || left != 0 {
					t.Errorf("CALL %x with value: %d gas left, error %v; want all gas used and %v", addr, left, err, ErrPrecompileRemoved)
				}
				if b := statedb.GetBalance(addr); !b.IsZero() {
					t.Errorf("%x received %v wei", addr, b)
				}
				if b := statedb.GetBalance(caller); b.Cmp(before) != 0 {
					t.Errorf("the caller has %v after the failed call, want %v", b, before)
				}
				// From a contract, the call fails and takes all the gas the
				// contract passes on, half of its gas.
				const outer = 1_000_000
				_, ok, left := callThroughContract(t, config, addr, make([]byte, 128), outer)
				if ok {
					t.Errorf("a contract's CALL to %x succeeds", addr)
				}
				if left > outer/2 {
					t.Errorf("a contract's CALL to %x leaves %d gas, want at most %d: the call must use all it is given", addr, left, outer/2)
				}
			}
			absent := []common.Address{common.BytesToAddress([]byte{0x01, 0x00})}
			for b := byte(0x0b); b <= 0x12; b++ {
				absent = append(absent, common.BytesToAddress([]byte{b}))
			}
			for _, addr := range absent {
				if active[addr] {
					t.Errorf("%x is a precompile; the BLS12-381 and P-256 precompiles are never added", addr)
				}
			}
		})
	}
}

// TestSignatureVerifyPrecompileSchemes is QS-2: only scheme 0x0001 is
// accepted. Scheme IDs 0x0000, 0x0003 and 0xffff fail, and so does 0x0002
// (SLH-DSA, not accepted by the precompile yet) with an input of its lengths.
func TestSignatureVerifyPrecompileSchemes(t *testing.T) {
	p := &signatureVerify{}
	pk, sk := sigTestKey(1)
	msg := []byte("a message")
	sig := sigTestSign(t, sk, sigTestContext, msg)
	cases := map[string][]byte{
		"0x0000": sigVerifyInput(0x0000, sigTestContext, pk.Bytes(), sig, msg),
		"0x0003": sigVerifyInput(0x0003, sigTestContext, pk.Bytes(), sig, msg),
		"0xffff": sigVerifyInput(0xffff, sigTestContext, pk.Bytes(), sig, msg),
		"0x0002": sigVerifyInput(types.GhostSchemeSLHDSA, sigTestContext,
			make([]byte, types.GhostSLHDSAPublicKeySize), make([]byte, types.GhostSLHDSASignatureSize), msg),
	}
	for name, in := range cases {
		if g := p.RequiredGas(in); g != 0 {
			t.Errorf("scheme %s: required gas %d, want 0 (the failure takes all the gas instead)", name, g)
		}
		ret, left, err := RunPrecompiledContract(p, in, 1_000_000)
		if !errors.Is(err, ErrSignatureVerifyScheme) || left != 0 || ret != nil {
			t.Errorf("scheme %s: %x, %d gas left, error %v; want a failure with %v and no gas left", name, ret, left, err, ErrSignatureVerifyScheme)
		}
		_, ok, _ := callThroughContract(t, ghost.InternalNetGenesis().Config, SignatureVerifyAddress, in, 1_000_000)
		if ok {
			t.Errorf("scheme %s: the contract's call succeeds", name)
		}
	}
	// The same key and signature under scheme 0x0001 verify.
	ret, _, err := RunPrecompiledContract(p, sigVerifyInput(types.GhostSchemeMLDSA44, sigTestContext, pk.Bytes(), sig, msg), 1_000_000)
	if err != nil || !bytes.Equal(ret, signatureValid) {
		t.Errorf("scheme 0x0001: %x, %v; want a valid signature", ret, err)
	}
}

// TestSignatureVerifyPrecompileTxContext is QS-7: a context that begins with
// "ghost/tx/" fails, so a transaction signature cannot be checked as a
// message signature; any other context verifies.
func TestSignatureVerifyPrecompileTxContext(t *testing.T) {
	if !strings.HasPrefix(types.GhostAccountTxContext, SignatureVerifyTxContextPrefix) {
		t.Fatalf("the transaction context %q does not begin with %q", types.GhostAccountTxContext, SignatureVerifyTxContextPrefix)
	}
	p := &signatureVerify{}
	msg := common.Hash{0x52}.Bytes()
	for _, ctx := range []string{types.GhostAccountTxContext, "ghost/tx/", "ghost/tx/v2", "ghost/tx/anything"} {
		in := validSigInput(t, ctx, msg)
		ret, left, err := RunPrecompiledContract(p, in, 1_000_000)
		if !errors.Is(err, ErrSignatureVerifyContext) || left != 0 || ret != nil {
			t.Errorf("context %q: %x, %d gas left, error %v; want a failure with %v", ctx, ret, left, err, ErrSignatureVerifyContext)
		}
	}
	for _, ctx := range []string{"", "ghost/tx", "ghost/txv1", "Ghost/tx/v1", "app/ghost/tx/", sigTestContext, strings.Repeat("c", 255)} {
		ret, _, err := RunPrecompiledContract(p, validSigInput(t, ctx, msg), 1_000_000)
		if err != nil || !bytes.Equal(ret, signatureValid) {
			t.Errorf("context %q: %x, %v; want a valid signature", ctx, ret, err)
		}
	}
}

// TestSignatureVerifyPrecompileShortInput checks that an input too short
// for its header, context, public key and signature fails.
func TestSignatureVerifyPrecompileShortInput(t *testing.T) {
	p := &signatureVerify{}
	full := validSigInput(t, sigTestContext, nil)
	if ret, _, err := RunPrecompiledContract(p, full, 1_000_000); err != nil || !bytes.Equal(ret, signatureValid) {
		t.Fatalf("an empty message: %x, %v; want a valid signature", ret, err)
	}
	for _, n := range []int{0, 1, 2, 3, 3 + len(sigTestContext), len(full) - mldsa44.SignatureSize, len(full) - 1} {
		in := full[:n]
		ret, left, err := RunPrecompiledContract(p, in, 1_000_000)
		if !errors.Is(err, ErrSignatureVerifyShort) || left != 0 || ret != nil {
			t.Errorf("%d bytes: %x, %d gas left, error %v; want a failure with %v", n, ret, left, err, ErrSignatureVerifyShort)
		}
	}
	// A context length that runs past the input.
	in := common.CopyBytes(full)
	in[2] = 255
	in = in[:3+200]
	if _, _, err := RunPrecompiledContract(p, in, 1_000_000); !errors.Is(err, ErrSignatureVerifyShort) {
		t.Errorf("a context longer than the input: %v, want %v", err, ErrSignatureVerifyShort)
	}
}

// TestSignatureVerifyPrecompileGas checks the gas: the scheme's verification
// gas plus SIGVERIFY_WORD_GAS for each 32-byte word of the message, charged
// before verifying, so a call with one gas less fails and uses all its gas.
func TestSignatureVerifyPrecompileGas(t *testing.T) {
	if ghost.SigVerifyWordGas == 0 {
		t.Fatal("SIGVERIFY_WORD_GAS is zero")
	}
	p := &signatureVerify{}
	for _, tc := range []struct{ size, words uint64 }{{0, 0}, {1, 1}, {31, 1}, {32, 1}, {33, 2}, {64, 2}, {1000, 32}, {4096, 128}} {
		msg := bytes.Repeat([]byte{0xaa}, int(tc.size))
		in := validSigInput(t, sigTestContext, msg)
		want := ghost.AccountTxVerifyGasMLDSA44 + tc.words*ghost.SigVerifyWordGas
		if got := p.RequiredGas(in); got != want {
			t.Errorf("message of %d bytes: gas %d, want %d", tc.size, got, want)
		}
		ret, left, err := RunPrecompiledContract(p, in, want)
		if err != nil || left != 0 || !bytes.Equal(ret, signatureValid) {
			t.Errorf("message of %d bytes with exactly %d gas: %x, %d left, %v", tc.size, want, ret, left, err)
		}
		ret, left, err = RunPrecompiledContract(p, in, want+10)
		if err != nil || left != 10 || !bytes.Equal(ret, signatureValid) {
			t.Errorf("message of %d bytes with %d gas: %x, %d left, %v; want 10 left", tc.size, want+10, ret, left, err)
		}
		if _, left, err := RunPrecompiledContract(p, in, want-1); !errors.Is(err, ErrOutOfGas) || left != 0 {
			t.Errorf("message of %d bytes with %d gas: %d left, %v; want out of gas", tc.size, want-1, left, err)
		}
	}
	// An invalid signature costs the same as a valid one.
	in := validSigInput(t, sigTestContext, []byte("message"))
	in[len(in)-1] ^= 1
	if got, want := p.RequiredGas(in), ghost.AccountTxVerifyGasMLDSA44+ghost.SigVerifyWordGas; got != want {
		t.Errorf("invalid signature: gas %d, want %d", got, want)
	}
}

// TestSignatureVerifyPrecompileContractCall verifies a valid and an invalid
// ML-DSA-44 signature through a contract's call to 0x51 on the internal
// network's configuration.
func TestSignatureVerifyPrecompileContractCall(t *testing.T) {
	config := ghost.InternalNetGenesis().Config
	evm, _ := newPrecompileTestEVM(t, config)
	found := false
	for _, a := range evm.ActivePrecompiles() {
		found = found || a == SignatureVerifyAddress
	}
	if !found || SignatureVerifyAddress != common.HexToAddress("0x0000000000000000000000000000000000000051") {
		t.Fatalf("the signature-verify precompile is not active at 0x51")
	}
	msg := []byte("transfer 10 to the example account")
	valid := validSigInput(t, sigTestContext, msg)

	out, ok, _ := callThroughContract(t, config, SignatureVerifyAddress, valid, 1_000_000)
	if !ok || !bytes.Equal(out, signatureValid) {
		t.Errorf("valid signature: success %v, output %x; want success and 1", ok, out)
	}

	invalid := map[string][]byte{}
	flipped := common.CopyBytes(valid)
	flipped[len(flipped)-len(msg)-1] ^= 1 // the last byte of the signature
	invalid["signature changed"] = flipped
	otherMsg := common.CopyBytes(valid)
	otherMsg[len(otherMsg)-1] ^= 1
	invalid["message changed"] = otherMsg
	otherCtx := common.CopyBytes(valid)
	otherCtx[3] ^= 1
	invalid["context changed"] = otherCtx
	otherPk, _ := sigTestKey(2)
	invalid["other key"] = sigVerifyInput(types.GhostSchemeMLDSA44, sigTestContext, otherPk.Bytes(), valid[3+len(sigTestContext)+types.GhostMLDSA44PublicKeySize:len(valid)-len(msg)], msg)
	for name, in := range invalid {
		out, ok, _ := callThroughContract(t, config, SignatureVerifyAddress, in, 1_000_000)
		if !ok || !bytes.Equal(out, signatureInvalid) {
			t.Errorf("%s: success %v, output %x; want success and 0", name, ok, out)
		}
	}

	// Not enough gas for the verification: the call fails.
	if _, ok, _ := callThroughContract(t, config, SignatureVerifyAddress, valid, 5_000); ok {
		t.Errorf("a call with less gas than the verification succeeds")
	}
}

// BenchmarkSignatureVerifyWordGasSlowest is the measurement SIGVERIFY_WORD_GAS
// is set from, the same way as VERIFY_GAS (docs/account-transactions.md):
// 1,000 valid and 1,000 invalid signatures, each over a different key. For
// each, the verification of a one-word message and of a message 1,024 words
// longer are timed; the cost of one extra word is the difference over 1,024.
// It reports the slowest, t_ms, and ceil(t_ms * 10,000), at least 1. Run it
// with
//
//	go test ./core/vm/ -run '^$' -bench SignatureVerifyWordGasSlowest -benchtime 1x
func BenchmarkSignatureVerifyWordGasSlowest(b *testing.B) {
	slowest, median := measureSignatureVerifyWordCost(b)
	gas := uint64(math.Ceil(slowest * ghost.AccountTxGasPerMs))
	if gas < 1 {
		gas = 1
	}
	b.ReportMetric(slowest, "slowest-ms")
	b.ReportMetric(median, "median-ms")
	b.ReportMetric(float64(gas), "word-gas")
	b.Logf("2000 signatures on %s/%s, %d CPUs, %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
}

// measureSignatureVerifyWordCost returns the slowest and the median measured
// cost of one extra 32-byte word of message, in milliseconds.
func measureSignatureVerifyWordCost(t testing.TB) (slowest, median float64) {
	const extraWords = 1024
	ctx := []byte(sigTestContext)
	short := bytes.Repeat([]byte{0x5a}, 32)
	long := bytes.Repeat([]byte{0x5a}, 32*(1+extraWords))
	timeVerify := func(pk *mldsa44.PublicKey, msg, sig []byte, want bool) time.Duration {
		start := time.Now()
		var key mldsa44.PublicKey
		if err := key.UnmarshalBinary(pk.Bytes()); err != nil {
			t.Fatal(err)
		}
		ok := mldsa44.Verify(&key, msg, ctx, sig)
		elapsed := time.Since(start)
		if ok != want {
			t.Fatal("unexpected verification result")
		}
		return elapsed
	}
	var costs []float64
	for round := 0; round < 2; round++ {
		for i := 0; i < 1000; i++ {
			var seed [mldsa44.SeedSize]byte
			seed[0], seed[1], seed[2] = byte(i), byte(i>>8), byte(round)
			pk, sk := mldsa44.NewKeyFromSeed(&seed)
			shortSig := sigTestSign(t, sk, sigTestContext, short)
			longSig := sigTestSign(t, sk, sigTestContext, long)
			if round == 1 {
				shortSig[i%len(shortSig)] ^= 1
				longSig[i%len(longSig)] ^= 1
			}
			tShort := timeVerify(pk, short, shortSig, round == 0)
			tLong := timeVerify(pk, long, longSig, round == 0)
			costs = append(costs, float64((tLong-tShort).Nanoseconds())/1e6/extraWords)
		}
	}
	sort.Float64s(costs)
	return costs[len(costs)-1], costs[len(costs)/2]
}
