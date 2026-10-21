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

package tracers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
)

// accountSenderTracerName is the name of senderTracer in the directory.
const accountSenderTracerName = "accountSenderTestTracer"

func init() {
	DefaultDirectory.Register(accountSenderTracerName, func(*Context, json.RawMessage) (Tracer, error) {
		return new(senderTracer), nil
	}, false)
}

// senderTracer records the sender and the gas, intrinsic gas included, of the
// traced transaction.
type senderTracer struct {
	sender   common.Address
	gasLimit uint64
	gasUsed  uint64
}

// senderTrace is the result of senderTracer.
type senderTrace struct {
	From    common.Address `json:"from"`
	GasUsed uint64         `json:"gasUsed"`
}

func (t *senderTracer) CaptureTxStart(gasLimit uint64) { t.gasLimit = gasLimit }
func (t *senderTracer) CaptureTxEnd(restGas uint64)    { t.gasUsed = t.gasLimit - restGas }
func (t *senderTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.sender = from
}
func (t *senderTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {}
func (t *senderTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}
func (t *senderTracer) CaptureExit(output []byte, gasUsed uint64, err error) {}
func (t *senderTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
}
func (t *senderTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}
func (t *senderTracer) Stop(err error) {}
func (t *senderTracer) GetResult() (json.RawMessage, error) {
	return json.Marshal(senderTrace{From: t.sender, GasUsed: t.gasUsed})
}

// accountSenderGas is the gas of an account transfer signed with ML-DSA-44.
var accountSenderGas = vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// otherGenesisBackend is a backend whose genesis header is not its chain's,
// so the sender of none of its account transactions can be derived.
type otherGenesisBackend struct {
	*testBackend
}

func (b otherGenesisBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number == 0 {
		return &types.Header{Number: new(big.Int), Extra: []byte("another chain")}, nil
	}
	return b.testBackend.HeaderByNumber(ctx, number)
}

// newAccountSenderBackend returns a backend whose chain has one account
// transaction in block 1 and two in block 2, all of the returned account.
func newAccountSenderBackend(t *testing.T) (*testBackend, common.Address) {
	key, pub, addr := testAccount(0x41)
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub); addr != want {
		t.Fatalf("account address %x, want %x", addr, want)
	}
	recipient := common.HexToAddress("0x5252525252525252525252525252525252525252")
	genesis := &genesisT.Genesis{
		Config:  params.TestChainConfig,
		Alloc:   genesisT.GenesisAlloc{addr: {Balance: big.NewInt(vars.Ether)}},
		BaseFee: big.NewInt(vars.InitialBaseFee),
	}
	signer := types.NewGhostAccountSigner(types.LatestSigner(genesis.Config), core.GenesisToBlock(genesis, nil).Hash())
	nonce := uint64(0)
	backend := newTestBackend(t, 2, genesis, func(i int, b *core.BlockGen) {
		for n := 0; n <= i; n++ {
			tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
				ChainID:   genesis.Config.GetChainID(),
				Nonce:     nonce,
				GasTipCap: new(big.Int),
				GasFeeCap: b.BaseFee(),
				Gas:       accountSenderGas,
				To:        &recipient,
				Value:     big.NewInt(1000),
			})
			if err != nil {
				t.Fatalf("sign account transaction %d: %v", nonce, err)
			}
			b.AddTx(tx)
			nonce++
		}
	})
	return backend, addr
}

// checkSenderTrace checks that a senderTracer result is the trace of an
// account transfer sent by addr.
func checkSenderTrace(t *testing.T, name string, result interface{}, addr common.Address) {
	t.Helper()
	raw, ok := result.(json.RawMessage)
	if !ok {
		t.Fatalf("%s: result of type %T", name, result)
	}
	var trace senderTrace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("%s: decode %s: %v", name, raw, err)
	}
	if trace.From != addr {
		t.Errorf("%s: traced from %x, want the account %x", name, trace.From, addr)
	}
	if trace.GasUsed != accountSenderGas {
		t.Errorf("%s: gas used %d, want %d with the signature gas", name, trace.GasUsed, accountSenderGas)
	}
}

// TestAccountSenderTraceTransaction checks that the trace of an account
// transaction runs from its account, and that a sender that cannot be
// derived is an error.
func TestAccountSenderTraceTransaction(t *testing.T) {
	t.Parallel()

	backend, addr := newAccountSenderBackend(t)
	defer backend.teardown()

	tracer := accountSenderTracerName
	for number := uint64(1); number <= 2; number++ {
		tx := backend.chain.GetBlockByNumber(number).Transactions()[0]
		result, err := NewAPI(backend).TraceTransaction(context.Background(), tx.Hash(), &TraceConfig{Tracer: &tracer})
		if err != nil {
			t.Fatalf("block %d: trace: %v", number, err)
		}
		checkSenderTrace(t, fmt.Sprintf("block %d", number), result, addr)

		// The struct logger runs the transaction with its signature gas.
		result, err = NewAPI(backend).TraceTransaction(context.Background(), tx.Hash(), nil)
		if err != nil {
			t.Fatalf("block %d: struct log trace: %v", number, err)
		}
		var logs struct {
			Gas    uint64 `json:"gas"`
			Failed bool   `json:"failed"`
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("block %d: encode struct log trace: %v", number, err)
		}
		if err := json.Unmarshal(raw, &logs); err != nil {
			t.Fatalf("block %d: decode struct log trace %s: %v", number, raw, err)
		}
		if logs.Failed || logs.Gas != accountSenderGas {
			t.Errorf("block %d: struct log trace %s, want gas %d and not failed", number, raw, accountSenderGas)
		}
	}

	// Bound to another genesis hash, the signature does not verify.
	tx := backend.chain.GetBlockByNumber(1).Transactions()[0]
	other := NewAPI(otherGenesisBackend{backend})
	if result, err := other.TraceTransaction(context.Background(), tx.Hash(), &TraceConfig{Tracer: &tracer}); !errors.Is(err, types.ErrInvalidSig) {
		t.Fatalf("underivable sender: result %s, error %v, want %v", result, err, types.ErrInvalidSig)
	}
}

// TestAccountSenderTraceBlock checks that the trace of a block runs each of
// its account transactions from their account, the second after the first
// one is replayed from the account, and that a sender that cannot be derived
// is an error.
func TestAccountSenderTraceBlock(t *testing.T) {
	t.Parallel()

	backend, addr := newAccountSenderBackend(t)
	defer backend.teardown()

	tracer := accountSenderTracerName
	results, err := NewAPI(backend).TraceBlockByNumber(context.Background(), rpc.BlockNumber(2), &TraceConfig{Tracer: &tracer})
	if err != nil {
		t.Fatalf("trace block: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("%d results, want 2", len(results))
	}
	for i, res := range results {
		if res.Error != "" {
			t.Fatalf("transaction %d: trace error %s", i, res.Error)
		}
		checkSenderTrace(t, fmt.Sprintf("transaction %d", i), res.Result, addr)
	}

	// The intermediate roots replay the block from the account as well, so
	// both transactions apply.
	block := backend.chain.GetBlockByNumber(2)
	roots, err := NewAPI(backend).IntermediateRoots(context.Background(), block.Hash(), nil)
	if err != nil {
		t.Fatalf("intermediate roots: %v", err)
	}
	if len(roots) != 2 {
		t.Errorf("%d intermediate roots, want 2", len(roots))
	}

	// Bound to another genesis hash, the signatures do not verify.
	other := NewAPI(otherGenesisBackend{backend})
	if results, err := other.TraceBlockByNumber(context.Background(), rpc.BlockNumber(2), &TraceConfig{Tracer: &tracer}); !errors.Is(err, types.ErrInvalidSig) {
		t.Fatalf("underivable sender: %d results, error %v, want %v", len(results), err, types.ErrInvalidSig)
	}
	if roots, err := other.IntermediateRoots(context.Background(), block.Hash(), nil); !errors.Is(err, types.ErrInvalidSig) {
		t.Fatalf("underivable sender, intermediate roots: %d roots, error %v, want %v", len(roots), err, types.ErrInvalidSig)
	}
}
