// Copyright 2025 The go-ethereum Authors
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

package ethapi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestGetRawNotFoundNoPanic checks that the raw-data debug methods do not
// dereference a nil block when the requested block number is unknown
// (go-ethereum #31157).
func TestGetRawNotFoundNoPanic(t *testing.T) {
	t.Parallel()

	api := NewDebugAPI(newBackendMock())
	number := rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(1 << 40))

	if res, err := api.GetRawHeader(context.Background(), number); err != nil || res != nil {
		t.Errorf("GetRawHeader: have %x, %v; want nil, nil", res, err)
	}
	if res, err := api.GetRawBlock(context.Background(), number); err != nil || res != nil {
		t.Errorf("GetRawBlock: have %x, %v; want nil, nil", res, err)
	}
	if res, err := api.GetRawReceipts(context.Background(), number); err != nil || res != nil {
		t.Errorf("GetRawReceipts: have %v, %v; want nil, nil", res, err)
	}
}

// TestGetProofSlotLimit checks that eth_getProof rejects requests with more
// storage keys than maxGetProofKeys before touching any state (go-ethereum
// #34617).
func TestGetProofSlotLimit(t *testing.T) {
	t.Parallel()

	api := NewBlockChainAPI(newBackendMock())
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	keys := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = hexutil.EncodeUint64(uint64(i))
		}
		return out
	}

	// At the limit the request passes validation; the mock backend has no
	// state, so the call ends without a result.
	if _, err := api.GetProof(context.Background(), common.Address{}, keys(maxGetProofKeys), latest); err != nil {
		t.Fatalf("at limit: unexpected error %v", err)
	}
	// One past the limit is rejected as invalid params.
	_, err := api.GetProof(context.Background(), common.Address{}, keys(maxGetProofKeys+1), latest)
	if err == nil {
		t.Fatal("over limit: expected error, got nil")
	}
	var perr *invalidParamsError
	if !errors.As(err, &perr) || perr.ErrorCode() != -32602 {
		t.Fatalf("over limit: want invalid params error, have %T %v", err, err)
	}
	want := fmt.Sprintf("too many storage keys requested (max %d, got %d)", maxGetProofKeys, maxGetProofKeys+1)
	if err.Error() != want {
		t.Fatalf("over limit: error mismatch, have %q want %q", err.Error(), want)
	}
}

// TestTxArgsTypeForkValidation checks that transaction arguments selecting a
// transaction type whose fork is not active are rejected (go-ethereum #35588).
func TestTxArgsTypeForkValidation(t *testing.T) {
	t.Parallel()

	var (
		b         = newBackendMock()
		config    = b.ChainConfig()
		from      = common.Address{0x1}
		to        = common.Address{0x2}
		fee       = (*hexutil.Big)(big.NewInt(100))
		gas       = hexutil.Uint64(21000)
		nonce     = hexutil.Uint64(0)
		emptyList = types.AccessList{}
	)
	// The mock enables EIP-2930 (Berlin) at 0 and EIP-1559 (London) at 1000.
	// Push Berlin out so access list transactions are not yet valid.
	if err := config.SetEIP2930Transition(newUint64(500)); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		number int64
		args   TransactionArgs
		reject bool
	}{
		{"legacy before berlin", 400, TransactionArgs{GasPrice: fee}, false},
		{"access list before berlin", 400, TransactionArgs{GasPrice: fee, AccessList: &emptyList}, true},
		{"access list after berlin", 900, TransactionArgs{GasPrice: fee, AccessList: &emptyList}, false},
		{"dynamic fee before london", 900, TransactionArgs{MaxFeePerGas: fee, MaxPriorityFeePerGas: fee}, true},
		{"priority fee before london", 900, TransactionArgs{MaxPriorityFeePerGas: fee}, true},
		{"dynamic fee after london", 1100, TransactionArgs{MaxFeePerGas: fee, MaxPriorityFeePerGas: fee}, false},
		{"dynamic fee with access list after london", 1100, TransactionArgs{MaxFeePerGas: fee, MaxPriorityFeePerGas: fee, AccessList: &emptyList}, false},
	}
	for _, tt := range tests {
		args := tt.args
		args.From, args.To = &from, &to
		err := args.ValidateTxTypeFork(config, big.NewInt(tt.number))
		if tt.reject != (err != nil) {
			t.Errorf("%s: reject=%v, have error %v", tt.name, tt.reject, err)
			continue
		}
		if err != nil && !errors.Is(err, core.ErrTxTypeNotSupported) {
			t.Errorf("%s: want ErrTxTypeNotSupported, have %v", tt.name, err)
		}
		// setDefaults, used by eth_sendTransaction and eth_signTransaction,
		// must apply the same rule at the current head.
		b.current.Number = big.NewInt(tt.number)
		args = tt.args
		args.From, args.To, args.Gas, args.Nonce = &from, &to, &gas, &nonce
		err = args.setDefaults(context.Background(), b, true)
		if tt.reject {
			if err == nil || !errors.Is(err, core.ErrTxTypeNotSupported) {
				t.Errorf("%s: setDefaults want ErrTxTypeNotSupported, have %v", tt.name, err)
			}
		} else if err != nil && strings.Contains(err.Error(), "transaction type not supported") {
			t.Errorf("%s: setDefaults rejected an active type: %v", tt.name, err)
		}
	}
}

func newUint64(v uint64) *uint64 { return &v }
