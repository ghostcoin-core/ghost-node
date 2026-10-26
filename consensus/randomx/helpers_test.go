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

package randomx

import (
	"math/big"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
	"github.com/holiman/uint256"
)

// Test chains use a small key interval and delay, and difficulty 16 so that
// sealing takes a few dozen hashes and a bad nonce is easy to find.
const (
	testEpoch     = 8
	testLag       = 4
	testBlockTime = 10 // the spacing of test blocks, so ASERT stays at 16
	testGenesisAt = 1_700_000_000
)

var testDifficulty = big.NewInt(16)

func testParams() ghostrules.Params {
	return ghostrules.Params{
		BlockTime:       testBlockTime,
		HalfLife:        3_600,
		StartDifficulty: new(big.Int).Set(testDifficulty),
		MinDifficulty:   new(big.Int).Set(testDifficulty),
		FutureDrift:     30,
		FirstReward:     uint256.NewInt(2_000_000_000_000_000_000),
		TailReward:      uint256.NewInt(100_000_000_000_000_000),
	}
}

// testConfig is a London chain with nothing after it, as the Ghost profile
// requires.
func testConfig() ctypes.ChainConfigurator {
	return &goethereum.ChainConfig{
		ChainID:             big.NewInt(1337),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		Ethash:              new(ctypes.EthashConfig),
	}
}

func newTestEngine(t *testing.T, params ghostrules.Params) *RandomX {
	t.Helper()
	engine, err := New(Config{Params: params, EpochLength: testEpoch, KeyLag: testLag})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return engine
}

// testReader is a header reader over a fixed set of headers. Headers are
// found by hash; GetHeaderByNumber answers only for genesis and counts
// every other call, so tests can show the key rule never uses it.
type testReader struct {
	config   ctypes.ChainConfigurator
	genesis  *types.Header
	byHash   map[common.Hash]*types.Header
	byNumber atomic.Int64
}

func newTestReader(config ctypes.ChainConfigurator, genesis *types.Header, headers ...*types.Header) *testReader {
	r := &testReader{config: config, genesis: genesis, byHash: make(map[common.Hash]*types.Header)}
	r.add(genesis)
	r.add(headers...)
	return r
}

func (r *testReader) add(headers ...*types.Header) {
	for _, h := range headers {
		if h != nil {
			r.byHash[h.Hash()] = h
		}
	}
}

func (r *testReader) Config() ctypes.ChainConfigurator { return r.config }
func (r *testReader) CurrentHeader() *types.Header     { return nil }
func (r *testReader) GetTd(common.Hash, uint64) *big.Int {
	return nil
}

func (r *testReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if h := r.byHash[hash]; h != nil && h.Number.Uint64() == number {
		return h
	}
	return nil
}

func (r *testReader) GetHeaderByHash(hash common.Hash) *types.Header { return r.byHash[hash] }

func (r *testReader) GetHeaderByNumber(number uint64) *types.Header {
	if number == 0 {
		return r.genesis
	}
	r.byNumber.Add(1)
	return nil
}

// fullHeader returns a header with every field set, the optional ones too.
func fullHeader() *types.Header {
	blobGasUsed, excessBlobGas := uint64(7), uint64(8)
	withdrawals, beaconRoot := common.Hash{9}, common.Hash{10}
	return &types.Header{
		ParentHash:       common.Hash{1},
		UncleHash:        common.Hash{2},
		Coinbase:         common.Address{3},
		Root:             common.Hash{4},
		TxHash:           common.Hash{5},
		ReceiptHash:      common.Hash{6},
		Bloom:            types.Bloom{7},
		Difficulty:       big.NewInt(16),
		Number:           big.NewInt(100),
		GasLimit:         8_000_000,
		GasUsed:          21_000,
		Time:             testGenesisAt + 1000,
		Extra:            []byte("extra"),
		MixDigest:        common.Hash{8},
		Nonce:            types.EncodeNonce(99),
		BaseFee:          big.NewInt(1_000_000_000),
		WithdrawalsHash:  &withdrawals,
		BlobGasUsed:      &blobGasUsed,
		ExcessBlobGas:    &excessBlobGas,
		ParentBeaconRoot: &beaconRoot,
	}
}

// ghostHeader returns a header of the Ghost layout with every field set:
// both tree roots, the data marker root and the base fee, and none of the fields it forbids.
func ghostHeader() *types.Header {
	h := fullHeader()
	h.WithdrawalsHash, h.BlobGasUsed, h.ExcessBlobGas, h.ParentBeaconRoot = nil, nil, nil, nil
	coin, data, marker := common.Hash{11}, common.Hash{12}, common.Hash{13}
	h.CoinTreeRoot, h.DataTreeRoot, h.DataMarkerRoot = &coin, &data, &marker
	return h
}

// headerFields returns the names of every field of types.Header.
func headerFields() []string {
	t := reflect.TypeOf(types.Header{})
	names := make([]string, t.NumField())
	for i := range names {
		names[i] = t.Field(i).Name
	}
	return names
}

// mutateField changes the named field of h in place to a different value,
// which depends on variant, setting a nil optional field. It fails the test
// on a field type it does not know, so a new header field is noticed.
func mutateField(t *testing.T, h *types.Header, name string, variant int) {
	t.Helper()
	f := reflect.ValueOf(h).Elem().FieldByName(name)
	delta := uint64(variant) + 1
	switch v := f.Addr().Interface().(type) {
	case *common.Hash:
		v[0] += byte(delta)
	case *common.Address:
		v[0] += byte(delta)
	case *types.Bloom:
		v[0] += byte(delta)
	case *types.BlockNonce:
		v[0] += byte(delta)
	case *uint64:
		*v += delta
	case *[]byte:
		*v = append(append([]byte{}, *v...), byte(delta))
	case **big.Int:
		if *v == nil {
			*v = new(big.Int)
		}
		*v = new(big.Int).Add(*v, new(big.Int).SetUint64(delta))
	case **common.Hash:
		next := common.Hash{}
		if *v != nil {
			next = **v
		}
		next[0] += byte(delta)
		*v = &next
	case **uint64:
		var next uint64
		if *v != nil {
			next = **v
		}
		next += delta
		*v = &next
	default:
		t.Fatalf("header field %s has type %s, which the test does not know how to change", name, f.Type())
	}
}
