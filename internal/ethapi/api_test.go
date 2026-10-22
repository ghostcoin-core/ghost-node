// Copyright 2023 The go-ethereum Authors
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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/ghostpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/internal/blocktest"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

func testTransactionMarshal(t *testing.T, tests []txData, config ctypes.ChainConfigurator) {
	var (
		signer           = types.NewGhostAccountSigner(types.LatestSigner(config), common.Hash{0x01})
		key, _           = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		accountKey, _, _ = testAccount(0x66)
	)

	for i, tt := range tests {
		var (
			tx2 types.Transaction
			tx  *types.Transaction
			err error
		)
		if txdata, ok := tt.Tx.(*types.GhostAccountTx); ok {
			tx, err = types.SignGhostAccountTx(signer, accountKey, txdata)
		} else {
			tx, err = types.SignNewTx(key, signer, tt.Tx)
		}
		if err != nil {
			t.Fatalf("test %d: signing failed: %v", i, err)
		}
		// Regular transaction
		if data, err := json.Marshal(tx); err != nil {
			t.Fatalf("test %d: marshalling failed; %v", i, err)
		} else if err = tx2.UnmarshalJSON(data); err != nil {
			t.Fatalf("test %d: sunmarshal failed: %v", i, err)
		} else if want, have := tx.Hash(), tx2.Hash(); want != have {
			t.Fatalf("test %d: stx changed, want %x have %x", i, want, have)
		}

		// rpcTransaction
		if tx.Type() == types.GhostAccountTxType {
			// The RPC form of an account transaction carries its scheme and
			// public key instead of v, r and s.
			rpcTx, err := newSignedRPCTransaction(signer, tx, common.Hash{}, 0, 0, nil)
			if err != nil {
				t.Fatalf("test %d: rpc transaction: %v", i, err)
			}
			if rpcTx.Hash != tx.Hash() {
				t.Fatalf("test %d: rpc hash %x, want %x", i, rpcTx.Hash, tx.Hash())
			}
			data, err := json.Marshal(rpcTx)
			if err != nil {
				t.Fatalf("test %d: marshalling failed; %v", i, err)
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatalf("test %d: unmarshal failed: %v", i, err)
			}
			scheme, publicKey, _, _ := tx.GhostAccountAuth()
			id := types.GhostScheme(scheme)
			for name, want := range map[string]string{
				"scheme":    hexutil.Encode(id[:]),
				"publicKey": hexutil.Encode(publicKey),
			} {
				if fields[name] != want {
					t.Fatalf("test %d: %s is %v, want %s", i, name, fields[name], want)
				}
				delete(fields, name)
			}
			for _, name := range []string{"v", "r", "s", "yParity", "signature"} {
				if _, ok := fields[name]; ok {
					t.Fatalf("test %d: account transaction has %s", i, name)
				}
			}
			rest, err := json.Marshal(fields)
			if err != nil {
				t.Fatalf("test %d: marshalling failed; %v", i, err)
			}
			want, have := tt.Want, string(rest)
			require.JSONEqf(t, want, have, "test %d: rpc json not match, want %s have %s", i, want, have)
			continue
		}
		rpcTx := newRPCTransaction(tx, common.Hash{}, 0, 0, 0, nil, config)
		if data, err := json.Marshal(rpcTx); err != nil {
			t.Fatalf("test %d: marshalling failed; %v", i, err)
		} else if err = tx2.UnmarshalJSON(data); err != nil {
			t.Fatalf("test %d: unmarshal failed: %v", i, err)
		} else if want, have := tx.Hash(), tx2.Hash(); want != have {
			t.Fatalf("test %d: tx changed, want %x have %x", i, want, have)
		} else {
			want, have := tt.Want, string(data)
			require.JSONEqf(t, want, have, "test %d: rpc json not match, want %s have %s", i, want, have)
		}
	}
}

func TestTransaction_RoundTripRpcJSON(t *testing.T) {
	// The ML-DSA-44 signatures are hedged: a fixed random stream makes the
	// recorded hashes reproducible.
	cryptotest.SetGlobalRandom(t, 1)
	var (
		config = params.AllEthashProtocolChanges
		tests  = allTransactionTypes(common.Address{0xde, 0xad}, config)
	)
	testTransactionMarshal(t, tests, config)
}

func TestTransactionBlobTx(t *testing.T) {
	t.Parallel()
	config := *params.TestChainConfig
	config.ShanghaiTime = new(uint64)
	config.CancunTime = new(uint64)
	tests := allBlobTxs(common.Address{0xde, 0xad}, &config)

	testTransactionMarshal(t, tests, &config)
}

type txData struct {
	Tx   types.TxData
	Want string
}

func allTransactionTypes(addr common.Address, config ctypes.ChainConfigurator) []txData {
	return []txData{
		{
			Tx: &types.GhostAccountTx{
				ChainID:   config.GetChainID(),
				Nonce:     5,
				GasTipCap: big.NewInt(6),
				GasFeeCap: big.NewInt(9),
				Gas:       7,
				To:        &addr,
				Value:     big.NewInt(8),
				Data:      []byte{0, 1, 2, 3, 4},
			},
			Want: `{
				"blockHash": null,
				"blockNumber": null,
				"from": "0xdac2f10f2d3510a7441026e1eb55f12c2df5baa7",
				"gas": "0x7",
				"gasPrice": "0x9",
				"hash": "0x4dd06cff1765537474b6d6db74daf6885dd23ed0380bf8cd9c758d24f0fbd30f",
				"input": "0x0001020304",
				"nonce": "0x5",
				"to": "0xdead000000000000000000000000000000000000",
				"transactionIndex": null,
				"value": "0x8",
				"type": "0x52",
				"chainId": "0x539",
				"maxFeePerGas": "0x9",
				"maxPriorityFeePerGas": "0x6",
				"accessList": []
			}`,
		}, {
			Tx: &types.GhostAccountTx{
				ChainID:   config.GetChainID(),
				Nonce:     5,
				GasTipCap: big.NewInt(6),
				GasFeeCap: big.NewInt(9),
				Gas:       7,
				To:        nil,
				Value:     big.NewInt(8),
				Data:      []byte{0, 1, 2, 3, 4},
			},
			Want: `{
				"blockHash": null,
				"blockNumber": null,
				"from": "0xdac2f10f2d3510a7441026e1eb55f12c2df5baa7",
				"gas": "0x7",
				"gasPrice": "0x9",
				"hash": "0xf31613e40b18bc7aa74fdde6b3355850e0d23298a5cba328a6f23ca07ab16ea0",
				"input": "0x0001020304",
				"nonce": "0x5",
				"to": null,
				"transactionIndex": null,
				"value": "0x8",
				"type": "0x52",
				"chainId": "0x539",
				"maxFeePerGas": "0x9",
				"maxPriorityFeePerGas": "0x6",
				"accessList": []
			}`,
		}, {
			Tx: &types.GhostAccountTx{
				ChainID:   config.GetChainID(),
				Nonce:     5,
				GasTipCap: big.NewInt(6),
				GasFeeCap: big.NewInt(9),
				Gas:       7,
				To:        &addr,
				Value:     big.NewInt(8),
				Data:      []byte{0, 1, 2, 3, 4},
				AccessList: types.AccessList{
					types.AccessTuple{
						Address:     common.Address{0x2},
						StorageKeys: []common.Hash{types.EmptyRootHash},
					},
				},
			},
			Want: `{
				"blockHash": null,
				"blockNumber": null,
				"from": "0xdac2f10f2d3510a7441026e1eb55f12c2df5baa7",
				"gas": "0x7",
				"gasPrice": "0x9",
				"hash": "0xd45450c76443aa19518c47211322146a6f93fa08be60800b98bfc3b4452cc697",
				"input": "0x0001020304",
				"nonce": "0x5",
				"to": "0xdead000000000000000000000000000000000000",
				"transactionIndex": null,
				"value": "0x8",
				"type": "0x52",
				"chainId": "0x539",
				"maxFeePerGas": "0x9",
				"maxPriorityFeePerGas": "0x6",
				"accessList": [
					{
						"address": "0x0200000000000000000000000000000000000000",
						"storageKeys": [
							"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
						]
					}
				]
			}`,
		}, {
			Tx: &types.GhostAccountTx{
				ChainID:    config.GetChainID(),
				Nonce:      5,
				GasTipCap:  big.NewInt(6),
				GasFeeCap:  big.NewInt(9),
				Gas:        7,
				To:         nil,
				Value:      big.NewInt(8),
				Data:       []byte{0, 1, 2, 3, 4},
				AccessList: types.AccessList{},
			},
			Want: `{
				"blockHash": null,
				"blockNumber": null,
				"from": "0xdac2f10f2d3510a7441026e1eb55f12c2df5baa7",
				"gas": "0x7",
				"gasPrice": "0x9",
				"hash": "0x90622b381f7018a98965605193e8e2cb00103245886ddc57f3615f56e9f10ee0",
				"input": "0x0001020304",
				"nonce": "0x5",
				"to": null,
				"transactionIndex": null,
				"value": "0x8",
				"type": "0x52",
				"chainId": "0x539",
				"maxFeePerGas": "0x9",
				"maxPriorityFeePerGas": "0x6",
				"accessList": []
			}`,
		},
	}
}

func allBlobTxs(addr common.Address, config ctypes.ChainConfigurator) []txData {
	return []txData{
		{
			Tx: &types.BlobTx{
				Nonce:      6,
				GasTipCap:  uint256.NewInt(1),
				GasFeeCap:  uint256.NewInt(5),
				Gas:        6,
				To:         addr,
				BlobFeeCap: uint256.NewInt(1),
				BlobHashes: []common.Hash{{1}},
				Value:      new(uint256.Int),
				V:          uint256.NewInt(32),
				R:          uint256.NewInt(10),
				S:          uint256.NewInt(11),
			},
			Want: `{
                "blockHash": null,
                "blockNumber": null,
                "from": "0x71562b71999873db5b286df957af199ec94617f7",
                "gas": "0x6",
                "gasPrice": "0x5",
                "maxFeePerGas": "0x5",
                "maxPriorityFeePerGas": "0x1",
                "maxFeePerBlobGas": "0x1",
                "hash": "0x1f2b59a20e61efc615ad0cbe936379d6bbea6f938aafaf35eb1da05d8e7f46a3",
                "input": "0x",
                "nonce": "0x6",
                "to": "0xdead000000000000000000000000000000000000",
                "transactionIndex": null,
                "value": "0x0",
                "type": "0x3",
                "accessList": [],
                "chainId": "0x1",
                "blobVersionedHashes": [
                    "0x0100000000000000000000000000000000000000000000000000000000000000"
                ],
                "v": "0x0",
                "r": "0x618be8908e0e5320f8f3b48042a079fe5a335ebd4ed1422a7d2207cd45d872bc",
                "s": "0x27b2bc6c80e849a8e8b764d4549d8c2efac3441e73cf37054eb0a9b9f8e89b27",
                "yParity": "0x0"
            }`,
		},
	}
}

// testAccountSeed is the seed of the ML-DSA-44 key of the test backend's
// keystore account.
var testAccountSeed = bytes.Repeat([]byte{0x5e}, keystore.SeedSize)

// fixtureAccountAddr is the address of the secp256k1 keystore account the
// testdata fixtures were generated with, which their genesis funds.
var fixtureAccountAddr = common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7")

func newTestAccountManager(t *testing.T) (*accounts.Manager, accounts.Account) {
	var (
		dir = t.TempDir()
		am  = accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: true})
		b   = keystore.NewKeyStore(dir, 2, 1)
	)
	acc, err := b.ImportSeed(testAccountSeed, "")
	if err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}
	if err := b.Unlock(acc, ""); err != nil {
		t.Fatalf("failed to unlock account: %v\n", err)
	}
	am.AddBackend(b)
	return am, acc
}

type testBackend struct {
	db      ethdb.Database
	chain   *core.BlockChain
	pending *types.Block
	accman  *accounts.Manager
	acc     accounts.Account
}

func newTestBackend(t *testing.T, n int, gspec *genesisT.Genesis, engine consensus.Engine, generator func(i int, b *core.BlockGen)) *testBackend {
	var (
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:    256,
			TrieDirtyLimit:    256,
			TrieTimeLimit:     5 * time.Minute,
			SnapshotLimit:     0,
			TrieDirtyDisabled: true, // Archive mode
		}
	)
	accman, acc := newTestAccountManager(t)
	// A genesis without allocations of its own funds the keystore account,
	// which signs. Any other genesis keeps the allocation the testdata
	// fixtures were generated with, so that their hashes hold.
	if len(gspec.Alloc) == 0 {
		gspec.Alloc[acc.Address] = genesisT.GenesisAccount{Balance: big.NewInt(vars.Ether)}
	} else {
		gspec.Alloc[fixtureAccountAddr] = genesisT.GenesisAccount{Balance: big.NewInt(vars.Ether)}
	}
	// Generate blocks for testing
	db, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, n, generator)
	txlookupLimit := uint64(0)
	chain, err := core.NewBlockChain(db, cacheConfig, gspec, nil, engine, vm.Config{}, nil, &txlookupLimit)
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}

	backend := &testBackend{db: db, chain: chain, accman: accman, acc: acc}
	return backend
}

func (b *testBackend) setPendingBlock(block *types.Block) {
	b.pending = block
}

func (b testBackend) SyncProgress() ethereum.SyncProgress { return ethereum.SyncProgress{} }
func (b testBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return big.NewInt(0), nil
}
func (b testBackend) FeeHistory(ctx context.Context, blockCount uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, error) {
	return nil, nil, nil, nil, nil
}
func (b testBackend) ChainDb() ethdb.Database           { return b.db }
func (b testBackend) AccountManager() *accounts.Manager { return b.accman }
func (b testBackend) ExtRPCEnabled() bool               { return false }
func (b testBackend) RPCGasCap() uint64                 { return 10000000 }
func (b testBackend) RPCEVMTimeout() time.Duration      { return time.Second }
func (b testBackend) RPCTxFeeCap() float64              { return 0 }
func (b testBackend) UnprotectedAllowed() bool          { return false }
func (b testBackend) SetHead(number uint64)             {}
func (b testBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if number == rpc.LatestBlockNumber {
		return b.chain.CurrentBlock(), nil
	}
	if number == rpc.PendingBlockNumber && b.pending != nil {
		return b.pending.Header(), nil
	}
	return b.chain.GetHeaderByNumber(uint64(number)), nil
}
func (b testBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.chain.GetHeaderByHash(hash), nil
}
func (b testBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if blockHash, ok := blockNrOrHash.Hash(); ok {
		return b.HeaderByHash(ctx, blockHash)
	}
	panic("unknown type rpc.BlockNumberOrHash")
}
func (b testBackend) CurrentHeader() *types.Header { return b.chain.CurrentBlock() }
func (b testBackend) CurrentBlock() *types.Header  { return b.chain.CurrentBlock() }
func (b testBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	if number == rpc.LatestBlockNumber {
		head := b.chain.CurrentBlock()
		return b.chain.GetBlock(head.Hash(), head.Number.Uint64()), nil
	}
	if number == rpc.PendingBlockNumber {
		return b.pending, nil
	}
	return b.chain.GetBlockByNumber(uint64(number)), nil
}
func (b testBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.chain.GetBlockByHash(hash), nil
}
func (b testBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if blockHash, ok := blockNrOrHash.Hash(); ok {
		return b.BlockByHash(ctx, blockHash)
	}
	panic("unknown type rpc.BlockNumberOrHash")
}
func (b testBackend) GetBody(ctx context.Context, hash common.Hash, number rpc.BlockNumber) (*types.Body, error) {
	return b.chain.GetBlock(hash, uint64(number.Int64())).Body(), nil
}
func (b testBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	if number == rpc.PendingBlockNumber {
		panic("pending state not implemented")
	}
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := b.chain.StateAt(header.Root)
	return stateDb, header, err
}
func (b testBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	panic("only implemented for number")
}
func (b testBackend) PendingBlockAndReceipts() (*types.Block, types.Receipts) { panic("implement me") }
func (b testBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	header, err := b.HeaderByHash(ctx, hash)
	if header == nil || err != nil {
		return nil, err
	}
	receipts := rawdb.ReadReceipts(b.db, hash, header.Number.Uint64(), header.Time, b.chain.Config())
	return receipts, nil
}
func (b testBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	if b.pending != nil && hash == b.pending.Hash() {
		return nil
	}
	return big.NewInt(1)
}
func (b testBackend) GetEVM(ctx context.Context, msg *core.Message, state *state.StateDB, header *types.Header, vmConfig *vm.Config, blockContext *vm.BlockContext) *vm.EVM {
	if vmConfig == nil {
		vmConfig = b.chain.GetVMConfig()
	}
	txContext := core.NewEVMTxContext(msg)
	context := core.NewEVMBlockContext(header, b.chain, nil)
	if blockContext != nil {
		context = *blockContext
	}
	return vm.NewEVM(context, txContext, state, b.chain.Config(), *vmConfig)
}
func (b testBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	panic("implement me")
}
func (b testBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	panic("implement me")
}
func (b testBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	panic("implement me")
}
func (b testBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	panic("implement me")
}
func (b testBackend) GetTransaction(ctx context.Context, txHash common.Hash) (bool, *types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.db, txHash)
	return true, tx, blockHash, blockNumber, index, nil
}
func (b testBackend) GetPoolTransactions() (types.Transactions, error)         { panic("implement me") }
func (b testBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction { panic("implement me") }
func (b testBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return 0, nil
}
func (b testBackend) Stats() (pending int, queued int) { panic("implement me") }
func (b testBackend) TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	panic("implement me")
}
func (b testBackend) TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	panic("implement me")
}
func (b testBackend) SubscribeNewTxsEvent(events chan<- core.NewTxsEvent) event.Subscription {
	panic("implement me")
}
func (b testBackend) ChainConfig() ctypes.ChainConfigurator { return b.chain.Config() }
func (b testBackend) Engine() consensus.Engine              { return b.chain.Engine() }
func (b testBackend) GetLogs(ctx context.Context, blockHash common.Hash, number uint64) ([][]*types.Log, error) {
	panic("implement me")
}
func (b testBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	panic("implement me")
}
func (b testBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}
func (b testBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	panic("implement me")
}
func (b testBackend) BloomStatus() (uint64, uint64) { panic("implement me") }
func (b testBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	panic("implement me")
}

func TestEstimateGas(t *testing.T) {
	t.Parallel()
	// Initialize test accounts
	var (
		accounts = newAccountsWithSender(2, 0x63)
		genesis  = &genesisT.Genesis{
			Config: params.TestChainConfig,
			Alloc: genesisT.GenesisAlloc{
				accounts[0].addr: {Balance: big.NewInt(vars.Ether)},
				accounts[1].addr: {Balance: big.NewInt(vars.Ether)},
			},
		}
		genBlocks      = 10
		randomAccounts = newAccounts(2)
	)
	api := NewBlockChainAPI(newTestBackend(t, genBlocks, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		// Transfer from account[0] to account[1]
		//    value: 1000 wei
		//    fee:   0 wei
		b.AddTx(signAccountTransfer(t, b, accounts[0].key, uint64(i), accounts[1].addr))
		if genesis.GetEthashTerminalTotalDifficultyPassed() {
			b.SetPoS()
		}
	}))
	var testSuite = []struct {
		blockNumber rpc.BlockNumber
		call        TransactionArgs
		overrides   StateOverride
		expectErr   error
		want        uint64
	}{
		// simple transfer on latest block
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:  &accounts[0].addr,
				To:    &accounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: nil,
			want:      21000,
		},
		// simple transfer with insufficient funds on latest block
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:  &randomAccounts[0].addr,
				To:    &accounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: core.ErrInsufficientFunds,
			want:      21000,
		},
		// empty create
		{
			blockNumber: rpc.LatestBlockNumber,
			call:        TransactionArgs{},
			expectErr:   nil,
			want:        53000,
		},
		{
			blockNumber: rpc.LatestBlockNumber,
			call:        TransactionArgs{},
			overrides: StateOverride{
				randomAccounts[0].addr: OverrideAccount{Balance: newRPCBalance(new(big.Int).Mul(big.NewInt(1), big.NewInt(vars.Ether)))},
			},
			expectErr: nil,
			want:      53000,
		},
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:  &randomAccounts[0].addr,
				To:    &randomAccounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			overrides: StateOverride{
				randomAccounts[0].addr: OverrideAccount{Balance: newRPCBalance(big.NewInt(0))},
			},
			expectErr: core.ErrInsufficientFunds,
		},
		// Test for a bug where the gas price was set to zero but the basefee non-zero
		//
		// contract BasefeeChecker {
		//    constructor() {
		//        require(tx.gasprice >= block.basefee);
		//        if (tx.gasprice > 0) {
		//            require(block.basefee > 0);
		//        }
		//    }
		// }
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:     &accounts[0].addr,
				Input:    hex2Bytes("6080604052348015600f57600080fd5b50483a1015601c57600080fd5b60003a111560315760004811603057600080fd5b5b603f80603e6000396000f3fe6080604052600080fdfea264697066735822122060729c2cee02b10748fae5200f1c9da4661963354973d9154c13a8e9ce9dee1564736f6c63430008130033"),
				GasPrice: (*hexutil.Big)(big.NewInt(1_000_000_000)), // Legacy as pricing
			},
			expectErr: nil,
			want:      67617,
		},
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:         &accounts[0].addr,
				Input:        hex2Bytes("6080604052348015600f57600080fd5b50483a1015601c57600080fd5b60003a111560315760004811603057600080fd5b5b603f80603e6000396000f3fe6080604052600080fdfea264697066735822122060729c2cee02b10748fae5200f1c9da4661963354973d9154c13a8e9ce9dee1564736f6c63430008130033"),
				MaxFeePerGas: (*hexutil.Big)(big.NewInt(1_000_000_000)), // 1559 gas pricing
			},
			expectErr: nil,
			want:      67617,
		},
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:         &accounts[0].addr,
				Input:        hex2Bytes("6080604052348015600f57600080fd5b50483a1015601c57600080fd5b60003a111560315760004811603057600080fd5b5b603f80603e6000396000f3fe6080604052600080fdfea264697066735822122060729c2cee02b10748fae5200f1c9da4661963354973d9154c13a8e9ce9dee1564736f6c63430008130033"),
				GasPrice:     nil, // No legacy gas pricing
				MaxFeePerGas: nil, // No 1559 gas pricing
			},
			expectErr: nil,
			want:      67595,
		},
		// Blobs should have no effect on gas estimate
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:       &accounts[0].addr,
				To:         &accounts[1].addr,
				Value:      (*hexutil.Big)(big.NewInt(1)),
				BlobHashes: []common.Hash{common.Hash{0x01, 0x22}},
				BlobFeeCap: (*hexutil.Big)(big.NewInt(1)),
			},
			want: 21000,
		},
	}
	for i, tc := range testSuite {
		result, err := api.EstimateGas(context.Background(), tc.call, &rpc.BlockNumberOrHash{BlockNumber: &tc.blockNumber}, &tc.overrides)
		if tc.expectErr != nil {
			if err == nil {
				t.Errorf("test %d: want error %v, have nothing", i, tc.expectErr)
				continue
			}
			if !errors.Is(err, tc.expectErr) {
				t.Errorf("test %d: error mismatch, want %v, have %v", i, tc.expectErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}
		if float64(result) > float64(tc.want)*(1+estimateGasErrorRatio) {
			t.Errorf("test %d, result mismatch, have\n%v\n, want\n%v\n", i, uint64(result), tc.want)
		}
	}
}

func TestCall(t *testing.T) {
	t.Parallel()
	// Initialize test accounts
	var (
		accounts = newAccountsWithSender(3, 0x64)
		genesis  = &genesisT.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: genesisT.GenesisAlloc{
				accounts[0].addr: {Balance: big.NewInt(vars.Ether)},
				accounts[1].addr: {Balance: big.NewInt(vars.Ether)},
				accounts[2].addr: {Balance: big.NewInt(vars.Ether)},
			},
		}
		genBlocks = 10
	)
	api := NewBlockChainAPI(newTestBackend(t, genBlocks, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		// Transfer from account[0] to account[1]
		//    value: 1000 wei
		//    fee:   0 wei
		b.AddTx(signAccountTransfer(t, b, accounts[0].key, uint64(i), accounts[1].addr))
		if genesis.GetEthashTerminalTotalDifficultyPassed() {
			b.SetPoS()
		}
	}))
	randomAccounts := newAccounts(3)
	var testSuite = []struct {
		blockNumber    rpc.BlockNumber
		overrides      StateOverride
		call           TransactionArgs
		blockOverrides BlockOverrides
		expectErr      error
		want           string
	}{
		// transfer on genesis
		{
			blockNumber: rpc.BlockNumber(0),
			call: TransactionArgs{
				From:  &accounts[0].addr,
				To:    &accounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: nil,
			want:      "0x",
		},
		// transfer on the head
		{
			blockNumber: rpc.BlockNumber(genBlocks),
			call: TransactionArgs{
				From:  &accounts[0].addr,
				To:    &accounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: nil,
			want:      "0x",
		},
		// transfer on a non-existent block, error expects
		{
			blockNumber: rpc.BlockNumber(genBlocks + 1),
			call: TransactionArgs{
				From:  &accounts[0].addr,
				To:    &accounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: errors.New("header not found"),
		},
		// transfer on the latest block
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:  &accounts[0].addr,
				To:    &accounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: nil,
			want:      "0x",
		},
		// Call which can only succeed if state is state overridden
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:  &randomAccounts[0].addr,
				To:    &randomAccounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			overrides: StateOverride{
				randomAccounts[0].addr: OverrideAccount{Balance: newRPCBalance(new(big.Int).Mul(big.NewInt(1), big.NewInt(vars.Ether)))},
			},
			want: "0x",
		},
		// Invalid call without state overriding
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:  &randomAccounts[0].addr,
				To:    &randomAccounts[1].addr,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			},
			expectErr: core.ErrInsufficientFunds,
		},
		// Successful simple contract call
		//
		// // SPDX-License-Identifier: GPL-3.0
		//
		//  pragma solidity >=0.7.0 <0.8.0;
		//
		//  /**
		//   * @title Storage
		//   * @dev Store & retrieve value in a variable
		//   */
		//  contract Storage {
		//      uint256 public number;
		//      constructor() {
		//          number = block.number;
		//      }
		//  }
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From: &randomAccounts[0].addr,
				To:   &randomAccounts[2].addr,
				Data: hex2Bytes("8381f58a"), // call number()
			},
			overrides: StateOverride{
				randomAccounts[2].addr: OverrideAccount{
					Code:      hex2Bytes("6080604052348015600f57600080fd5b506004361060285760003560e01c80638381f58a14602d575b600080fd5b60336049565b6040518082815260200191505060405180910390f35b6000548156fea2646970667358221220eab35ffa6ab2adfe380772a48b8ba78e82a1b820a18fcb6f59aa4efb20a5f60064736f6c63430007040033"),
					StateDiff: &map[common.Hash]common.Hash{{}: common.BigToHash(big.NewInt(123))},
				},
			},
			want: "0x000000000000000000000000000000000000000000000000000000000000007b",
		},
		// Block overrides should work
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From: &accounts[1].addr,
				Input: &hexutil.Bytes{
					0x43,             // NUMBER
					0x60, 0x00, 0x52, // MSTORE offset 0
					0x60, 0x20, 0x60, 0x00, 0xf3,
				},
			},
			blockOverrides: BlockOverrides{Number: (*hexutil.Big)(big.NewInt(11))},
			want:           "0x000000000000000000000000000000000000000000000000000000000000000b",
		},
		// Invalid blob tx
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:       &accounts[1].addr,
				Input:      &hexutil.Bytes{0x00},
				BlobHashes: []common.Hash{},
			},
			expectErr: core.ErrBlobTxCreate,
		},
		// BLOBHASH opcode
		{
			blockNumber: rpc.LatestBlockNumber,
			call: TransactionArgs{
				From:       &accounts[1].addr,
				To:         &randomAccounts[2].addr,
				BlobHashes: []common.Hash{common.Hash{0x01, 0x22}},
				BlobFeeCap: (*hexutil.Big)(big.NewInt(1)),
			},
			overrides: StateOverride{
				randomAccounts[2].addr: {
					Code: hex2Bytes("60004960005260206000f3"),
				},
			},
			want: "0x0122000000000000000000000000000000000000000000000000000000000000",
		},
	}
	for i, tc := range testSuite {
		result, err := api.Call(context.Background(), tc.call, &rpc.BlockNumberOrHash{BlockNumber: &tc.blockNumber}, &tc.overrides, &tc.blockOverrides)
		if tc.expectErr != nil {
			if err == nil {
				t.Errorf("test %d: want error %v, have nothing", i, tc.expectErr)
				continue
			}
			if !errors.Is(err, tc.expectErr) {
				// Second try
				if !reflect.DeepEqual(err, tc.expectErr) {
					t.Errorf("test %d: error mismatch, want %v, have %v", i, tc.expectErr, err)
				}
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}
		if !reflect.DeepEqual(result.String(), tc.want) {
			t.Errorf("test %d, result mismatch, have\n%v\n, want\n%v\n", i, result.String(), tc.want)
		}
	}
}

func TestFillBlobTransaction(t *testing.T) {
	t.Parallel()
	// Initialize test accounts
	var (
		key, _  = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		to      = crypto.PubkeyToAddress(key.PublicKey)
		genesis = &genesisT.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc:  genesisT.GenesisAlloc{},
		}
		emptyBlob                      = kzg4844.Blob{}
		emptyBlobCommit, _             = kzg4844.BlobToCommitment(emptyBlob)
		emptyBlobProof, _              = kzg4844.ComputeBlobProof(emptyBlob, emptyBlobCommit)
		emptyBlobHash      common.Hash = kzg4844.CalcBlobHashV1(sha256.New(), &emptyBlobCommit)
	)
	b := newTestBackend(t, 1, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		b.SetPoS()
	})
	api := NewTransactionAPI(b, nil)
	type result struct {
		Hashes  []common.Hash
		Sidecar *types.BlobTxSidecar
	}
	suite := []struct {
		name string
		args TransactionArgs
		err  string
		want *result
	}{
		{
			name: "TestInvalidParamsCombination1",
			args: TransactionArgs{
				From:   &b.acc.Address,
				To:     &to,
				Value:  (*hexutil.Big)(big.NewInt(1)),
				Blobs:  []kzg4844.Blob{{}},
				Proofs: []kzg4844.Proof{{}},
			},
			err: `blob proofs provided while commitments were not`,
		},
		{
			name: "TestInvalidParamsCombination2",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				Blobs:       []kzg4844.Blob{{}},
				Commitments: []kzg4844.Commitment{{}},
			},
			err: `blob commitments provided while proofs were not`,
		},
		{
			name: "TestInvalidParamsCount1",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				Blobs:       []kzg4844.Blob{{}},
				Commitments: []kzg4844.Commitment{{}, {}},
				Proofs:      []kzg4844.Proof{{}, {}},
			},
			err: `number of blobs and commitments mismatch (have=2, want=1)`,
		},
		{
			name: "TestInvalidParamsCount2",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				Blobs:       []kzg4844.Blob{{}, {}},
				Commitments: []kzg4844.Commitment{{}, {}},
				Proofs:      []kzg4844.Proof{{}},
			},
			err: `number of blobs and proofs mismatch (have=1, want=2)`,
		},
		{
			name: "TestInvalidProofVerification",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				Blobs:       []kzg4844.Blob{{}, {}},
				Commitments: []kzg4844.Commitment{{}, {}},
				Proofs:      []kzg4844.Proof{{}, {}},
			},
			err: `failed to verify blob proof: short buffer`,
		},
		{
			name: "TestGenerateBlobHashes",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				Blobs:       []kzg4844.Blob{emptyBlob},
				Commitments: []kzg4844.Commitment{emptyBlobCommit},
				Proofs:      []kzg4844.Proof{emptyBlobProof},
			},
			want: &result{
				Hashes: []common.Hash{emptyBlobHash},
				Sidecar: &types.BlobTxSidecar{
					Blobs:       []kzg4844.Blob{emptyBlob},
					Commitments: []kzg4844.Commitment{emptyBlobCommit},
					Proofs:      []kzg4844.Proof{emptyBlobProof},
				},
			},
		},
		{
			name: "TestValidBlobHashes",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				BlobHashes:  []common.Hash{emptyBlobHash},
				Blobs:       []kzg4844.Blob{emptyBlob},
				Commitments: []kzg4844.Commitment{emptyBlobCommit},
				Proofs:      []kzg4844.Proof{emptyBlobProof},
			},
			want: &result{
				Hashes: []common.Hash{emptyBlobHash},
				Sidecar: &types.BlobTxSidecar{
					Blobs:       []kzg4844.Blob{emptyBlob},
					Commitments: []kzg4844.Commitment{emptyBlobCommit},
					Proofs:      []kzg4844.Proof{emptyBlobProof},
				},
			},
		},
		{
			name: "TestInvalidBlobHashes",
			args: TransactionArgs{
				From:        &b.acc.Address,
				To:          &to,
				Value:       (*hexutil.Big)(big.NewInt(1)),
				BlobHashes:  []common.Hash{{0x01, 0x22}},
				Blobs:       []kzg4844.Blob{emptyBlob},
				Commitments: []kzg4844.Commitment{emptyBlobCommit},
				Proofs:      []kzg4844.Proof{emptyBlobProof},
			},
			err: fmt.Sprintf("blob hash verification failed (have=%s, want=%s)", common.Hash{0x01, 0x22}, emptyBlobHash),
		},
		{
			name: "TestGenerateBlobProofs",
			args: TransactionArgs{
				From:  &b.acc.Address,
				To:    &to,
				Value: (*hexutil.Big)(big.NewInt(1)),
				Blobs: []kzg4844.Blob{emptyBlob},
			},
			want: &result{
				Hashes: []common.Hash{emptyBlobHash},
				Sidecar: &types.BlobTxSidecar{
					Blobs:       []kzg4844.Blob{emptyBlob},
					Commitments: []kzg4844.Commitment{emptyBlobCommit},
					Proofs:      []kzg4844.Proof{emptyBlobProof},
				},
			},
		},
	}
	for _, tc := range suite {
		t.Run(tc.name, func(t *testing.T) {
			res, err := api.FillTransaction(context.Background(), tc.args)
			if len(tc.err) > 0 {
				if err == nil {
					t.Fatalf("missing error. want: %s", tc.err)
				} else if err != nil && err.Error() != tc.err {
					t.Fatalf("error mismatch. want: %s, have: %s", tc.err, err.Error())
				}
				return
			}
			if err != nil && len(tc.err) == 0 {
				t.Fatalf("expected no error. have: %s", err)
			}
			if res == nil {
				t.Fatal("result missing")
			}
			want, err := json.Marshal(tc.want)
			if err != nil {
				t.Fatalf("failed to encode expected: %v", err)
			}
			have, err := json.Marshal(result{Hashes: res.Tx.BlobHashes(), Sidecar: res.Tx.BlobTxSidecar()})
			if err != nil {
				t.Fatalf("failed to encode computed sidecar: %v", err)
			}
			if !bytes.Equal(have, want) {
				t.Errorf("blob sidecar mismatch. Have: %s, want: %s", have, want)
			}
		})
	}
}

func argsFromTransaction(tx *types.Transaction, from common.Address) TransactionArgs {
	var (
		gas   = tx.Gas()
		nonce = tx.Nonce()
		input = tx.Data()
	)
	return TransactionArgs{
		From:                 &from,
		To:                   tx.To(),
		Gas:                  (*hexutil.Uint64)(&gas),
		MaxFeePerGas:         (*hexutil.Big)(tx.GasFeeCap()),
		MaxPriorityFeePerGas: (*hexutil.Big)(tx.GasTipCap()),
		Value:                (*hexutil.Big)(tx.Value()),
		Nonce:                (*hexutil.Uint64)(&nonce),
		Input:                (*hexutil.Bytes)(&input),
		ChainID:              (*hexutil.Big)(tx.ChainId()),
		// TODO: impl accessList conversion
		// AccessList: tx.AccessList(),
		BlobFeeCap: (*hexutil.Big)(tx.BlobGasFeeCap()),
		BlobHashes: tx.BlobHashes(),
	}
}

type account struct {
	key  *mldsa44.PrivateKey // nil for an account that sends nothing
	addr common.Address
}

// newAccounts returns n accounts of random addresses, which send nothing.
func newAccounts(n int) (accounts []account) {
	for i := 0; i < n; i++ {
		key, _ := crypto.GenerateKey()
		accounts = append(accounts, account{addr: crypto.PubkeyToAddress(key.PublicKey)})
	}
	slices.SortFunc(accounts, func(a, b account) int { return a.addr.Cmp(b.addr) })
	return accounts
}

// newAccountsWithSender returns n accounts, the first of which is the account
// of the ML-DSA-44 key of seed, which sends the test's transactions.
func newAccountsWithSender(n int, seed byte) []account {
	accounts := newAccounts(n)
	key, _, addr := testAccount(seed)
	accounts[0] = account{key: key, addr: addr}
	return accounts
}

// accountSigGas is the gas an account transaction signed with ML-DSA-44 takes
// on top of the gas of its execution.
var accountSigGas = accountSenderGas - vars.TxGas

// signAccountTx signs txdata with key for the chain b is generated on. A nil
// chain ID is the chain's.
func signAccountTx(t *testing.T, b *core.BlockGen, key *mldsa44.PrivateKey, txdata *types.GhostAccountTx) *types.Transaction {
	t.Helper()
	signer := types.NewGhostAccountSigner(b.Signer(), b.PrevBlock(-1).Hash())
	if txdata.ChainID == nil {
		txdata.ChainID = signer.ChainID()
	}
	tx, err := types.SignGhostAccountTx(signer, key, txdata)
	if err != nil {
		t.Fatalf("sign account transaction %d: %v", txdata.Nonce, err)
	}
	return tx
}

// signAccountTransfer returns an account transaction of key that sends 1000
// wei to to at the base fee of the block b generates.
func signAccountTransfer(t *testing.T, b *core.BlockGen, key *mldsa44.PrivateKey, nonce uint64, to common.Address) *types.Transaction {
	t.Helper()
	return signAccountTx(t, b, key, &types.GhostAccountTx{
		Nonce:     nonce,
		GasFeeCap: b.BaseFee(),
		Gas:       accountSenderGas,
		To:        &to,
		Value:     big.NewInt(1000),
	})
}

func newRPCBalance(balance *big.Int) **hexutil.Big {
	rpcBalance := (*hexutil.Big)(balance)
	return &rpcBalance
}

func hex2Bytes(str string) *hexutil.Bytes {
	rpcBytes := hexutil.Bytes(common.Hex2Bytes(str))
	return &rpcBytes
}

func TestRPCMarshalBlock(t *testing.T) {
	t.Parallel()
	var (
		txs []*types.Transaction
		to  = common.BytesToAddress([]byte{0x11})
	)
	for i := uint64(1); i <= 4; i++ {
		var tx *types.Transaction
		if i%2 == 0 {
			tx = types.NewTx(&types.LegacyTx{
				Nonce:    i,
				GasPrice: big.NewInt(11111),
				Gas:      1111,
				To:       &to,
				Value:    big.NewInt(111),
				Data:     []byte{0x11, 0x11, 0x11},
			})
		} else {
			tx = types.NewTx(&types.AccessListTx{
				ChainID:  big.NewInt(1337),
				Nonce:    i,
				GasPrice: big.NewInt(11111),
				Gas:      1111,
				To:       &to,
				Value:    big.NewInt(111),
				Data:     []byte{0x11, 0x11, 0x11},
			})
		}
		txs = append(txs, tx)
	}
	block := types.NewBlock(&types.Header{Number: big.NewInt(100)}, txs, nil, nil, blocktest.NewHasher())

	var testSuite = []struct {
		inclTx bool
		fullTx bool
		want   string
	}{
		// without txs
		{
			inclTx: false,
			fullTx: false,
			want: `{
				"difficulty": "0x0",
				"totalDifficulty": null,
				"extraData": "0x",
				"gasLimit": "0x0",
				"gasUsed": "0x0",
				"hash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
				"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"miner": "0x0000000000000000000000000000000000000000",
				"mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"nonce": "0x0000000000000000",
				"number": "0x64",
				"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
				"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size": "0x296",
				"stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"timestamp": "0x0",
				"transactionsRoot": "0x661a9febcfa8f1890af549b874faf9fa274aede26ef489d9db0b25daa569450e",
				"uncles": []
			}`,
		},
		// only tx hashes
		{
			inclTx: true,
			fullTx: false,
			want: `{
				"difficulty": "0x0",
				"totalDifficulty": null,
				"extraData": "0x",
				"gasLimit": "0x0",
				"gasUsed": "0x0",
				"hash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
				"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"miner": "0x0000000000000000000000000000000000000000",
				"mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"nonce": "0x0000000000000000",
				"number": "0x64",
				"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
				"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size": "0x296",
				"stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"timestamp": "0x0",
				"transactions": [
					"0x7d39df979e34172322c64983a9ad48302c2b889e55bda35324afecf043a77605",
					"0x9bba4c34e57c875ff57ac8d172805a26ae912006985395dc1bdf8f44140a7bf4",
					"0x98909ea1ff040da6be56bc4231d484de1414b3c1dac372d69293a4beb9032cb5",
					"0x12e1f81207b40c3bdcc13c0ee18f5f86af6d31754d57a0ea1b0d4cfef21abef1"
				],
				"transactionsRoot": "0x661a9febcfa8f1890af549b874faf9fa274aede26ef489d9db0b25daa569450e",
				"uncles": []
			}`,
		},
		// full tx details
		{
			inclTx: true,
			fullTx: true,
			want: `{
				"difficulty": "0x0",
				"totalDifficulty": null,
				"extraData": "0x",
				"gasLimit": "0x0",
				"gasUsed": "0x0",
				"hash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
				"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"miner": "0x0000000000000000000000000000000000000000",
				"mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"nonce": "0x0000000000000000",
				"number": "0x64",
				"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
				"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size": "0x296",
				"stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
				"timestamp": "0x0",
				"transactions": [
					{
						"blockHash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
						"blockNumber": "0x64",
						"from": "0x0000000000000000000000000000000000000000",
						"gas": "0x457",
						"gasPrice": "0x2b67",
						"hash": "0x7d39df979e34172322c64983a9ad48302c2b889e55bda35324afecf043a77605",
						"input": "0x111111",
						"nonce": "0x1",
						"to": "0x0000000000000000000000000000000000000011",
						"transactionIndex": "0x0",
						"value": "0x6f",
						"type": "0x1",
						"accessList": [],
						"chainId": "0x539",
						"v": "0x0",
						"r": "0x0",
						"s": "0x0",
						"yParity": "0x0"
					},
					{
						"blockHash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
						"blockNumber": "0x64",
						"from": "0x0000000000000000000000000000000000000000",
						"gas": "0x457",
						"gasPrice": "0x2b67",
						"hash": "0x9bba4c34e57c875ff57ac8d172805a26ae912006985395dc1bdf8f44140a7bf4",
						"input": "0x111111",
						"nonce": "0x2",
						"to": "0x0000000000000000000000000000000000000011",
						"transactionIndex": "0x1",
						"value": "0x6f",
						"type": "0x0",
						"chainId": "0x7fffffffffffffee",
						"v": "0x0",
						"r": "0x0",
						"s": "0x0"
					},
					{
						"blockHash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
						"blockNumber": "0x64",
						"from": "0x0000000000000000000000000000000000000000",
						"gas": "0x457",
						"gasPrice": "0x2b67",
						"hash": "0x98909ea1ff040da6be56bc4231d484de1414b3c1dac372d69293a4beb9032cb5",
						"input": "0x111111",
						"nonce": "0x3",
						"to": "0x0000000000000000000000000000000000000011",
						"transactionIndex": "0x2",
						"value": "0x6f",
						"type": "0x1",
						"accessList": [],
						"chainId": "0x539",
						"v": "0x0",
						"r": "0x0",
						"s": "0x0",
						"yParity": "0x0"
					},
					{
						"blockHash": "0x9b73c83b25d0faf7eab854e3684c7e394336d6e135625aafa5c183f27baa8fee",
						"blockNumber": "0x64",
						"from": "0x0000000000000000000000000000000000000000",
						"gas": "0x457",
						"gasPrice": "0x2b67",
						"hash": "0x12e1f81207b40c3bdcc13c0ee18f5f86af6d31754d57a0ea1b0d4cfef21abef1",
						"input": "0x111111",
						"nonce": "0x4",
						"to": "0x0000000000000000000000000000000000000011",
						"transactionIndex": "0x3",
						"value": "0x6f",
						"type": "0x0",
						"chainId": "0x7fffffffffffffee",
						"v": "0x0",
						"r": "0x0",
						"s": "0x0"
					}
				],
				"transactionsRoot": "0x661a9febcfa8f1890af549b874faf9fa274aede26ef489d9db0b25daa569450e",
				"uncles": []
			}`,
		},
	}

	for i, tc := range testSuite {
		resp := RPCMarshalBlock(block, tc.inclTx, tc.fullTx, params.MainnetChainConfig)
		out, err := json.Marshal(resp)
		if err != nil {
			t.Errorf("test %d: json marshal error: %v", i, err)
			continue
		}
		require.JSONEqf(t, tc.want, string(out), "test %d", i)
	}
}

func TestRPCGetBlockOrHeader(t *testing.T) {
	// The ML-DSA-44 signatures are hedged: a fixed random stream makes the
	// recorded outputs reproducible.
	cryptotest.SetGlobalRandom(t, 1)

	// Initialize test accounts
	var (
		acc1Key, _, acc1Addr = testAccount(0x67)
		_, _, acc2Addr       = testAccount(0x68)
		genesis              = &genesisT.Genesis{
			Config: params.TestChainConfig,
			Alloc: genesisT.GenesisAlloc{
				acc1Addr: {Balance: big.NewInt(vars.Ether)},
				acc2Addr: {Balance: big.NewInt(vars.Ether)},
			},
		}
		genBlocks  = 10
		withdrawal = &types.Withdrawal{
			Index:     0,
			Validator: 1,
			Address:   common.Address{0x12, 0x34},
			Amount:    10,
		}
	)
	backend := newTestBackend(t, genBlocks, genesis, ethash.NewFaker(), func(i int, b *core.BlockGen) {
		// Transfer from account[0] to account[1]
		//    value: 1000 wei
		//    fee:   0 wei
		b.AddTx(signAccountTransfer(t, b, acc1Key, uint64(i), acc2Addr))
	})
	signer := types.NewGhostAccountSigner(types.LatestSigner(genesis.Config), backend.chain.Genesis().Hash())
	tx, err := types.SignGhostAccountTx(signer, acc1Key, &types.GhostAccountTx{
		ChainID:   genesis.Config.GetChainID(),
		Nonce:     11,
		GasTipCap: big.NewInt(11111),
		GasFeeCap: big.NewInt(11111),
		Gas:       1111,
		To:        &acc2Addr,
		Value:     big.NewInt(111),
		Data:      []byte{0x11, 0x11, 0x11},
	})
	if err != nil {
		t.Fatalf("sign pending transaction: %v", err)
	}
	pending := types.NewBlockWithWithdrawals(&types.Header{Number: big.NewInt(11), Time: 42}, []*types.Transaction{tx}, nil, nil, []*types.Withdrawal{withdrawal}, blocktest.NewHasher())
	backend.setPendingBlock(pending)
	api := NewBlockChainAPI(backend)
	blockHashes := make([]common.Hash, genBlocks+1)
	ctx := context.Background()
	for i := 0; i <= genBlocks; i++ {
		header, err := backend.HeaderByNumber(ctx, rpc.BlockNumber(i))
		if err != nil {
			t.Errorf("failed to get block: %d err: %v", i, err)
		}
		blockHashes[i] = header.Hash()
	}
	pendingHash := pending.Hash()

	var testSuite = []struct {
		blockNumber rpc.BlockNumber
		blockHash   *common.Hash
		fullTx      bool
		reqHeader   bool
		file        string
		expectErr   error
	}{
		// 0. latest header
		{
			blockNumber: rpc.LatestBlockNumber,
			reqHeader:   true,
			file:        "tag-latest",
		},
		// 1. genesis header
		{
			blockNumber: rpc.BlockNumber(0),
			reqHeader:   true,
			file:        "number-0",
		},
		// 2. #1 header
		{
			blockNumber: rpc.BlockNumber(1),
			reqHeader:   true,
			file:        "number-1",
		},
		// 3. latest-1 header
		{
			blockNumber: rpc.BlockNumber(9),
			reqHeader:   true,
			file:        "number-latest-1",
		},
		// 4. latest+1 header
		{
			blockNumber: rpc.BlockNumber(11),
			reqHeader:   true,
			file:        "number-latest+1",
		},
		// 5. pending header
		{
			blockNumber: rpc.PendingBlockNumber,
			reqHeader:   true,
			file:        "tag-pending",
		},
		// 6. latest block
		{
			blockNumber: rpc.LatestBlockNumber,
			file:        "tag-latest",
		},
		// 7. genesis block
		{
			blockNumber: rpc.BlockNumber(0),
			file:        "number-0",
		},
		// 8. #1 block
		{
			blockNumber: rpc.BlockNumber(1),
			file:        "number-1",
		},
		// 9. latest-1 block
		{
			blockNumber: rpc.BlockNumber(9),
			fullTx:      true,
			file:        "number-latest-1",
		},
		// 10. latest+1 block
		{
			blockNumber: rpc.BlockNumber(11),
			fullTx:      true,
			file:        "number-latest+1",
		},
		// 11. pending block
		{
			blockNumber: rpc.PendingBlockNumber,
			file:        "tag-pending",
		},
		// 12. pending block + fullTx
		{
			blockNumber: rpc.PendingBlockNumber,
			fullTx:      true,
			file:        "tag-pending-fullTx",
		},
		// 13. latest header by hash
		{
			blockHash: &blockHashes[len(blockHashes)-1],
			reqHeader: true,
			file:      "hash-latest",
		},
		// 14. genesis header by hash
		{
			blockHash: &blockHashes[0],
			reqHeader: true,
			file:      "hash-0",
		},
		// 15. #1 header
		{
			blockHash: &blockHashes[1],
			reqHeader: true,
			file:      "hash-1",
		},
		// 16. latest-1 header
		{
			blockHash: &blockHashes[len(blockHashes)-2],
			reqHeader: true,
			file:      "hash-latest-1",
		},
		// 17. empty hash
		{
			blockHash: &common.Hash{},
			reqHeader: true,
			file:      "hash-empty",
		},
		// 18. pending hash
		{
			blockHash: &pendingHash,
			reqHeader: true,
			file:      `hash-pending`,
		},
		// 19. latest block
		{
			blockHash: &blockHashes[len(blockHashes)-1],
			file:      "hash-latest",
		},
		// 20. genesis block
		{
			blockHash: &blockHashes[0],
			file:      "hash-genesis",
		},
		// 21. #1 block
		{
			blockHash: &blockHashes[1],
			file:      "hash-1",
		},
		// 22. latest-1 block
		{
			blockHash: &blockHashes[len(blockHashes)-2],
			fullTx:    true,
			file:      "hash-latest-1-fullTx",
		},
		// 23. empty hash + body
		{
			blockHash: &common.Hash{},
			fullTx:    true,
			file:      "hash-empty-fullTx",
		},
		// 24. pending block
		{
			blockHash: &pendingHash,
			file:      `hash-pending`,
		},
		// 25. pending block + fullTx
		{
			blockHash: &pendingHash,
			fullTx:    true,
			file:      "hash-pending-fullTx",
		},
	}

	for i, tt := range testSuite {
		var (
			result interface{}
			err    error
			rpc    string
		)
		if tt.blockHash != nil {
			if tt.reqHeader {
				result = api.GetHeaderByHash(context.Background(), *tt.blockHash)
				rpc = "eth_getHeaderByHash"
			} else {
				result, err = api.GetBlockByHash(context.Background(), *tt.blockHash, tt.fullTx)
				rpc = "eth_getBlockByHash"
			}
		} else {
			if tt.reqHeader {
				result, err = api.GetHeaderByNumber(context.Background(), tt.blockNumber)
				rpc = "eth_getHeaderByNumber"
			} else {
				result, err = api.GetBlockByNumber(context.Background(), tt.blockNumber, tt.fullTx)
				rpc = "eth_getBlockByNumber"
			}
		}
		if tt.expectErr != nil {
			if err == nil {
				t.Errorf("test %d: want error %v, have nothing", i, tt.expectErr)
				continue
			}
			if !errors.Is(err, tt.expectErr) {
				t.Errorf("test %d: error mismatch, want %v, have %v", i, tt.expectErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}

		testRPCResponseWithFile(t, i, result, rpc, tt.file)
	}
}

func setupReceiptBackend(t *testing.T, genBlocks int) (*testBackend, []common.Hash) {
	// The ML-DSA-44 signatures are hedged: a fixed random stream makes the
	// recorded outputs reproducible.
	cryptotest.SetGlobalRandom(t, 1)
	config := *params.MergedTestChainConfig
	var (
		// The account sends every transaction but the blob one, which the
		// secp256k1 key of blobAddr sends.
		accKey, _, accAddr = testAccount(0x69)
		blobKey, _         = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		acc2Key, _         = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
		blobAddr           = crypto.PubkeyToAddress(blobKey.PublicKey)
		acc2Addr           = crypto.PubkeyToAddress(acc2Key.PublicKey)
		contract           = common.HexToAddress("0000000000000000000000000000000000031ec7")
		genesis            = &genesisT.Genesis{
			Config:        &config,
			ExcessBlobGas: new(uint64),
			BlobGasUsed:   new(uint64),
			Alloc: genesisT.GenesisAlloc{
				accAddr:  {Balance: big.NewInt(vars.Ether)},
				blobAddr: {Balance: big.NewInt(vars.Ether)},
				acc2Addr: {Balance: big.NewInt(vars.Ether)},
				// // SPDX-License-Identifier: GPL-3.0
				// pragma solidity >=0.7.0 <0.9.0;
				//
				// contract Token {
				//     event Transfer(address indexed from, address indexed to, uint256 value);
				//     function transfer(address to, uint256 value) public returns (bool) {
				//         emit Transfer(msg.sender, to, value);
				//         return true;
				//     }
				// }
				contract: {Balance: big.NewInt(vars.Ether), Code: common.FromHex("0x608060405234801561001057600080fd5b506004361061002b5760003560e01c8063a9059cbb14610030575b600080fd5b61004a6004803603810190610045919061016a565b610060565b60405161005791906101c5565b60405180910390f35b60008273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516100bf91906101ef565b60405180910390a36001905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610101826100d6565b9050919050565b610111816100f6565b811461011c57600080fd5b50565b60008135905061012e81610108565b92915050565b6000819050919050565b61014781610134565b811461015257600080fd5b50565b6000813590506101648161013e565b92915050565b60008060408385031215610181576101806100d1565b5b600061018f8582860161011f565b92505060206101a085828601610155565b9150509250929050565b60008115159050919050565b6101bf816101aa565b82525050565b60006020820190506101da60008301846101b6565b92915050565b6101e981610134565b82525050565b600060208201905061020460008301846101e0565b9291505056fea2646970667358221220b469033f4b77b9565ee84e0a2f04d496b18160d26034d54f9487e57788fd36d564736f6c63430008120033")},
			},
		}
		signer   = types.LatestSignerForChainID(params.TestChainConfig.GetChainID())
		txHashes = make([]common.Hash, genBlocks)
	)

	// Set the terminal total difficulty in the config
	genesis.Config.(*goethereum.ChainConfig).TerminalTotalDifficulty = big.NewInt(0)
	genesis.Config.(*goethereum.ChainConfig).TerminalTotalDifficultyPassed = true
	backend := newTestBackend(t, genBlocks, genesis, beacon.New(ethash.NewFaker()), func(i int, b *core.BlockGen) {
		var (
			tx  *types.Transaction
			err error
		)
		b.SetPoS()
		switch i {
		case 0:
			// transfer 1000wei
			tx = signAccountTransfer(t, b, accKey, uint64(i), acc2Addr)
		case 1:
			// create contract
			tx = signAccountTx(t, b, accKey, &types.GhostAccountTx{Nonce: uint64(i), To: nil, Gas: 53100 + accountSigGas, GasFeeCap: b.BaseFee(), Data: common.FromHex("0x60806040")})
		case 2:
			// with logs
			// transfer(address to, uint256 value)
			data := fmt.Sprintf("0xa9059cbb%s%s", common.HexToHash(common.BigToAddress(big.NewInt(int64(i + 1))).Hex()).String()[2:], common.BytesToHash([]byte{byte(i + 11)}).String()[2:])
			tx = signAccountTx(t, b, accKey, &types.GhostAccountTx{Nonce: uint64(i), To: &contract, Gas: 60000 + accountSigGas, GasFeeCap: b.BaseFee(), Data: common.FromHex(data)})
		case 3:
			// with a tip, with logs
			// transfer(address to, uint256 value)
			data := fmt.Sprintf("0xa9059cbb%s%s", common.HexToHash(common.BigToAddress(big.NewInt(int64(i + 1))).Hex()).String()[2:], common.BytesToHash([]byte{byte(i + 11)}).String()[2:])
			fee := big.NewInt(500)
			fee.Add(fee, b.BaseFee())
			tx = signAccountTx(t, b, accKey, &types.GhostAccountTx{Nonce: uint64(i), To: &contract, Gas: 60000 + accountSigGas, Value: big.NewInt(1), GasTipCap: big.NewInt(500), GasFeeCap: fee, Data: common.FromHex(data)})
		case 4:
			// access list with contract create
			accessList := types.AccessList{{
				Address:     contract,
				StorageKeys: []common.Hash{{0}},
			}}
			tx = signAccountTx(t, b, accKey, &types.GhostAccountTx{Nonce: uint64(i), To: nil, Gas: 58100 + accountSigGas, GasFeeCap: b.BaseFee(), Data: common.FromHex("0x60806040"), AccessList: accessList})
		case 5:
			// blob tx, the first transaction of its sender
			fee := big.NewInt(500)
			fee.Add(fee, b.BaseFee())
			tx, err = types.SignTx(types.NewTx(&types.BlobTx{
				Nonce:      0,
				GasTipCap:  uint256.NewInt(1),
				GasFeeCap:  uint256.MustFromBig(fee),
				Gas:        vars.TxGas,
				To:         acc2Addr,
				BlobFeeCap: uint256.NewInt(1),
				BlobHashes: []common.Hash{{1}},
				Value:      new(uint256.Int),
			}), signer, blobKey)
		}
		if err != nil {
			t.Errorf("failed to sign tx: %v", err)
		}
		if tx != nil {
			b.AddTx(tx)
			txHashes[i] = tx.Hash()
		}
	})
	return backend, txHashes
}

func TestRPCGetTransactionReceipt(t *testing.T) {
	var (
		backend, txHashes = setupReceiptBackend(t, 6)
		api               = NewTransactionAPI(backend, new(AddrLocker))
	)

	var testSuite = []struct {
		txHash common.Hash
		file   string
	}{
		// 0. normal success
		{
			txHash: txHashes[0],
			file:   "normal-transfer-tx",
		},
		// 1. create contract
		{
			txHash: txHashes[1],
			file:   "create-contract-tx",
		},
		// 2. with logs success
		{
			txHash: txHashes[2],
			file:   "with-logs",
		},
		// 3. account tx with a tip, with logs success
		{
			txHash: txHashes[3],
			file:   `account-tip-tx-with-logs`,
		},
		// 4. access list tx with create contract
		{
			txHash: txHashes[4],
			file:   "create-contract-with-access-list",
		},
		// 5. txhash empty
		{
			txHash: common.Hash{},
			file:   "txhash-empty",
		},
		// 6. txhash not found
		{
			txHash: common.HexToHash("deadbeef"),
			file:   "txhash-notfound",
		},
		// 7. blob tx
		{
			txHash: txHashes[5],
			file:   "blob-tx",
		},
	}

	for i, tt := range testSuite {
		var (
			result interface{}
			err    error
		)
		result, err = api.GetTransactionReceipt(context.Background(), tt.txHash)
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}
		testRPCResponseWithFile(t, i, result, "eth_getTransactionReceipt", tt.file)
	}
}

func TestRPCGetBlockReceipts(t *testing.T) {
	var (
		genBlocks  = 6
		backend, _ = setupReceiptBackend(t, genBlocks)
		api        = NewBlockChainAPI(backend)
	)
	blockHashes := make([]common.Hash, genBlocks+1)
	ctx := context.Background()
	for i := 0; i <= genBlocks; i++ {
		header, err := backend.HeaderByNumber(ctx, rpc.BlockNumber(i))
		if err != nil {
			t.Errorf("failed to get block: %d err: %v", i, err)
		}
		blockHashes[i] = header.Hash()
	}

	var testSuite = []struct {
		test rpc.BlockNumberOrHash
		file string
	}{
		// 0. block without any txs(hash)
		{
			test: rpc.BlockNumberOrHashWithHash(blockHashes[0], false),
			file: "number-0",
		},
		// 1. block without any txs(number)
		{
			test: rpc.BlockNumberOrHashWithNumber(0),
			file: "number-1",
		},
		// 2. earliest tag
		{
			test: rpc.BlockNumberOrHashWithNumber(rpc.EarliestBlockNumber),
			file: "tag-earliest",
		},
		// 3. latest tag
		{
			test: rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
			file: "tag-latest",
		},
		// 4. block with account transfer tx(hash)
		{
			test: rpc.BlockNumberOrHashWithHash(blockHashes[1], false),
			file: "block-with-account-transfer-tx",
		},
		// 5. block with contract create tx(number)
		{
			test: rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(2)),
			file: "block-with-contract-create-tx",
		},
		// 6. block with account contract call tx(hash)
		{
			test: rpc.BlockNumberOrHashWithHash(blockHashes[3], false),
			file: "block-with-account-contract-call-tx",
		},
		// 7. block with account tx with a tip(number)
		{
			test: rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(4)),
			file: "block-with-account-tip-tx",
		},
		// 8. block is empty
		{
			test: rpc.BlockNumberOrHashWithHash(common.Hash{}, false),
			file: "hash-empty",
		},
		// 9. block is not found
		{
			test: rpc.BlockNumberOrHashWithHash(common.HexToHash("deadbeef"), false),
			file: "hash-notfound",
		},
		// 10. block is not found
		{
			test: rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(genBlocks + 1)),
			file: "block-notfound",
		},
		// 11. block with blob tx
		{
			test: rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(6)),
			file: "block-with-blob-tx",
		},
	}

	for i, tt := range testSuite {
		var (
			result interface{}
			err    error
		)
		result, err = api.GetBlockReceipts(context.Background(), tt.test)
		if err != nil {
			t.Errorf("test %d: want no error, have %v", i, err)
			continue
		}
		testRPCResponseWithFile(t, i, result, "eth_getBlockReceipts", tt.file)
	}
}

func testRPCResponseWithFile(t *testing.T, testid int, result interface{}, rpc string, file string) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Errorf("test %d: json marshal error", testid)
		return
	}
	outputFile := filepath.Join("testdata", fmt.Sprintf("%s-%s.json", rpc, file))
	if os.Getenv("WRITE_TEST_FILES") != "" {
		os.WriteFile(outputFile, data, 0644)
	}
	want, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("error reading expected test file: %s output: %v", outputFile, err)
	}
	require.JSONEqf(t, string(want), string(data), "test %d: json not match, want: %s, have: %s", testid, string(want), string(data))
}

// revealBackend is the test backend with its transactions sent to a reveal
// pool on its chain.
type revealBackend struct {
	*testBackend
	pool *ghostpool.Pool
	sent []*types.Transaction
}

func (b *revealBackend) SendTx(ctx context.Context, tx *types.Transaction) error {
	b.sent = append(b.sent, tx)
	return b.pool.Add([]*types.Transaction{tx}, true, false)[0]
}

func TestSendRawRevealTransaction(t *testing.T) {
	t.Cleanup(ghostpriv.SetVerifier(ghostprivtest.Verifier{}))

	var (
		key, _, addr = testAccount(0x6a)
		oneGhost     = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
		gspec        = ghost.InternalNetGenesis()
		chainID      = gspec.Config.GetChainID()
	)
	gspec.Alloc = genesisT.GenesisAlloc{addr: {Balance: new(big.Int).Mul(oneGhost, big.NewInt(100))}}
	data, err := ghostpriv.CommitData(ghosttree.K("ghost/test-coin-f", []byte("rpc")), make([]byte, ghostpriv.NoteSize))
	if err != nil {
		t.Fatal(err)
	}
	to := ghost.CommitEntryAddress
	tb := newTestBackend(t, 1, gspec, ethash.NewFaker(), func(i int, b *core.BlockGen) {
		b.AddTx(signAccountTx(t, b, key, &types.GhostAccountTx{
			ChainID:   chainID,
			Nonce:     0,
			GasTipCap: big.NewInt(vars.InitialBaseFee),
			GasFeeCap: big.NewInt(100 * vars.InitialBaseFee),
			Gas:       60_000 + accountSigGas,
			To:        &to,
			Value:     oneGhost,
			Data:      data,
		}))
	})
	defer tb.chain.Stop()
	pool := ghostpool.New(tb.chain)
	if err := pool.Init(0, tb.chain.CurrentBlock(), nil); err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	backend := &revealBackend{testBackend: tb, pool: pool}
	api := NewTransactionAPI(backend, new(AddrLocker))

	// A reveal for block 2, in the genesis's fee window.
	genesis := tb.chain.Genesis()
	fee, err := ghostpriv.WindowFee(genesis.BaseFee())
	if err != nil {
		t.Fatal(err)
	}
	r := &ghostpriv.Reveal{
		Version:   ghostpriv.Version,
		ChainID:   chainID.Uint64(),
		Marker:    ghosttree.K("ghost/test-marker", []byte("synthetic rpc marker")),
		Root:      *genesis.Header().CoinTreeRoot,
		Remainder: ghosttree.K("ghost/test-remainder", []byte("synthetic rpc remainder")),
		Recipient: common.Address{0x52},
		Out:       uint256.NewInt(1000),
		Fee:       fee.Total,
	}
	r.Proof = ghostprivtest.Proof(r.BindingDigest(chainID.Uint64(), genesis.Hash()))
	envelope, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	hash, err := api.SendRawTransaction(context.Background(), envelope)
	if err != nil {
		t.Fatalf("raw reveal refused: %v", err)
	}
	if want := crypto.Keccak256Hash(envelope); hash != want {
		t.Fatalf("hash %x, want keccak256 of the envelope %x", hash, want)
	}
	if len(backend.sent) != 1 || !bytes.Equal(backend.sent[0].GhostRevealEnvelope(), envelope) {
		t.Fatal("the backend did not get the reveal with its exact envelope")
	}
	if !pool.Has(hash) {
		t.Fatal("the reveal pool does not hold the reveal")
	}
	// The same reveal again is already known.
	if _, err := api.SendRawTransaction(context.Background(), envelope); !errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Fatalf("second send: error %v, want %v", err, txpool.ErrAlreadyKnown)
	}
	// A competing reveal of the same marker is refused.
	r2 := *r
	r2.Recipient = common.Address{0x53}
	r2.Proof = ghostprivtest.Proof(r2.BindingDigest(chainID.Uint64(), genesis.Hash()))
	competing, err := r2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SendRawTransaction(context.Background(), competing); !errors.Is(err, ghostpool.ErrMarkerPending) {
		t.Fatalf("competing reveal: error %v, want %v", err, ghostpool.ErrMarkerPending)
	}
	// An envelope of the wrong length never reaches the backend.
	sent := len(backend.sent)
	if _, err := api.SendRawTransaction(context.Background(), envelope[:len(envelope)-1]); !errors.Is(err, types.ErrGhostRevealLength) {
		t.Fatalf("short envelope: error %v, want %v", err, types.ErrGhostRevealLength)
	}
	if len(backend.sent) != sent {
		t.Fatal("a short envelope reached the backend")
	}

	// The RPC form carries the payload as its input and decodes back to the
	// same reveal.
	rpcTx := NewRPCPendingTransaction(backend.sent[0], tb.chain.CurrentBlock(), tb.chain.Config())
	if rpcTx.Type != types.GhostRevealTxType || rpcTx.Hash != hash || !bytes.Equal(rpcTx.Input, envelope[1:]) || rpcTx.From != (common.Address{}) {
		t.Fatal("the RPC form of the reveal is not its payload under its hash")
	}
	enc, err := json.Marshal(rpcTx)
	if err != nil {
		t.Fatal(err)
	}
	var dec types.Transaction
	if err := json.Unmarshal(enc, &dec); err != nil {
		t.Fatalf("decoding the RPC form: %v", err)
	}
	if dec.Hash() != hash {
		t.Fatalf("decoded reveal hash %x, want %x", dec.Hash(), hash)
	}
}
