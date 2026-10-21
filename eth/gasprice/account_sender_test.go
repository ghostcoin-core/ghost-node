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

package gasprice

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rpc"
)

// accountSenderGas is the gas of an account transfer signed with ML-DSA-44.
var accountSenderGas = vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// accountSenderBackend serves a chain whose head is its latest block. With a
// genesis header set, it serves that header as block 0 in place of the
// chain's.
type accountSenderBackend struct {
	chain   *core.BlockChain
	genesis *types.Header
}

func (b *accountSenderBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	switch {
	case number == rpc.LatestBlockNumber:
		return b.chain.CurrentHeader(), nil
	case number == 0 && b.genesis != nil:
		return b.genesis, nil
	case number < 0:
		return nil, nil
	}
	return b.chain.GetHeaderByNumber(uint64(number)), nil
}

func (b *accountSenderBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	switch {
	case number == rpc.LatestBlockNumber:
		return b.chain.GetBlockByNumber(b.chain.CurrentHeader().Number.Uint64()), nil
	case number < 0:
		return nil, nil
	}
	return b.chain.GetBlockByNumber(uint64(number)), nil
}

func (b *accountSenderBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return b.chain.GetReceiptsByHash(hash), nil
}

func (b *accountSenderBackend) PendingBlockAndReceipts() (*types.Block, types.Receipts) {
	return nil, nil
}

func (b *accountSenderBackend) ChainConfig() ctypes.ChainConfigurator {
	return b.chain.Config()
}

func (b *accountSenderBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return nil
}

// TestAccountSenderGasPrice checks that the oracle derives the senders of
// account transactions and skips the coinbase's own, and that a sender that
// cannot be derived is an error.
func TestAccountSenderGasPrice(t *testing.T) {
	coinbaseKey, coinbasePub, coinbase := testAccount(0x51)
	userKey, userPub, user := testAccount(0x52)
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, coinbasePub); coinbase != want {
		t.Fatalf("coinbase account address %x, want %x", coinbase, want)
	}
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, userPub); user != want {
		t.Fatalf("user account address %x, want %x", user, want)
	}
	var (
		coinbaseTip = big.NewInt(50 * vars.GWei)
		userTip     = big.NewInt(2 * vars.GWei)
		recipient   = common.HexToAddress("0x5252525252525252525252525252525252525252")
	)
	gspec := &genesisT.Genesis{
		Config: params.TestChainConfig,
		Alloc: genesisT.GenesisAlloc{
			coinbase: {Balance: big.NewInt(vars.Ether)},
			user:     {Balance: big.NewInt(vars.Ether)},
		},
		BaseFee: big.NewInt(vars.InitialBaseFee),
	}
	signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), core.GenesisToBlock(gspec, nil).Hash())
	engine := ethash.NewFaker()
	senders := []struct {
		key  *mldsa44.PrivateKey
		addr common.Address
		tip  *big.Int
	}{{coinbaseKey, coinbase, coinbaseTip}, {userKey, user, userTip}}
	genDb, blocks, receipts := core.GenerateChainWithGenesis(gspec, engine, 4, func(i int, b *core.BlockGen) {
		b.SetCoinbase(coinbase)
		for n := range senders {
			sender := senders[n]
			txdata := &types.GhostAccountTx{
				ChainID:   gspec.Config.GetChainID(),
				Nonce:     b.TxNonce(sender.addr),
				GasTipCap: sender.tip,
				GasFeeCap: big.NewInt(200 * vars.GWei),
				Gas:       accountSenderGas,
				To:        &recipient,
				Value:     big.NewInt(1000),
			}
			tx, err := types.SignGhostAccountTx(signer, sender.key, txdata)
			if err != nil {
				t.Fatalf("sign account transaction of %x: %v", sender.addr, err)
			}
			b.AddTx(tx)
		}
	})
	defer genDb.Close()
	if len(receipts) != 4 {
		t.Fatalf("generated %d blocks of receipts, want 4", len(receipts))
	}
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), &core.CacheConfig{TrieCleanNoPrefetch: true}, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("insert block %d: %v", n, err)
	}
	config := Config{Blocks: 2, Percentile: 60, Default: big.NewInt(vars.GWei)}

	// Each block samples the user's transaction only: the coinbase's own
	// is skipped.
	oracle := NewOracle(&accountSenderBackend{chain: chain}, config)
	result := make(chan results, 1)
	oracle.getBlockValues(context.Background(), 1, sampleNumber, oracle.ignorePrice, result, make(chan struct{}))
	res := <-result
	if res.err != nil {
		t.Fatalf("block 1 values: %v", res.err)
	}
	if len(res.values) != 1 || res.values[0].Cmp(userTip) != 0 {
		t.Fatalf("block 1 values %v, want only the user's tip %v", res.values, userTip)
	}
	got, err := oracle.SuggestTipCap(context.Background())
	if err != nil {
		t.Fatalf("suggest tip cap: %v", err)
	}
	if got.Cmp(userTip) != 0 {
		t.Fatalf("tip cap %v, want the user's tip %v", got, userTip)
	}

	// Bound to another genesis hash, the signatures do not verify.
	other := &types.Header{Number: new(big.Int), Extra: []byte("another chain")}
	oracle = NewOracle(&accountSenderBackend{chain: chain, genesis: other}, config)
	if tip, err := oracle.SuggestTipCap(context.Background()); !errors.Is(err, types.ErrInvalidSig) {
		t.Fatalf("underivable sender: tip cap %v, error %v, want %v", tip, err, types.ErrInvalidSig)
	}
}
