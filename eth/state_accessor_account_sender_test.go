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

package eth

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// stateAccessorAccountGas is the gas of an account transfer signed with
// ML-DSA-44.
var stateAccessorAccountGas = vars.TxGas + ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// TestAccountSenderStateAtTransaction checks that the execution environment
// of a transaction replays the account transactions before it from their
// account, returns the message of an account transaction from its account,
// and refuses a block whose account transaction has an underivable sender.
func TestAccountSenderStateAtTransaction(t *testing.T) {
	key, pub, addr := testAccount(0x31)
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub); addr != want {
		t.Fatalf("account address %x, want %x", addr, want)
	}
	recipient := common.HexToAddress("0x5252525252525252525252525252525252525252")
	gspec := &genesisT.Genesis{
		Config:  params.TestChainConfig,
		Alloc:   genesisT.GenesisAlloc{addr: {Balance: big.NewInt(vars.Ether)}},
		BaseFee: big.NewInt(vars.InitialBaseFee),
	}
	genesisHash := core.GenesisToBlock(gspec, nil).Hash()
	signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), genesisHash)
	sign := func(nonce uint64, feeCap *big.Int, s types.Signer) *types.Transaction {
		tx, err := types.SignGhostAccountTx(s, key, &types.GhostAccountTx{
			ChainID:   gspec.Config.GetChainID(),
			Nonce:     nonce,
			GasTipCap: new(big.Int),
			GasFeeCap: feeCap,
			Gas:       stateAccessorAccountGas,
			To:        &recipient,
			Value:     big.NewInt(1000),
		})
		if err != nil {
			t.Fatalf("sign account transaction %d: %v", nonce, err)
		}
		return tx
	}
	engine := ethash.NewFaker()
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *core.BlockGen) {
		b.AddTx(sign(0, b.BaseFee(), signer))
		b.AddTx(sign(1, b.BaseFee(), signer))
	})
	db := rawdb.NewMemoryDatabase()
	cacheConfig := &core.CacheConfig{
		TrieCleanLimit:    256,
		TrieDirtyLimit:    256,
		TrieTimeLimit:     5 * time.Minute,
		TrieDirtyDisabled: true, // Archive mode
	}
	chain, err := core.NewBlockChain(db, cacheConfig, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("insert block %d: %v", n, err)
	}
	eth := &Ethereum{blockchain: chain, chainDb: db}
	block := chain.GetBlockByNumber(1)
	if block == nil || len(block.Transactions()) != 2 {
		t.Fatalf("block 1 not imported with its two account transactions")
	}

	// The second transaction runs after the first one is replayed from the
	// account: from the zero address the replay fails.
	for i := 0; i < 2; i++ {
		msg, _, statedb, release, err := eth.stateAtTransaction(context.Background(), block, i, 0)
		if err != nil {
			t.Fatalf("transaction %d: %v", i, err)
		}
		if msg.From != addr {
			t.Errorf("transaction %d: from %x, want the account %x", i, msg.From, addr)
		}
		if msg.ExtraIntrinsicGas == 0 {
			t.Errorf("transaction %d: no signature gas in the message", i)
		}
		if nonce := statedb.GetNonce(addr); nonce != uint64(i) {
			t.Errorf("transaction %d: account nonce %d before it, want %d", i, nonce, i)
		}
		release()
	}

	// A transaction signed for another chain has a sender that cannot be
	// derived: it is an error, never the zero address.
	other := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), common.HexToHash("0x01"))
	bad := types.NewBlockWithHeader(&types.Header{
		ParentHash: block.Hash(),
		Number:     big.NewInt(2),
		GasLimit:   block.GasLimit(),
		Time:       block.Time() + 10,
		BaseFee:    block.BaseFee(),
		Difficulty: big.NewInt(1),
	}).WithBody([]*types.Transaction{sign(2, block.BaseFee(), other)}, nil)
	if _, _, _, _, err := eth.stateAtTransaction(context.Background(), bad, 0, 0); !errors.Is(err, types.ErrInvalidSig) {
		t.Fatalf("underivable sender: error %v, want %v", err, types.ErrInvalidSig)
	}
}
