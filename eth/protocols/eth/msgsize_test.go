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
	"math"
	"math/big"
	"testing"

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
	"github.com/ethereum/go-ethereum/rlp"
)

// poolTxMaxSize is the largest transaction the pool takes, txMaxSize of the
// legacy pool: 128 KiB.
const poolTxMaxSize = 128 * 1024

// mapTxPool serves the transactions it holds by hash.
type mapTxPool map[common.Hash]*types.Transaction

func (p mapTxPool) Get(hash common.Hash) *types.Transaction { return p[hash] }

// poolBackend is a test backend that serves pooled transactions from pool.
type poolBackend struct {
	*testBackend
	pool TxPool
}

func (b poolBackend) TxPool() TxPool { return b.pool }

// zeroDataTx signs an account call carrying dataLen zero bytes of calldata,
// with exactly the gas it needs, for the chain of genesis.
func zeroDataTx(genesis common.Hash, nonce uint64, feeCap *big.Int, dataLen int) *types.Transaction {
	to := common.Address{0xbb}
	return signTestTx(genesis, testKey, &types.GhostAccountTx{
		Nonce:     nonce,
		GasFeeCap: feeCap,
		Gas:       testTransferGas + vars.TxDataZeroGas*uint64(dataLen),
		To:        &to,
		Data:      make([]byte, dataLen),
	})
}

// sizedZeroDataTx returns the zero-data transaction whose size, as measured
// by size, is exactly target. Every field but the data has a fixed encoded
// length, so one correction suffices.
func sizedZeroDataTx(t *testing.T, genesis common.Hash, nonce uint64, feeCap *big.Int, target int, size func(*types.Transaction) int) *types.Transaction {
	t.Helper()
	guess := target - 16*1024
	tx := zeroDataTx(genesis, nonce, feeCap, guess)
	tx = zeroDataTx(genesis, nonce, feeCap, guess+target-size(tx))
	if got := size(tx); got != target {
		t.Fatalf("sized transaction measures %d bytes, want %d", got, target)
	}
	return tx
}

func bodySize(tx *types.Transaction) int {
	enc, err := rlp.EncodeToBytes(&types.Body{Transactions: []*types.Transaction{tx}})
	if err != nil {
		panic(err)
	}
	return len(enc)
}

func encodedSize(t *testing.T, name string, packet interface{}) int {
	t.Helper()
	enc, err := rlp.EncodeToBytes(packet)
	if err != nil {
		t.Fatalf("encoding %s: %v", name, err)
	}
	if len(enc) >= maxMessageSize {
		t.Errorf("%s is %d bytes, not under the message cap of %d", name, len(enc), maxMessageSize)
	}
	t.Logf("%s: %d bytes (cap %d, margin %d)", name, len(enc), maxMessageSize, maxMessageSize-len(enc))
	return len(enc)
}

// TestMaxBlockFitsMessageCap is the QS-9 check (spec 09, section 8.4): the
// block with the most bytes at the largest allowed gas limit, one account
// transaction of zero calldata bytes at 4 gas each filling the block, fits in
// every message that carries it, a new block message and a block bodies
// response, under the 10 MiB message cap; and so does the pooled transactions
// reply for transactions of the pool's largest size.
func TestMaxBlockFitsMessageCap(t *testing.T) {
	if maxMessageSize != 10_485_760 {
		t.Fatalf("message cap %d, want 10,485,760", maxMessageSize)
	}
	if vars.TxDataZeroGas != 4 {
		t.Fatalf("zero calldata byte costs %d gas, want 4", vars.TxDataZeroGas)
	}
	var (
		db     = rawdb.NewMemoryDatabase()
		engine = ethash.NewFaker()
		gspec  = &genesisT.Genesis{
			Config:   params.TestChainConfig,
			GasLimit: ghost.MaxBlockGasLimit,
			Alloc:    genesisT.GenesisAlloc{testAddr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
		}
		// The calldata of the largest transaction the gas limit allows.
		maxData = int((ghost.MaxBlockGasLimit - testTransferGas) / vars.TxDataZeroGas)
	)
	// Block 1 carries a body of one byte under the serving soft limit, so a
	// bodies response serves the next body too: the largest response there
	// is. Block 2 is the block with the most bytes.
	genesis := core.GenesisToBlock(gspec, nil).Hash()
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 2, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(sizedZeroDataTx(t, genesis, b.TxNonce(testAddr), b.BaseFee(), softResponseLimit-1, bodySize))
		case 1:
			b.AddTx(zeroDataTx(genesis, b.TxNonce(testAddr), b.BaseFee(), maxData))
		}
	})
	chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{db: db, chain: chain}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d not imported: %v", n+1, err)
	}

	// The block is as full as the gas limit allows: no further zero byte fits.
	block := blocks[1]
	if block.GasLimit() != ghost.MaxBlockGasLimit {
		t.Fatalf("block gas limit %d, want %d", block.GasLimit(), ghost.MaxBlockGasLimit)
	}
	if left := block.GasLimit() - block.GasUsed(); left >= vars.TxDataZeroGas {
		t.Fatalf("block leaves %d gas unused, room for more calldata", left)
	}
	t.Logf("largest block: %d gas used, %d calldata bytes, %d bytes encoded", block.GasUsed(), maxData, block.Size())

	// A new block message, with the largest total difficulty a peer accepts.
	maxTD := new(big.Int).Sub(new(big.Int).Lsh(common.Big1, 100), common.Big1)
	encodedSize(t, "new block message", &NewBlockPacket{Block: block, TD: maxTD})

	// Block bodies responses as the serving handler builds them: the largest
	// body alone, and after a body just under the soft limit.
	for _, c := range []struct {
		name  string
		query GetBlockBodiesRequest
		want  int
	}{
		{"block bodies response, largest body", GetBlockBodiesRequest{block.Hash()}, 1},
		{"block bodies response, largest body after the soft limit", GetBlockBodiesRequest{blocks[0].Hash(), block.Hash()}, 2},
	} {
		bodies := ServiceGetBlockBodiesQuery(chain, c.query)
		if len(bodies) != c.want {
			t.Fatalf("%s: %d bodies served, want %d", c.name, len(bodies), c.want)
		}
		encodedSize(t, c.name, &BlockBodiesRLPPacket{RequestId: math.MaxUint64, BlockBodiesRLPResponse: bodies})
	}

	// A pooled transactions reply of transactions of the pool's largest size.
	var (
		pool   = make(mapTxPool)
		query  = GetPooledTransactionsRequest{}
		txSize = func(tx *types.Transaction) int { return int(tx.Size()) }
	)
	for nonce := uint64(0); nonce < 2*softResponseLimit/poolTxMaxSize; nonce++ {
		tx := sizedZeroDataTx(t, genesis, nonce, big.NewInt(vars.InitialBaseFee), poolTxMaxSize, txSize)
		pool[tx.Hash()] = tx
		query = append(query, tx.Hash())
	}
	hashes, txs := answerGetPooledTransactions(poolBackend{backend, pool}, query)
	if want := (softResponseLimit + poolTxMaxSize - 1) / poolTxMaxSize; len(hashes) != want {
		t.Fatalf("%d pooled transactions served, want %d", len(hashes), want)
	}
	encodedSize(t, "pooled transactions reply", &PooledTransactionsRLPPacket{RequestId: math.MaxUint64, PooledTransactionsRLPResponse: txs})
}
