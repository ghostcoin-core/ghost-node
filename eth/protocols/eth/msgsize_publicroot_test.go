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
)

// messageCap is the 10 MiB message cap of spec 09, section 8.4, in bytes.
const messageCap = 10 * 1024 * 1024

// TestPublicRootFreeBlockFitsMessageCapAndCountsRawSigTxs builds the block
// without a public root that holds the most account transactions with their
// raw signatures (0x52) at the largest allowed gas limit: ML-DSA-44 plain
// transfers, the cheapest raw-signature transaction, as many as the gas
// limit pays for. It checks that no message carrying the block, a new block
// message or a block bodies response, alone or after a body just under the
// serving soft limit, is over 10,485,760 bytes, and records the count of
// raw-signature transactions the block achieved: the count the gas limit
// allows, not a count the test assumes.
func TestPublicRootFreeBlockFitsMessageCapAndCountsRawSigTxs(t *testing.T) {
	if maxMessageSize > messageCap {
		t.Fatalf("message cap %d, above 10 MiB (%d)", maxMessageSize, messageCap)
	}
	var (
		db     = rawdb.NewMemoryDatabase()
		engine = ethash.NewFaker()
		gspec  = &genesisT.Genesis{
			Config:   params.TestChainConfig,
			GasLimit: ghost.MaxBlockGasLimit,
			Alloc:    genesisT.GenesisAlloc{testAddr: {Balance: new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1_000_000_000_000_000_000))}},
		}
		genesis = core.GenesisToBlock(gspec, nil).Hash()
		to      = common.Address{0xbb}
	)
	// Block 1 carries a body of one byte under the serving soft limit, so a
	// bodies response serves the next body too. Block 2 is the block of raw-
	// signature transfers, as many as its gas pays for.
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 2, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(sizedZeroDataTx(t, genesis, b.TxNonce(testAddr), b.BaseFee(), softResponseLimit-1, bodySize))
		case 1:
			for b.Gas() >= testTransferGas {
				b.AddTx(signTestTx(genesis, testKey, &types.GhostAccountTx{
					Nonce:     b.TxNonce(testAddr),
					GasFeeCap: b.BaseFee(),
					Gas:       testTransferGas,
					To:        &to,
					Value:     big.NewInt(1),
				}))
			}
		}
	})
	chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d not imported: %v", n+1, err)
	}

	// The block holds no public root and no binding transaction, only
	// raw-signature transfers, and no further one fits its gas.
	block := blocks[1]
	if block.GasLimit() != ghost.MaxBlockGasLimit {
		t.Fatalf("block gas limit %d, want %d", block.GasLimit(), ghost.MaxBlockGasLimit)
	}
	count := 0
	for i, tx := range block.Transactions() {
		if tx.Type() != types.GhostAccountTxType {
			t.Fatalf("transaction %d of type %#x, want raw-signature account transactions only", i, tx.Type())
		}
		if _, _, sig, ok := tx.GhostAccountAuth(); !ok || len(sig) != types.GhostMLDSA44SignatureSize {
			t.Fatalf("transaction %d carries no raw ML-DSA-44 signature", i)
		}
		count++
	}
	if count == 0 {
		t.Fatal("the block holds no raw-signature transaction")
	}
	if left := block.GasLimit() - block.GasUsed(); left >= testTransferGas {
		t.Fatalf("the block leaves %d gas unused, room for another raw-signature transfer of %d", left, testTransferGas)
	}
	if want := int(block.GasLimit() / testTransferGas); count != want {
		t.Fatalf("%d raw-signature transfers, the gas limit pays for %d", count, want)
	}
	rs := chain.GetReceiptsByHash(block.Hash())
	if len(rs) != count {
		t.Fatalf("%d receipts for %d transactions", len(rs), count)
	}
	for i, r := range rs {
		if r.Status != types.ReceiptStatusSuccessful || r.GasUsed != testTransferGas {
			t.Fatalf("transfer %d: status %d, gas %d, want successful at %d", i, r.Status, r.GasUsed, testTransferGas)
		}
	}
	t.Logf("public-root-free block: %d raw-signature transactions achieved at gas limit %d, %d gas a transfer, %d gas used, %d bytes encoded",
		count, block.GasLimit(), testTransferGas, block.GasUsed(), block.Size())

	// Every message that carries the block is within the cap.
	measure := func(name string, packet interface{}) int {
		t.Helper()
		size := encodedSize(t, name, packet)
		if size > messageCap {
			t.Fatalf("%s is %d bytes, over the 10 MiB message cap of %d", name, size, messageCap)
		}
		return size
	}
	maxTD := new(big.Int).Sub(new(big.Int).Lsh(common.Big1, 100), common.Big1)
	measure("new block message", &NewBlockPacket{Block: block, TD: maxTD})
	for _, c := range []struct {
		name  string
		query GetBlockBodiesRequest
		want  int
	}{
		{"block bodies response, the raw-signature body", GetBlockBodiesRequest{block.Hash()}, 1},
		{"block bodies response, the raw-signature body after the soft limit", GetBlockBodiesRequest{blocks[0].Hash(), block.Hash()}, 2},
	} {
		bodies := ServiceGetBlockBodiesQuery(chain, c.query)
		if len(bodies) != c.want {
			t.Fatalf("%s: %d bodies served, want %d", c.name, len(bodies), c.want)
		}
		measure(c.name, &BlockBodiesRLPPacket{RequestId: math.MaxUint64, BlockBodiesRLPResponse: bodies})
	}
}
