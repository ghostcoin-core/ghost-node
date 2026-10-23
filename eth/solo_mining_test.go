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
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestSoloMiningExternalMiner starts a node on the internal test network
// with local mining off, takes work over its HTTP RPC as an external miner
// would, solves it with a RandomX hash loop of its own, submits it and sees
// the block on the chain.
func TestSoloMiningExternalMiner(t *testing.T) {
	stack, err := node.New(&node.Config{
		HTTPHost:    "127.0.0.1",
		HTTPPort:    0,
		HTTPModules: []string{"eth"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	etherbase := common.Address{0x5e}
	config := ethconfig.Defaults
	config.Genesis = ghost.InternalNetGenesis()
	config.Miner.Etherbase = etherbase
	backend, err := New(stack, &config)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.Engine().(*randomx.RandomX); !ok {
		t.Fatalf("the internal network runs engine %T, want RandomX", backend.Engine())
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	// Mining on, with no local CPU threads: only an external miner seals.
	if err := backend.StartMining(-1); err != nil {
		t.Fatal(err)
	}
	defer backend.StopMining()

	client, err := rpc.Dial(stack.HTTPEndpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Take work.
	var work [4]string
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(50 * time.Millisecond) {
		if err = client.Call(&work, "eth_getWork"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no work over RPC: %v", err)
		}
	}
	if number, err := hexutil.DecodeUint64(work[3]); err != nil || number != 1 {
		t.Fatalf("work for block %s, want block 1", work[3])
	}
	if key := common.HexToHash(work[1]); key != backend.BlockChain().Genesis().Hash() {
		t.Fatalf("work keyed by %x, want the genesis hash %x", key, backend.BlockChain().Genesis().Hash())
	}

	// Solve it outside the node's sealer.
	sealHash := common.HexToHash(work[0])
	key := common.HexToHash(work[1])
	target := new(big.Int).SetBytes(common.FromHex(work[2]))
	hasher, err := randomx.NewHasher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	defer hasher.Close()
	input := make([]byte, 40)
	copy(input, sealHash[:])
	var (
		nonce  uint64
		result [32]byte
		solved bool
	)
	for ; nonce < 1_000_000; nonce++ {
		binary.BigEndian.PutUint64(input[32:], nonce)
		if result = hasher.Hash(input); new(big.Int).SetBytes(result[:]).Cmp(target) <= 0 {
			solved = true
			break
		}
	}
	if !solved {
		t.Fatal("no nonce found")
	}

	// A solution for work the node never handed out is refused.
	var accepted bool
	if err := client.Call(&accepted, "eth_submitWork", types.EncodeNonce(nonce), common.Hash{0x01}, common.Hash(result)); err != nil {
		t.Fatal(err)
	}
	if accepted {
		t.Fatal("the node accepted a solution for work it never handed out")
	}

	// Submit it.
	if err := client.Call(&accepted, "eth_submitWork", types.EncodeNonce(nonce), sealHash, common.Hash(result)); err != nil {
		t.Fatal(err)
	}
	if !accepted {
		t.Fatal("the node refused a valid solution")
	}

	// See the block on the chain.
	var block map[string]interface{}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		block = nil
		if err := client.Call(&block, "eth_getBlockByNumber", "0x1", false); err != nil {
			t.Fatal(err)
		}
		if block != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the submitted block did not reach the chain")
		}
	}
	encoded := types.EncodeNonce(nonce)
	if got, want := block["nonce"], hexutil.Encode(encoded[:]); got != want {
		t.Errorf("block 1 has nonce %v, want the submitted %v", got, want)
	}
	if got := common.HexToAddress(block["miner"].(string)); got != etherbase {
		t.Errorf("block 1 is mined by %x, want the etherbase %x", got, etherbase)
	}
	head := backend.BlockChain().CurrentBlock()
	if head.Number.Uint64() != 1 || backend.Engine().SealHash(head) != sealHash {
		t.Errorf("head is block %d with seal hash %x, want block 1 with %x", head.Number.Uint64(), backend.Engine().SealHash(head), sealHash)
	}
}
