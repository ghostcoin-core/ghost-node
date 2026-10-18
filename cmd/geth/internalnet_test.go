// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

// The internal network's accounts have fixed test keys, the same numbers as
// in scripts/internal-net.sh. They are test keys only, never launch keys.
const (
	minerKeyNumber    = 6_777_971
	receiverKeyNumber = 6_777_972
)

func testKey(t *testing.T, n int64) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.ToECDSA(common.LeftPadBytes(big.NewInt(n).Bytes(), 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// internalNode is one geth process of a test network.
type internalNode struct {
	name string
	geth *testgeth
	rpc  *rpc.Client
	eth  *ethclient.Client
}

// blockRef is the number and hash of a block as a node reports it.
type blockRef struct {
	Number hexutil.Uint64 `json:"number"`
	Hash   common.Hash    `json:"hash"`
}

func (n *internalNode) block(t *testing.T, number string) blockRef {
	t.Helper()
	var h *blockRef
	if err := n.rpc.Call(&h, "eth_getBlockByNumber", number, false); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	if h == nil {
		t.Fatalf("%s: no block %s", n.name, number)
	}
	return *h
}

func (n *internalNode) balance(t *testing.T, account common.Address, number *big.Int) *big.Int {
	t.Helper()
	balance, err := n.eth.BalanceAt(context.Background(), account, number)
	if err != nil {
		t.Fatalf("%s: balance of %x at %v: %v", n.name, account, number, err)
	}
	return balance
}

// writeGenesis writes the genesis as a genesis file and returns its path.
func writeGenesis(t *testing.T, g *genesisT.Genesis) string {
	t.Helper()
	blob, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "genesis.json")
	if err := os.WriteFile(file, blob, 0600); err != nil {
		t.Fatal(err)
	}
	return file
}

// initDatadir initialises a fresh data directory with the genesis file.
func initDatadir(t *testing.T, genesis string) string {
	t.Helper()
	datadir := t.TempDir()
	g := runGeth(t, "--datadir", datadir, "init", genesis)
	g.WaitExit()
	if g.Err != nil {
		t.Fatalf("geth init: %v", g.Err)
	}
	return datadir
}

// startInternalNode starts a geth process on an initialised data directory,
// with no discovery and the operating system's choice of port.
func startInternalNode(t *testing.T, name, datadir string, extra ...string) *internalNode {
	t.Helper()
	args := append([]string{
		"--datadir", datadir, "--networkid", fmt.Sprint(ghost.InternalNetChainID),
		"--syncmode", "full", "--gcmode", "archive", "--cache", "64", "--datadir.minfreedisk", "0",
		"--port", "0", "--authrpc.port", "0", "--nat", "none", "--nodiscover", "--verbosity", "2",
	}, extra...)
	n := &internalNode{name: name, geth: runGeth(t, args...)}
	t.Cleanup(func() {
		if n.rpc != nil {
			n.rpc.Close()
		}
		n.geth.Kill()
		n.geth.WaitExit()
	})
	ipc := filepath.Join(datadir, "geth.ipc")
	waitForEndpoint(t, ipc, time.Minute)
	client, err := rpc.Dial(ipc)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	n.rpc, n.eth = client, ethclient.NewClient(client)
	return n
}

// startInternalNet starts the two-node internal network: a node mining to
// the miner account, and a peer that only syncs.
func startInternalNet(t *testing.T) (miner, peer *internalNode, account common.Address) {
	t.Helper()
	account = crypto.PubkeyToAddress(testKey(t, minerKeyNumber).PublicKey)
	genesis := writeGenesis(t, ghost.InternalNetGenesis())
	minerDir, peerDir := initDatadir(t, genesis), initDatadir(t, genesis)

	miner = startInternalNode(t, "miner", minerDir, "--mine", "--miner.threads", "1", "--miner.etherbase", account.Hex())
	peer = startInternalNode(t, "peer", peerDir)

	var info struct {
		Enode string `json:"enode"`
	}
	if err := miner.rpc.Call(&info, "admin_nodeInfo"); err != nil {
		t.Fatal(err)
	}
	var added bool
	if err := peer.rpc.Call(&added, "admin_addPeer", info.Enode); err != nil || !added {
		t.Fatalf("adding the miner %s as a peer: %v", info.Enode, err)
	}
	waitFor(t, time.Minute, "the nodes to peer", func() (bool, error) {
		var peers []json.RawMessage
		err := miner.rpc.Call(&peers, "admin_peers")
		return len(peers) > 0, err
	})
	return miner, peer, account
}

// waitFor polls cond every 200ms until it holds, failing the test after the
// timeout or on an error.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, err := cond()
		if err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// rewardsUpTo returns the sum of the block rewards of blocks 1..n.
func rewardsUpTo(n uint64) *big.Int {
	params, sum := ghost.InternalNetParams(), new(uint256.Int)
	for h := uint64(1); h <= n; h++ {
		sum.Add(sum, params.BlockReward(h))
	}
	return sum.ToBig()
}

// TestInternalNetMinesAndSyncs1000Blocks runs the internal network as two
// geth processes: one mines a thousand RandomX blocks, the other syncs them,
// and both agree on the head. The miner account holds exactly the emission
// formula's rewards on both nodes.
func TestInternalNetMinesAndSyncs1000Blocks(t *testing.T) {
	const target = 1000
	miner, peer, account := startInternalNet(t)

	waitFor(t, 15*time.Minute, "the miner to reach block 1000", func() (bool, error) {
		number, err := miner.eth.BlockNumber(context.Background())
		return number >= target, err
	})
	if err := miner.rpc.Call(nil, "miner_stop"); err != nil {
		t.Fatal(err)
	}
	// Once mining has stopped the miner's head stays put; the peer must
	// reach exactly that block.
	var last blockRef
	stableSince := time.Now()
	waitFor(t, 5*time.Minute, "the heads to agree", func() (bool, error) {
		if h := miner.block(t, "latest"); h != last {
			last, stableSince = h, time.Now()
			return false, nil
		}
		return time.Since(stableSince) > 2*time.Second && peer.block(t, "latest") == last, nil
	})
	t.Logf("both nodes at block %d, hash %x", last.Number, last.Hash)
	if last.Number < target {
		t.Fatalf("head %d is below %d", last.Number, target)
	}
	for _, number := range []uint64{1, target / 2, target} {
		at := hexutil.EncodeUint64(number)
		if a, b := miner.block(t, at), peer.block(t, at); a != b {
			t.Errorf("block %d differs: miner %x, peer %x", number, a.Hash, b.Hash)
		}
	}

	// The end-to-end reward check: the miner account has exactly the sum of
	// BlockReward(h), at block 1000 and at the head, on both nodes.
	for _, c := range []struct {
		number uint64
		want   *big.Int
	}{
		{target, rewardsUpTo(target)},
		{uint64(last.Number), rewardsUpTo(uint64(last.Number))},
	} {
		for _, n := range []*internalNode{miner, peer} {
			if got := n.balance(t, account, new(big.Int).SetUint64(c.number)); got.Cmp(c.want) != 0 {
				t.Errorf("%s: miner balance at block %d is %v, want the emission sum %v", n.name, c.number, got, c.want)
			}
		}
	}
	if rewardsUpTo(target).Sign() == 0 {
		t.Fatal("the emission sum is zero")
	}
}

// TestInternalNetTransfers sends ordinary EVM transfers between two public
// accounts, a dynamic-fee one through the syncing peer and a legacy one back
// through the miner, and checks that both are mined and that the balances
// change the same way on both nodes.
func TestInternalNetTransfers(t *testing.T) {
	miner, peer, account := startInternalNet(t)
	var (
		ctx         = context.Background()
		chainID     = big.NewInt(ghost.InternalNetChainID)
		signer      = types.LatestSignerForChainID(chainID)
		minerKey    = testKey(t, minerKeyNumber)
		receiverKey = testKey(t, receiverKeyNumber)
		receiver    = crypto.PubkeyToAddress(receiverKey.PublicKey)
		ether       = big.NewInt(1_000_000_000_000_000_000)
		gwei        = big.NewInt(1_000_000_000)
	)
	// The peer must know the miner's funds before it takes the transfer.
	waitFor(t, 5*time.Minute, "the peer to see mined funds", func() (bool, error) {
		balance, err := peer.eth.BalanceAt(ctx, account, nil)
		return err == nil && balance.Cmp(ether) > 0, err
	})
	for _, n := range []*internalNode{miner, peer} {
		if got := n.balance(t, receiver, nil); got.Sign() != 0 {
			t.Fatalf("%s: receiver starts with %v", n.name, got)
		}
	}

	send := func(via *internalNode, key *ecdsa.PrivateKey, data types.TxData) common.Hash {
		t.Helper()
		tx, err := types.SignNewTx(key, signer, data)
		if err != nil {
			t.Fatal(err)
		}
		// The transaction pool moves to a new head shortly after the chain
		// does, so funds the head already shows may not be in it yet.
		waitFor(t, time.Minute, "the "+via.name+" to take the transaction", func() (bool, error) {
			err := via.eth.SendTransaction(ctx, tx)
			if err != nil && strings.Contains(err.Error(), "insufficient funds") {
				return false, nil
			}
			return err == nil, err
		})
		return tx.Hash()
	}
	mined := func(hash common.Hash) {
		t.Helper()
		var blocks [2]common.Hash
		for i, n := range []*internalNode{miner, peer} {
			waitFor(t, 5*time.Minute, fmt.Sprintf("the %s to have transaction %x mined", n.name, hash), func() (bool, error) {
				var receipt *struct {
					Status    hexutil.Uint64 `json:"status"`
					BlockHash common.Hash    `json:"blockHash"`
				}
				if err := n.rpc.Call(&receipt, "eth_getTransactionReceipt", hash); err != nil || receipt == nil {
					return false, err
				}
				if uint64(receipt.Status) != types.ReceiptStatusSuccessful {
					return false, fmt.Errorf("transaction %x failed", hash)
				}
				blocks[i] = receipt.BlockHash
				return true, nil
			})
		}
		if blocks[0] != blocks[1] {
			t.Fatalf("transaction %x is in block %x on the miner and %x on the peer", hash, blocks[0], blocks[1])
		}
	}

	// A dynamic-fee transfer of one ether, given to the peer, which passes it
	// to the miner.
	nonce, err := peer.eth.PendingNonceAt(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	mined(send(peer, minerKey, &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: new(big.Int).Mul(big.NewInt(2), gwei),
		GasFeeCap: new(big.Int).Mul(big.NewInt(100), gwei),
		Gas:       21_000,
		To:        &receiver,
		Value:     ether,
	}))
	for _, n := range []*internalNode{miner, peer} {
		if got := n.balance(t, receiver, nil); got.Cmp(ether) != 0 {
			t.Errorf("%s: receiver has %v after the transfer, want %v", n.name, got, ether)
		}
	}

	// A legacy transfer of a tenth of that back, from the receiver.
	gasPrice := new(big.Int).Mul(big.NewInt(100), gwei)
	tenth := new(big.Int).Div(ether, big.NewInt(10))
	mined(send(miner, receiverKey, &types.LegacyTx{
		Nonce:    0,
		GasPrice: gasPrice,
		Gas:      21_000,
		To:       &account,
		Value:    tenth,
	}))
	want := new(big.Int).Sub(ether, tenth)
	want.Sub(want, new(big.Int).Mul(gasPrice, big.NewInt(21_000)))
	for _, n := range []*internalNode{miner, peer} {
		if got := n.balance(t, receiver, nil); got.Cmp(want) != 0 {
			t.Errorf("%s: receiver has %v after sending, want %v", n.name, got, want)
		}
	}
}

// TestUnknownChainIDRefusedAtStart checks that a node whose chain ID has no
// consensus parameters refuses to start, with a one-line message.
func TestUnknownChainIDRefusedAtStart(t *testing.T) {
	g := ghost.InternalNetGenesis()
	if err := g.Config.SetChainID(big.NewInt(7)); err != nil {
		t.Fatal(err)
	}
	seven := uint64(7)
	if err := g.Config.SetNetworkID(&seven); err != nil {
		t.Fatal(err)
	}
	datadir := initDatadir(t, writeGenesis(t, g))
	geth := runGeth(t, "--datadir", datadir, "--port", "0", "--authrpc.port", "0", "--maxpeers", "0",
		"--nodiscover", "--nat", "none", "--ipcdisable")
	geth.KillTimeout = time.Minute
	geth.ExpectRegexp(`Fatal: Failed to register the Ethereum service: no consensus parameters for chain ID 7: [^\n]+\n`)
	geth.ExpectExit()
	if status := geth.ExitStatus(); status == 0 {
		t.Errorf("node with chain ID 7 exited with status 0")
	}
}

// TestDevModeMines checks that developer mode still starts and mines.
func TestDevModeMines(t *testing.T) {
	geth := runGeth(t, "--dev", "--port", "0", "--authrpc.port", "0", "--maxpeers", "0", "--nodiscover",
		"--nat", "none", "--ipcdisable", "--exec", "admin.sleepBlocks(3, 120); eth.blockNumber >= 3", "console")
	geth.KillTimeout = 3 * time.Minute
	geth.Expect("true\n")
	geth.ExpectExit()
}

// TestInternalNetScriptMatchesGenesis checks that scripts/internal-net.sh
// starts the network from InternalNetGenesis and mines to the test key.
func TestInternalNetScriptMatchesGenesis(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "internal-net.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	const open, end = "<<'GENESIS'\n", "\nGENESIS\n"
	start := strings.Index(text, open)
	if start < 0 {
		t.Fatal("the script has no genesis document")
	}
	body := text[start+len(open):]
	stop := strings.Index(body, end)
	if stop < 0 {
		t.Fatal("the script's genesis document does not end")
	}
	var got genesisT.Genesis
	if err := json.Unmarshal([]byte(body[:stop]), &got); err != nil {
		t.Fatalf("the script's genesis does not parse: %v", err)
	}
	want := ghost.InternalNetGenesis()
	if a, b := core.GenesisToBlock(&got, nil).Hash(), core.GenesisToBlock(want, nil).Hash(); a != b {
		t.Errorf("the script's genesis block is %x, InternalNetGenesis is %x", a, b)
	}
	gotConfig, err := json.Marshal(got.Config)
	if err != nil {
		t.Fatal(err)
	}
	wantConfig, err := json.Marshal(want.Config)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotConfig) != string(wantConfig) {
		t.Errorf("the script's chain configuration differs:\n%s\nwant\n%s", gotConfig, wantConfig)
	}
	if err := ghost.CheckProfile(got.Config); err != nil {
		t.Error(err)
	}
	if line := fmt.Sprintf("printf '%%064x\\n' %d", minerKeyNumber); !strings.Contains(text, line) {
		t.Errorf("the script does not write the miner test key (%s)", line)
	}
}
