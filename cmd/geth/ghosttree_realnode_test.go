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

//go:build integrationtests

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// The modules of the ghost tree methods, as the live test ran them.
var ghostRPCFlags = []string{"--http", "--http.addr", "127.0.0.1", "--http.port", "0", "--http.api", "eth,net,web3,ghost"}

// treeHeader is the part of a block the tree methods are checked against.
type treeHeader struct {
	Number          hexutil.Uint64 `json:"number"`
	Hash            common.Hash    `json:"hash"`
	TotalDifficulty *hexutil.Big   `json:"totalDifficulty"`
	CoinTreeRoot    *common.Hash   `json:"coinTreeRoot"`
	DataTreeRoot    *common.Hash   `json:"dataTreeRoot"`
}

func (h treeHeader) root(kind ghosttree.Kind) common.Hash {
	if kind == ghosttree.Data {
		return *h.DataTreeRoot
	}
	return *h.CoinTreeRoot
}

func (n *internalNode) treeHeader(t *testing.T, number string) treeHeader {
	t.Helper()
	var h *treeHeader
	if err := n.rpc.Call(&h, "eth_getBlockByNumber", number, false); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	if h == nil || h.CoinTreeRoot == nil || h.DataTreeRoot == nil {
		t.Fatalf("%s: block %s missing or without tree roots: %+v", n.name, number, h)
	}
	return *h
}

// leafPage and markerPage are the two results of ghost_getTreePage.
type leafPage struct {
	Kind      string         `json:"kind"`
	TreeIndex hexutil.Uint64 `json:"treeIndex"`
	Page      hexutil.Uint64 `json:"page"`
	Filled    hexutil.Uint64 `json:"filled"`
	Entries   []struct {
		Leaf common.Hash   `json:"leaf"`
		Note hexutil.Bytes `json:"note"`
	} `json:"entries"`
}

type markerPage struct {
	Count   hexutil.Uint64 `json:"count"`
	Markers []common.Hash  `json:"markers"`
}

// treeLeaf is a leaf a commit appended, with its note.
type treeLeaf struct {
	leaf common.Hash
	note []byte
}

// checkTrees checks what node n serves as of anchor the way a wallet checks
// it: the page-root list of each tree against the header root, every page
// against its page root, a witness of every leaf against the header root,
// and the leaves and notes against want. Both marker lists must hold
// wantMarkers markers, each page a whole page of {count, markers}.
func checkTrees(t *testing.T, n *internalNode, anchor treeHeader, want map[ghosttree.Kind][]treeLeaf, wantMarkers int) {
	t.Helper()
	for _, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		var roots []common.Hash
		if err := n.rpc.Call(&roots, "ghost_getPageRoots", kind.String(), "0x0", anchor.Hash); err != nil {
			t.Fatalf("%s: %v page roots at block %d: %v", n.name, kind, anchor.Number, err)
		}
		if got := ghosttree.RootFromPageRoots(kind, roots); got != anchor.root(kind) {
			t.Fatalf("%s: %v page roots at block %d give root %x, header %x", n.name, kind, anchor.Number, got, anchor.root(kind))
		}
		var got []treeLeaf
		for p := 0; p <= len(roots); p++ {
			var page leafPage
			if err := n.rpc.Call(&page, "ghost_getTreePage", kind.String(), "0x0", hexutil.Uint64(p), anchor.Hash); err != nil {
				t.Fatalf("%s: %v page %d at block %d: %v", n.name, kind, p, anchor.Number, err)
			}
			if page.Kind != kind.String() || page.TreeIndex != 0 || int(page.Page) != p || int(page.Filled) != len(page.Entries) {
				t.Fatalf("%s: %v page %d at block %d: %+v", n.name, kind, p, anchor.Number, page)
			}
			if p == len(roots) {
				if page.Filled != 0 {
					t.Fatalf("%s: %v page %d past the list holds %d leaves", n.name, kind, p, page.Filled)
				}
				break
			}
			leaves := make([]common.Hash, len(page.Entries))
			for i, e := range page.Entries {
				leaves[i] = e.Leaf
				got = append(got, treeLeaf{e.Leaf, e.Note})
			}
			if ghosttree.PageRoot(kind, leaves) != roots[p] {
				t.Fatalf("%s: %v page %d at block %d does not match its page root", n.name, kind, p, anchor.Number)
			}
			// The witness a wallet builds from the page verifies against
			// the header, which is what a reveal needs.
			header := &types.Header{CoinTreeRoot: anchor.CoinTreeRoot, DataTreeRoot: anchor.DataTreeRoot}
			for i, leaf := range leaves {
				position := uint32(p*ghosttree.PageLeaves + i)
				path, err := ghosttree.Witness(kind, position, leaves, roots)
				if err != nil {
					t.Fatalf("%s: witness of %v position %d: %v", n.name, kind, position, err)
				}
				if !ghosttree.VerifyMembership(header, kind, position, leaf, path) {
					t.Fatalf("%s: %v position %d does not verify against the header of block %d", n.name, kind, position, anchor.Number)
				}
			}
		}
		if len(got) != len(want[kind]) {
			t.Fatalf("%s: %v tree at block %d holds %d leaves, want %d", n.name, kind, anchor.Number, len(got), len(want[kind]))
		}
		for i, w := range want[kind] {
			if got[i].leaf != w.leaf || !bytes.Equal(got[i].note, w.note) {
				t.Fatalf("%s: %v position %d at block %d: leaf %x, want %x (or the note differs)", n.name, kind, i, anchor.Number, got[i].leaf, w.leaf)
			}
		}
	}
	for _, kind := range []string{"coin-markers", "data-markers"} {
		var seen int
		for p := 0; ; p++ {
			var raw map[string]json.RawMessage
			if err := n.rpc.Call(&raw, "ghost_getTreePage", kind, "0x0", hexutil.Uint64(p), anchor.Hash); err != nil {
				t.Fatalf("%s: %s page %d at block %d: %v", n.name, kind, p, anchor.Number, err)
			}
			if len(raw) != 2 || raw["count"] == nil || raw["markers"] == nil {
				t.Fatalf("%s: %s page %d: fields %v, want count and markers", n.name, kind, p, raw)
			}
			var page markerPage
			blob, _ := json.Marshal(raw)
			if err := json.Unmarshal(blob, &page); err != nil {
				t.Fatal(err)
			}
			if int(page.Count) != len(page.Markers) || page.Markers == nil {
				t.Fatalf("%s: %s page %d: count %d with %d markers", n.name, kind, p, page.Count, len(page.Markers))
			}
			seen += len(page.Markers)
			if len(page.Markers) < ghosttree.PageLeaves {
				break
			}
		}
		if seen != wantMarkers {
			t.Fatalf("%s: %s at block %d: %d markers, want %d", n.name, kind, anchor.Number, seen, wantMarkers)
		}
	}
}

// refusesAnchor checks that node n answers no tree method for an anchor that
// left its canonical chain.
func refusesAnchor(t *testing.T, n *internalNode, anchor common.Hash) {
	t.Helper()
	var out interface{}
	for _, call := range [][]interface{}{
		{"ghost_getPageRoots", "coin", "0x0", anchor},
		{"ghost_getPageRoots", "data", "0x0", anchor},
		{"ghost_getTreePage", "coin", "0x0", "0x0", anchor},
		{"ghost_getTreePage", "data", "0x0", "0x0", anchor},
		{"ghost_getTreePage", "coin-markers", "0x0", "0x0", anchor},
		{"ghost_getTreePage", "data-markers", "0x0", "0x0", anchor},
	} {
		err := n.rpc.Call(&out, call[0].(string), call[1:]...)
		if err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Errorf("%s: %v %v at the removed anchor %x: %v, %v", n.name, call[0], call[1], anchor, out, err)
		}
	}
}

// waitStable waits until node n's head has not moved for two seconds.
func waitStable(t *testing.T, n *internalNode) treeHeader {
	t.Helper()
	var (
		last  treeHeader
		since = time.Now()
	)
	waitFor(t, 2*time.Minute, "the head of "+n.name+" to settle", func() (bool, error) {
		if h := n.treeHeader(t, "latest"); h.Hash != last.Hash {
			last, since = h, time.Now()
			return false, nil
		}
		return time.Since(since) > 2*time.Second, nil
	})
	return last
}

// waitReceipt waits until node n has the transaction mined with status 1 and
// returns the block that holds it.
func waitReceipt(t *testing.T, n *internalNode, hash common.Hash) treeHeader {
	t.Helper()
	var block common.Hash
	waitFor(t, 5*time.Minute, fmt.Sprintf("%s to mine transaction %x", n.name, hash), func() (bool, error) {
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
		block = receipt.BlockHash
		return true, nil
	})
	var h *treeHeader
	if err := n.rpc.Call(&h, "eth_getBlockByHash", block, false); err != nil || h == nil {
		t.Fatalf("%s: block %x: %v", n.name, block, err)
	}
	return *h
}

func addPeer(t *testing.T, from, to *internalNode) {
	t.Helper()
	var info struct {
		Enode string `json:"enode"`
	}
	if err := to.rpc.Call(&info, "admin_nodeInfo"); err != nil {
		t.Fatal(err)
	}
	var added bool
	if err := from.rpc.Call(&added, "admin_addPeer", info.Enode); err != nil || !added {
		t.Fatalf("adding %s as a peer of %s: %v", to.name, from.name, err)
	}
}

// TestGhostTreeRealNodePagesAndReorg runs real geth processes on the internal
// network with the RPC modules eth,net,web3,ghost. Node a mines one coin
// commit and one data commit; its tree methods then answer for the coin and
// data trees and both marker lists, checked against the header roots, also
// after a restart. Node b mines a longer chain without them on its own; once
// the nodes peer, a reorganises to it and answers for the new chain, refusing
// the removed blocks. Mining again, the commits return to the chain, and both
// nodes answer for them.
func TestGhostTreeRealNodePagesAndReorg(t *testing.T) {
	var (
		ctx             = context.Background()
		key, _, account = testAccount(minerAccountSeed)
		chainID         = big.NewInt(ghost.InternalNetChainID)
		signer          = internalNetSigner()
		gwei            = big.NewInt(1_000_000_000)
		value           = new(big.Int).Mul(big.NewInt(1_000_000), gwei)
		genesis         = writeGenesis(t, ghost.InternalNetGenesis())
		aDir            = initDatadir(t, genesis)
		bDir            = initDatadir(t, genesis)
		coinF           = crypto.Keccak256Hash([]byte("ghost tree real node test coin F"))
		dataF           = crypto.Keccak256Hash([]byte("ghost tree real node test data F"))
		coinNote        = bytes.Repeat([]byte{0xc1}, ghostpriv.NoteSize)
		dataNote        = bytes.Repeat([]byte{0xd2}, ghostpriv.NoteSize)
		mining          = []string{"--miner.threads", "1", "--miner.etherbase", account.Hex()}
	)
	a := startInternalNode(t, "a", aDir, append(append([]string{"--mine"}, mining...), ghostRPCFlags...)...)

	// Before any commit both trees are empty and answer at genesis.
	empty := map[ghosttree.Kind][]treeLeaf{}
	checkTrees(t, a, a.treeHeader(t, "0x0"), empty, 0)

	waitFor(t, 5*time.Minute, "mined funds on a", func() (bool, error) {
		balance, err := a.eth.BalanceAt(ctx, account, nil)
		return err == nil && balance.Cmp(new(big.Int).Mul(big.NewInt(1000), value)) > 0, err
	})
	nonce, err := a.eth.PendingNonceAt(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	send := func(to common.Address, value *big.Int, data []byte) common.Hash {
		t.Helper()
		tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasTipCap: new(big.Int).Mul(big.NewInt(2), gwei),
			GasFeeCap: new(big.Int).Mul(big.NewInt(100), gwei),
			Gas:       60_000 + accountTxGas - vars.TxGas,
			To:        &to,
			Value:     value,
			Data:      data,
		})
		if err != nil {
			t.Fatal(err)
		}
		nonce++
		waitFor(t, time.Minute, "a to take the transaction", func() (bool, error) {
			err := a.eth.SendTransaction(ctx, tx)
			if err != nil && strings.Contains(err.Error(), "insufficient funds") {
				return false, nil
			}
			return err == nil, err
		})
		return tx.Hash()
	}
	coinData, err := ghostpriv.SaltedCommitData(coinF, make([]byte, ghostpriv.SaltSize), coinNote)
	if err != nil {
		t.Fatal(err)
	}
	dataData, err := ghostpriv.SaltedCommitData(dataF, make([]byte, ghostpriv.SaltSize), dataNote)
	if err != nil {
		t.Fatal(err)
	}
	coinTx := send(ghost.CommitEntryAddress, value, coinData)
	dataTx := send(ghost.DataCommitEntryAddress, ghostpriv.DataReserve.ToBig(), dataData)
	coinBlock, dataBlock := waitReceipt(t, a, coinTx), waitReceipt(t, a, dataTx)
	t.Logf("coin commit in block %d, data commit in block %d", coinBlock.Number, dataBlock.Number)

	committed := map[ghosttree.Kind][]treeLeaf{
		ghosttree.Coin: {{ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, coinF, uint256.MustFromBig(value)), coinNote}},
		ghosttree.Data: {{ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, dataF), dataNote}},
	}
	// Let a mine past both, then stop it.
	last := max(coinBlock.Number, dataBlock.Number)
	waitFor(t, 5*time.Minute, "a to mine past the commits", func() (bool, error) {
		return a.treeHeader(t, "latest").Number >= last+2, nil
	})
	if err := a.rpc.Call(nil, "miner_stop"); err != nil {
		t.Fatal(err)
	}
	aHead := waitStable(t, a)

	// Each commit is served from the block that holds it on, checked against
	// that block's header, and not before.
	for n := uint64(0); n <= uint64(aHead.Number); n++ {
		at := a.treeHeader(t, hexutil.EncodeUint64(n))
		want := map[ghosttree.Kind][]treeLeaf{}
		if n >= uint64(coinBlock.Number) {
			want[ghosttree.Coin] = committed[ghosttree.Coin]
		}
		if n >= uint64(dataBlock.Number) {
			want[ghosttree.Data] = committed[ghosttree.Data]
		}
		if n+3 < uint64(min(coinBlock.Number, dataBlock.Number)) && n%10 != 0 {
			continue // the early empty blocks are sampled
		}
		checkTrees(t, a, at, want, 0)
	}
	if *aHead.CoinTreeRoot == ghosttree.EmptyRoot(ghosttree.Coin) || *aHead.DataTreeRoot == ghosttree.EmptyRoot(ghosttree.Data) {
		t.Fatal("the header roots did not change with the commits")
	}

	// A restarted node answers from its stored history.
	a.rpc.Close()
	a.rpc = nil
	a.geth.Interrupt()
	a.geth.WaitExit()
	a = startInternalNode(t, "a", aDir, append(append([]string{}, mining...), ghostRPCFlags...)...)
	if h := a.treeHeader(t, "latest"); h.Hash != aHead.Hash {
		t.Fatalf("a restarted at block %d %x, stopped at %d %x", h.Number, h.Hash, aHead.Number, aHead.Hash)
	}
	checkTrees(t, a, aHead, committed, 0)

	// Node b mines a heavier chain of its own, without the commits.
	b := startInternalNode(t, "b", bDir, append(append([]string{"--mine"}, mining...), ghostRPCFlags...)...)
	waitFor(t, 15*time.Minute, "b to mine a heavier chain than a", func() (bool, error) {
		h := b.treeHeader(t, "latest")
		if h.TotalDifficulty != nil && aHead.TotalDifficulty != nil && h.TotalDifficulty.ToInt().Cmp(aHead.TotalDifficulty.ToInt()) <= 0 {
			return false, nil
		}
		return h.Number > aHead.Number+3, nil
	})
	if err := b.rpc.Call(nil, "miner_stop"); err != nil {
		t.Fatal(err)
	}
	bHead := waitStable(t, b)
	checkTrees(t, b, bHead, empty, 0)

	// a takes b's chain: the commits' blocks leave its canonical chain.
	addPeer(t, a, b)
	waitFor(t, 5*time.Minute, "a to reorganise to b's chain", func() (bool, error) {
		return a.treeHeader(t, "latest").Hash == bHead.Hash, nil
	})
	checkTrees(t, a, bHead, empty, 0)
	for _, removed := range []common.Hash{aHead.Hash, coinBlock.Hash, dataBlock.Hash} {
		refusesAnchor(t, a, removed)
	}
	for _, n := range []uint64{uint64(coinBlock.Number), uint64(dataBlock.Number), uint64(aHead.Number)} {
		checkTrees(t, a, a.treeHeader(t, hexutil.EncodeUint64(n)), empty, 0)
	}

	// Mining again on a, the commits return from its pool into the new
	// chain; b imports the blocks, and both nodes serve the same trees.
	if err := a.rpc.Call(nil, "miner_start"); err != nil {
		t.Fatal(err)
	}
	coinBlock, dataBlock = waitReceipt(t, a, coinTx), waitReceipt(t, a, dataTx)
	t.Logf("after the reorganisation: coin commit in block %d, data commit in block %d", coinBlock.Number, dataBlock.Number)
	last = max(coinBlock.Number, dataBlock.Number)
	waitFor(t, 5*time.Minute, "a to mine past the commits again", func() (bool, error) {
		return a.treeHeader(t, "latest").Number >= last+1, nil
	})
	if err := a.rpc.Call(nil, "miner_stop"); err != nil {
		t.Fatal(err)
	}
	head := waitStable(t, a)
	waitFor(t, 5*time.Minute, "b to import a's blocks", func() (bool, error) {
		return b.treeHeader(t, "latest").Hash == head.Hash, nil
	})
	for _, n := range []*internalNode{a, b} {
		checkTrees(t, n, head, committed, 0)
		checkTrees(t, n, n.treeHeader(t, hexutil.EncodeUint64(uint64(bHead.Number))), empty, 0)
	}
}
