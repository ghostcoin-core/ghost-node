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
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/ghostpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// nodeFilterTxPool is the mock pool with the node's own type filter: that of
// a transaction pool over the reveal pool, so that the fetcher requests just
// the types the node's pools take from the network.
type nodeFilterTxPool struct {
	*testTxPool
	node *txpool.TxPool
}

func (p *nodeFilterTxPool) FilterType(kind byte) bool { return p.node.FilterType(kind) }

// newNodeFilterHandler is a test handler whose pool has the node's own type
// filter and whose reveal pool is reveals, which records what it is handed.
func newNodeFilterHandler(t *testing.T, reveals *recordingGhostPool) (*handler, *testTxPool) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	gspec := &genesisT.Genesis{
		Config:   params.TestChainConfig,
		GasLimit: 30_000_000,
		Alloc:    genesisT.GenesisAlloc{testAddr: {Balance: big.NewInt(1000000)}},
	}
	chain, err := core.NewBlockChain(db, nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	node, err := txpool.New(1, chain, []txpool.SubPool{ghostpool.New(chain)})
	if err != nil {
		t.Fatal(err)
	}
	mock := newTestTxPool()
	cfg := &handlerConfig{
		Database:   db,
		Chain:      chain,
		TxPool:     &nodeFilterTxPool{testTxPool: mock, node: node},
		Merger:     consensus.NewMerger(rawdb.NewMemoryDatabase()),
		Network:    1,
		Sync:       downloader.SnapSync,
		BloomCache: 1,
	}
	if reveals != nil {
		cfg.GhostPool = reveals
	}
	h, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.Start(1000)
	t.Cleanup(func() {
		h.Stop()
		node.Close()
		chain.Stop()
	})
	return h, mock
}

// TestPolicyTransactionsFetchedFromAnnouncements runs two nodes: the first
// holds a policy reveal, a policy action and a private bundle, each too large
// to be broadcast whole, so it only announces them; the second, with the
// node's own type filter, fetches all three from the announcement and hands
// them to its reveal pool with the peer they came from.
func TestPolicyTransactionsFetchedFromAnnouncements(t *testing.T) {
	envelope := func(kind byte, size int) []byte {
		env := make([]byte, size)
		env[0] = kind
		return env
	}
	reveal, err := types.NewGhostPolicyRevealTx(envelope(types.GhostPolicyRevealTxType, types.GhostPolicyRevealEnvelopeSize))
	if err != nil {
		t.Fatal(err)
	}
	action, err := types.NewGhostPolicyActionTx(envelope(types.GhostPolicyActionTxType, types.GhostPolicyActionEnvelopeSize))
	if err != nil {
		t.Fatal(err)
	}
	bundleEnv := envelope(types.GhostBundleTxType, 1+types.GhostBundlePayloadSize(1))
	binary.BigEndian.PutUint16(bundleEnv[1:], 1)     // version
	binary.BigEndian.PutUint16(bundleEnv[1+2+8:], 1) // count
	bundle, err := types.NewGhostBundleTx(bundleEnv)
	if err != nil {
		t.Fatal(err)
	}
	want := []*types.Transaction{reveal, action, bundle}
	for _, tx := range want {
		if tx.Size() <= txMaxBroadcastSize {
			t.Fatalf("type %#x of %d bytes is broadcast whole", tx.Type(), tx.Size())
		}
	}

	source, sourcePool := newNodeFilterHandler(t, nil)
	source.snapSync.Store(false)
	reveals := newRecordingGhostPool()
	sink, sinkPool := newNodeFilterHandler(t, reveals)
	sink.synced.Store(true)

	sourcePipe, sinkPipe := p2p.MsgPipe()
	defer sourcePipe.Close()
	defer sinkPipe.Close()
	sourcePeer := eth.NewPeer(eth.ETH68, p2p.NewPeerPipe(enode.ID{1}, "", nil, sourcePipe), sourcePipe, sourcePool)
	sinkPeer := eth.NewPeer(eth.ETH68, p2p.NewPeerPipe(enode.ID{2}, "", nil, sinkPipe), sinkPipe, sinkPool)
	defer sourcePeer.Close()
	defer sinkPeer.Close()
	go source.runEthPeer(sourcePeer, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(source), peer)
	})
	go sink.runEthPeer(sinkPeer, func(peer *eth.Peer) error {
		return eth.Handle((*ethHandler)(sink), peer)
	})

	arrived := make(chan core.NewTxsEvent, 16)
	sub := sinkPool.SubscribeTransactions(arrived, false)
	defer sub.Unsubscribe()
	sourcePool.Add(want, false, false)

	got := make(map[common.Hash]bool)
	timeout := time.After(10 * time.Second)
	for len(got) < len(want) {
		select {
		case ev := <-arrived:
			for _, tx := range ev.Txs {
				got[tx.Hash()] = true
			}
		case <-timeout:
			t.Fatalf("the second node fetched %d of the %d announced transactions", len(got), len(want))
		}
	}
	// Each reached the reveal pool with the peer it came from.
	reveals.mu.Lock()
	defer reveals.mu.Unlock()
	from := reveals.added[sinkPeer.ID()]
	if len(reveals.added) != 1 || len(from) != len(want) {
		t.Fatalf("reveal pool got %v, want the three from peer %s", reveals.added, sinkPeer.ID())
	}
	for _, tx := range want {
		found := false
		for _, h := range from {
			found = found || h == tx.Hash()
		}
		if !found {
			t.Fatalf("type %#x did not reach the reveal pool", tx.Type())
		}
	}
}
