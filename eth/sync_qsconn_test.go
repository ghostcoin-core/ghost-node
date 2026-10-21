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
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/internal/testlog"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/qsconn"
)

// startQSConnServer runs the eth protocol of h on a p2p server that has only
// a quantum-safe identity: no secp256k1 key.
func startQSConnServer(t *testing.T, name string, h *testHandler, static ...*enode.Node) (*p2p.Server, *qsconn.Identity) {
	t.Helper()
	key, err := qsconn.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	srv := &p2p.Server{Config: p2p.Config{
		Name:        name,
		Identity:    key,
		MaxPeers:    10,
		NoDiscovery: true,
		ListenAddr:  "127.0.0.1:0",
		StaticNodes: static,
		Protocols:   eth.MakeProtocols((*ethHandler)(h.handler), 1, []uint{eth.ETH68}, nil),
		Logger:      testlog.Logger(t, log.LvlInfo).New("server", name),
	}}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return srv, key
}

// TestSyncOverQSConn connects two nodes with the quantum-safe handshake only
// and syncs a short chain over the eth protocol.
func TestSyncOverQSConn(t *testing.T) {
	const blocks = 32
	full := newTestHandlerWithBlocksWithOpts(blocks, downloader.FullSync, nil)
	defer full.close()
	empty := newTestHandlerWithBlocksWithOpts(0, downloader.FullSync, nil)
	defer empty.close()

	fullSrv, fullKey := startQSConnServer(t, "full", full)
	if fullSrv.PrivateKey != nil {
		t.Fatal("server has a secp256k1 key")
	}
	// The empty node knows the full one only by its 64 hex chars URL.
	fullNode, err := enode.ParseV4(fullSrv.Self().URLv4())
	if err != nil {
		t.Fatal(err)
	}
	if fullNode.ID() != enode.ID(fullKey.ID()) {
		t.Fatalf("URL names %v, want %v", fullNode.ID(), fullKey.ID())
	}
	emptySrv, emptyKey := startQSConnServer(t, "empty", empty, fullNode)

	// Wait for the eth handshake on both sides.
	deadline := time.Now().Add(20 * time.Second)
	for empty.handler.peers.len() == 0 || full.handler.peers.len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("eth peers not registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p := empty.handler.peers.peer(fullKey.ID().String()); p == nil {
		t.Fatal("empty node's eth peer is not the full node's quantum-safe ID")
	}
	if p := full.handler.peers.peer(emptyKey.ID().String()); p == nil {
		t.Fatal("full node's eth peer is not the empty node's quantum-safe ID")
	}
	for _, p := range append(emptySrv.Peers(), fullSrv.Peers()...) {
		if p.Node().Pubkey() != nil {
			t.Fatal("peer identified by a secp256k1 key")
		}
	}

	op := peerToSyncOp(downloader.FullSync, empty.handler.peers.peerWithHighestTD())
	if err := empty.handler.doSync(op); err != nil {
		// The handler's own sync loop may have started first.
		t.Logf("sync: %v", err)
	}
	for empty.chain.CurrentBlock().Number.Uint64() != blocks {
		if time.Now().After(deadline) {
			t.Fatalf("empty node at block %d, want %d", empty.chain.CurrentBlock().Number.Uint64(), blocks)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if empty.chain.CurrentBlock().Hash() != full.chain.CurrentBlock().Hash() {
		t.Fatal("synced head differs from the full node's head")
	}
}
