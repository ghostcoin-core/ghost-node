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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/internal/cmdtest"
	"github.com/ethereum/go-ethereum/internal/reexec"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/rpc"
)

// The test binary never contacts the public test network's seed nodes: every
// geth it runs starts with no built-in seeds, except one run as
// "geth-test-seeds", whose first argument is the comma-separated list of
// local seeds that replaces the built-in one. The shipped geth has no such
// switch.
func init() {
	ghost.TestNetBootnodes = nil
	reexec.Register("geth-test-seeds", func() {
		if len(os.Args) < 2 {
			fmt.Fprintln(os.Stderr, "geth-test-seeds: no seed list")
			os.Exit(1)
		}
		if os.Args[1] != "" {
			ghost.TestNetBootnodes = strings.Split(os.Args[1], ",")
		}
		args := append([]string{"geth"}, os.Args[2:]...)
		if err := app.Run(args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	})
}

// localNetFlags are the only flags a "no flags" node gets: the operating
// system's choice of ports and no NAT, so tests can run side by side on one
// machine. None of them picks a network, a genesis or bootstrap nodes.
var localNetFlags = []string{"--port", "0", "--authrpc.port", "0", "--nat", "none"}

// testNode is a geth process with its IPC client.
type testNode struct {
	name string
	geth *testgeth
	rpc  *rpc.Client
}

// startTestNode starts geth on datadir, as "geth-test" or, with seeds not
// nil, as "geth-test-seeds" with seeds as its built-in seed list, and dials
// its IPC endpoint.
func startTestNode(t *testing.T, name, datadir string, seeds []string, args ...string) *testNode {
	t.Helper()
	args = append([]string{"--datadir", datadir}, args...)
	g := &testgeth{Datadir: datadir}
	g.TestCmd = cmdtest.NewTestCmd(t, g)
	if seeds == nil {
		g.Run("geth-test", args...)
	} else {
		g.Run("geth-test-seeds", append([]string{strings.Join(seeds, ",")}, args...)...)
	}
	n := &testNode{name: name, geth: g}
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
	n.rpc = client
	return n
}

// enode returns the node's enode URL on the loopback address.
func (n *testNode) enode(t *testing.T) (id, url string) {
	t.Helper()
	var info struct {
		ID    string `json:"id"`
		Ports struct {
			Listener int `json:"listener"`
		} `json:"ports"`
	}
	if err := n.rpc.Call(&info, "admin_nodeInfo"); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	if info.ID == "" || info.Ports.Listener == 0 {
		t.Fatalf("%s: node info has no ID or port: %+v", n.name, info)
	}
	return info.ID, fmt.Sprintf("enode://%s@127.0.0.1:%d", info.ID, info.Ports.Listener)
}

// chain returns the node's chain ID and genesis block hash.
func (n *testNode) chain(t *testing.T) (uint64, common.Hash) {
	t.Helper()
	var id hexutil.Uint64
	if err := n.rpc.Call(&id, "eth_chainId"); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	var genesis *blockRef
	if err := n.rpc.Call(&genesis, "eth_getBlockByNumber", "0x0", false); err != nil || genesis == nil {
		t.Fatalf("%s: no genesis block: %v", n.name, err)
	}
	return uint64(id), genesis.Hash
}

// ethPeers returns the IDs of the node's peers that run the eth protocol with
// it, which they do only after a handshake on the same genesis and network.
func (n *testNode) ethPeers(t *testing.T) map[string]bool {
	t.Helper()
	var peers []struct {
		ID        string         `json:"id"`
		Protocols map[string]any `json:"protocols"`
	}
	if err := n.rpc.Call(&peers, "admin_peers"); err != nil {
		t.Fatalf("%s: %v", n.name, err)
	}
	ids := make(map[string]bool)
	for _, p := range peers {
		if eth, ok := p.Protocols["eth"]; ok && eth != nil && eth != "handshake" {
			ids[p.ID] = true
		}
	}
	return ids
}

// checkTestNet fails the test unless the node runs the public test network.
func checkTestNet(t *testing.T, n *testNode) {
	t.Helper()
	id, genesis := n.chain(t)
	if id != ghost.TestNetChainID {
		t.Errorf("%s: chain ID %d, want the test network's %d", n.name, id, ghost.TestNetChainID)
	}
	if want := core.GenesisToBlock(ghost.TestNetGenesis(), nil).Hash(); genesis != want || genesis != ghost.TestNetGenesisHash {
		t.Errorf("%s: genesis %x, want the test network's %x", n.name, genesis, want)
	}
}

// waitForEthPeer waits until a and b run the eth protocol with each other.
func waitForEthPeer(t *testing.T, a, b *testNode) {
	t.Helper()
	idA, _ := a.enode(t)
	idB, _ := b.enode(t)
	waitFor(t, 2*time.Minute, a.name+" and "+b.name+" to peer", func() (bool, error) {
		return a.ethPeers(t)[idB] && b.ethPeers(t)[idA], nil
	})
}

// TestPublicTestNetFreshNodeJoinsSeed starts a local seed and then a node on
// an empty data directory with no network flags whose built-in seed list is
// that seed. The node writes the built-in genesis, finds the seed through
// discovery and peers with it on the eth protocol.
func TestPublicTestNetFreshNodeJoinsSeed(t *testing.T) {
	seed := startTestNode(t, "seed", t.TempDir(), nil, localNetFlags...)
	checkTestNet(t, seed)
	_, seedURL := seed.enode(t)

	fresh := startTestNode(t, "fresh", t.TempDir(), []string{seedURL}, localNetFlags...)
	checkTestNet(t, fresh)
	waitForEthPeer(t, fresh, seed)

	var network string
	if err := fresh.rpc.Call(&network, "net_version"); err != nil {
		t.Fatal(err)
	}
	if network != fmt.Sprint(ghost.TestNetChainID) {
		t.Errorf("network ID %s, want %d", network, ghost.TestNetChainID)
	}
}

// TestPublicTestNetBootnodesFlagOverrides checks that --bootnodes replaces the
// built-in seed list: the built-in list names a seed that is not running, and
// the node finds the seed --bootnodes names.
func TestPublicTestNetBootnodesFlagOverrides(t *testing.T) {
	seed := startTestNode(t, "seed", t.TempDir(), nil, localNetFlags...)
	seedID, seedURL := seed.enode(t)

	// A built-in seed with the real seed's ID at a port nothing listens on.
	dead := fmt.Sprintf("enode://%s@127.0.0.1:1", seedID)
	args := append([]string{"--bootnodes", seedURL}, localNetFlags...)
	fresh := startTestNode(t, "fresh", t.TempDir(), []string{dead}, args...)
	checkTestNet(t, fresh)
	waitForEthPeer(t, fresh, seed)
}

// TestPublicTestNetStoredChainKept checks that a data directory holding
// another chain keeps it when the node starts with no network flags: the
// built-in genesis is used only for a data directory holding none.
func TestPublicTestNetStoredChainKept(t *testing.T) {
	datadir := initDatadir(t, writeGenesis(t, ghost.InternalNetGenesis()))
	n := startTestNode(t, "internal", datadir, nil, localNetFlags...)
	id, genesis := n.chain(t)
	if id != ghost.InternalNetChainID {
		t.Errorf("chain ID %d, want the stored internal network's %d", id, ghost.InternalNetChainID)
	}
	if want := core.GenesisToBlock(ghost.InternalNetGenesis(), nil).Hash(); genesis != want {
		t.Errorf("genesis %x, want the stored internal network's %x", genesis, want)
	}
}

// TestPublicTestNetDevModeUnchanged checks that developer mode on an empty
// data directory still runs its own chain, not the test network.
func TestPublicTestNetDevModeUnchanged(t *testing.T) {
	geth := runGeth(t, "--dev", "--port", "0", "--authrpc.port", "0", "--maxpeers", "0", "--nodiscover",
		"--nat", "none", "--ipcdisable", "--exec", "eth.chainId()", "console")
	geth.KillTimeout = 3 * time.Minute
	geth.Expect(fmt.Sprintf("%q\n", hexutil.EncodeUint64(ghost.DeveloperChainID)))
	geth.ExpectExit()
}
