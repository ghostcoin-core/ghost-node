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
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/triedb"
)

var resetDay = time.Date(2026, 10, 27, 20, 0, 0, 0, time.UTC)

// staleTestNetGenesis is a public test network genesis from before a reset:
// the same chain ID, another genesis time, so another hash.
func staleTestNetGenesis() *genesisT.Genesis {
	g := ghost.TestNetGenesis()
	g.Timestamp = ghost.TestNetTimestamp - 86400
	return g
}

func TestTestNetResetDecision(t *testing.T) {
	other := common.HexToHash("0x01")
	tests := []struct {
		name    string
		hash    common.Hash
		chainID *big.Int
		want    bool
	}{
		{"old test network chain", other, big.NewInt(ghost.TestNetChainID), true},
		{"current test network chain", ghost.TestNetGenesisHash, big.NewInt(ghost.TestNetChainID), false},
		{"no stored genesis", common.Hash{}, big.NewInt(ghost.TestNetChainID), false},
		{"no stored chain config", other, nil, false},
		{"internal network", other, big.NewInt(ghost.InternalNetChainID), false},
		{"developer mode", other, big.NewInt(ghost.DeveloperChainID), false},
		{"other network", other, big.NewInt(1), false},
		{"chain id beyond 64 bits", other, new(big.Int).Lsh(big.NewInt(ghost.TestNetChainID), 64), false},
	}
	for _, tt := range tests {
		if got := isStaleTestNetChain(tt.hash, tt.chainID); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := isStaleTestNetChain(staleTestNetGenesisHash(), big.NewInt(ghost.TestNetChainID)); !got {
		t.Errorf("a test network genesis with another time is not taken for an old chain")
	}
}

func staleTestNetGenesisHash() common.Hash {
	return core.GenesisToBlock(staleTestNetGenesis(), nil).Hash()
}

func newResetTestNode(t *testing.T, dir string) *node.Node {
	t.Helper()
	stack, err := node.New(&node.Config{DataDir: dir, Name: "geth"})
	if err != nil {
		t.Fatalf("creating node: %v", err)
	}
	t.Cleanup(func() { stack.Close() })
	return stack
}

// writeChain stores g as the genesis of the node's chain database.
func writeChain(t *testing.T, stack *node.Node, config *ethconfig.Config, g *genesisT.Genesis) common.Hash {
	t.Helper()
	db, err := stack.OpenDatabaseWithFreezer("chaindata", 16, 16, config.DatabaseFreezer, "", false)
	if err != nil {
		t.Fatalf("opening chain database: %v", err)
	}
	defer db.Close()
	block, err := core.CommitGenesis(g, db, triedb.NewDatabase(db, nil))
	if err != nil {
		t.Fatalf("writing genesis: %v", err)
	}
	return block.Hash()
}

// storedGenesis returns the stored genesis hash of the chain database at dir.
func storedGenesis(t *testing.T, dir, ancient string) common.Hash {
	t.Helper()
	db, err := rawdb.Open(rawdb.OpenOptions{Directory: dir, AncientsDirectory: ancient, Cache: 16, Handles: 16, ReadOnly: true})
	if err != nil {
		t.Fatalf("opening %s: %v", dir, err)
	}
	defer db.Close()
	return rawdb.ReadCanonicalHash(db, 0)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func checkFile(t *testing.T, path, content string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is gone: %v", path, err)
	}
	if string(got) != content {
		t.Fatalf("%s changed: %q", path, got)
	}
}

func TestTestNetResetMovesOldChainAside(t *testing.T) {
	dir := t.TempDir()
	stack := newResetTestNode(t, dir)
	config := &ethconfig.Config{DatabaseCache: 16, DatabaseHandles: 16}
	oldHash := writeChain(t, stack, config, staleTestNetGenesis())

	keyfile := filepath.Join(dir, "keystore", "fake-key-file")
	nodekey := stack.ResolvePath("nodekey")
	writeFile(t, keyfile, "fake keystore content")
	writeFile(t, nodekey, "fake node key")

	moved, err := moveStaleTestNetChain(stack, config, resetDay)
	if err != nil {
		t.Fatalf("moving the old chain: %v", err)
	}
	chaindata := stack.ResolvePath("chaindata")
	if want := chaindata + ".old-2026-10-27"; moved != want {
		t.Fatalf("moved to %q, want %q", moved, want)
	}
	if _, err := os.Stat(chaindata); !os.IsNotExist(err) {
		t.Fatalf("chain data still in place: %v", err)
	}
	if got := storedGenesis(t, moved, filepath.Join(moved, "ancient")); got != oldHash {
		t.Fatalf("moved folder holds genesis %x, want the old %x", got, oldHash)
	}
	checkFile(t, keyfile, "fake keystore content")
	checkFile(t, nodekey, "fake node key")

	// The node now starts on the built-in genesis.
	db, err := stack.OpenDatabaseWithFreezer("chaindata", 16, 16, "", "", false)
	if err != nil {
		t.Fatalf("opening the new chain database: %v", err)
	}
	_, hash, err := core.SetupGenesisBlock(db, triedb.NewDatabase(db, nil), nil)
	db.Close()
	if err != nil {
		t.Fatalf("setting up genesis: %v", err)
	}
	if hash != ghost.TestNetGenesisHash {
		t.Fatalf("started on %x, want the built-in %x", hash, ghost.TestNetGenesisHash)
	}
	// Starting again on the new chain moves nothing.
	if again, err := moveStaleTestNetChain(stack, config, resetDay); err != nil || again != "" {
		t.Fatalf("the current chain was moved: %q, %v", again, err)
	}
}

func TestTestNetResetAddsSuffixWhenFolderExists(t *testing.T) {
	dir := t.TempDir()
	stack := newResetTestNode(t, dir)
	config := &ethconfig.Config{DatabaseCache: 16, DatabaseHandles: 16}
	chaindata := stack.ResolvePath("chaindata")
	writeFile(t, filepath.Join(chaindata+".old-2026-10-27", "earlier"), "an earlier reset")
	writeChain(t, stack, config, staleTestNetGenesis())

	moved, err := moveStaleTestNetChain(stack, config, resetDay)
	if err != nil {
		t.Fatalf("moving the old chain: %v", err)
	}
	if want := chaindata + ".old-2026-10-27-2"; moved != want {
		t.Fatalf("moved to %q, want %q", moved, want)
	}
	checkFile(t, filepath.Join(chaindata+".old-2026-10-27", "earlier"), "an earlier reset")
}

func TestTestNetResetMovesExternalFreezer(t *testing.T) {
	dir := t.TempDir()
	stack := newResetTestNode(t, dir)
	ancient := filepath.Join(t.TempDir(), "freezer")
	config := &ethconfig.Config{DatabaseCache: 16, DatabaseHandles: 16, DatabaseFreezer: ancient}
	oldHash := writeChain(t, stack, config, staleTestNetGenesis())

	moved, err := moveStaleTestNetChain(stack, config, resetDay)
	if err != nil {
		t.Fatalf("moving the old chain: %v", err)
	}
	if moved == "" {
		t.Fatal("old chain not moved")
	}
	if _, err := os.Stat(ancient); !os.IsNotExist(err) {
		t.Fatalf("freezer still in place: %v", err)
	}
	movedAncient := ancient + ".old-2026-10-27"
	if got := storedGenesis(t, moved, movedAncient); got != oldHash {
		t.Fatalf("moved folders hold genesis %x, want the old %x", got, oldHash)
	}
}

func TestTestNetResetLeavesOtherChains(t *testing.T) {
	tests := []struct {
		name    string
		genesis *genesisT.Genesis
		config  ethconfig.Config
	}{
		{"current test network", ghost.TestNetGenesis(), ethconfig.Config{}},
		{"internal network", ghost.InternalNetGenesis(), ethconfig.Config{}},
		{"developer chain", params.DeveloperGenesisBlock(11_500_000, &common.Address{1}), ethconfig.Config{}},
		// Developer mode falling back to a stored chain gives no genesis
		// but network ID 1337.
		{"developer mode on an old test network chain", staleTestNetGenesis(), ethconfig.Config{NetworkId: 1337}},
		{"explicit genesis", staleTestNetGenesis(), ethconfig.Config{Genesis: staleTestNetGenesis()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			stack := newResetTestNode(t, dir)
			config := tt.config
			config.DatabaseCache, config.DatabaseHandles = 16, 16
			hash := writeChain(t, stack, &config, tt.genesis)

			moved, err := moveStaleTestNetChain(stack, &config, resetDay)
			if err != nil || moved != "" {
				t.Fatalf("chain moved: %q, %v", moved, err)
			}
			chaindata := stack.ResolvePath("chaindata")
			if got := storedGenesis(t, chaindata, filepath.Join(chaindata, "ancient")); got != hash {
				t.Fatalf("stored genesis %x, want %x", got, hash)
			}
		})
	}
}

func TestTestNetResetEmptyDataDir(t *testing.T) {
	stack := newResetTestNode(t, t.TempDir())
	config := &ethconfig.Config{DatabaseCache: 16, DatabaseHandles: 16}
	if moved, err := moveStaleTestNetChain(stack, config, resetDay); err != nil || moved != "" {
		t.Fatalf("empty data directory: %q, %v", moved, err)
	}
}
