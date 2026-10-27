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
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// isStaleTestNetChain reports whether a stored chain is the public test
// network from before a reset: its genesis exists, its stored chain ID is the
// public test network's, and its genesis hash is not the built-in one. Any
// other chain ID (the internal network, developer mode, any other network)
// and the built-in genesis itself are never stale.
func isStaleTestNetChain(storedHash common.Hash, storedChainID *big.Int) bool {
	if storedHash == (common.Hash{}) || storedChainID == nil {
		return false
	}
	if !storedChainID.IsUint64() || storedChainID.Uint64() != ghost.TestNetChainID {
		return false
	}
	return storedHash != ghost.TestNetGenesisHash
}

// runsBuiltInTestNet reports whether the node is configured to run the
// built-in public test network: no genesis given (an explicit genesis and
// developer mode set one) and no network ID other than the test network's
// (developer mode, including its fallback to the stored chain, sets 1337).
func runsBuiltInTestNet(config *ethconfig.Config) bool {
	if config.Genesis != nil {
		return false
	}
	return config.NetworkId == 0 || config.NetworkId == ghost.TestNetChainID
}

// moveStaleTestNetChain moves a public test network chain left from before a
// reset aside, so the node starts on the built-in genesis instead of mining
// alone on the old chain. It must run before the chain database is opened.
// The chain data, and its freezer if that lies outside it, are renamed to a
// dated sibling folder, never deleted; the keystore and node key are not
// touched. It returns the folder the chain data was moved to, or "" if
// nothing was moved.
func moveStaleTestNetChain(stack *node.Node, config *ethconfig.Config, now time.Time) (string, error) {
	if stack.DataDir() == "" || !runsBuiltInTestNet(config) {
		return "", nil
	}
	chaindata := stack.ResolvePath("chaindata")
	if rawdb.PreexistingDatabase(chaindata) == "" {
		return "", nil
	}
	ancient := stack.ResolveAncient("chaindata", config.DatabaseFreezer)

	db, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "", true)
	if err != nil {
		// Leave the decision to the normal open, which reports the error.
		log.Debug("Could not inspect the stored chain for a test network reset", "err", err)
		return "", nil
	}
	storedHash := rawdb.ReadCanonicalHash(db, 0)
	var storedChainID *big.Int
	if storedHash != (common.Hash{}) {
		if cfg := rawdb.ReadChainConfig(db, storedHash); cfg != nil {
			storedChainID = cfg.GetChainID()
		}
	}
	if err := db.Close(); err != nil {
		return "", fmt.Errorf("closing the stored chain: %w", err)
	}
	if !isStaleTestNetChain(storedHash, storedChainID) {
		return "", nil
	}

	// A freezer outside the chain data moves to its own sibling folder.
	var movedAncient string
	if !isWithin(ancient, chaindata) {
		if _, err := os.Stat(ancient); err == nil {
			movedAncient, err = freeSibling(ancient, now)
			if err != nil {
				return "", err
			}
			if err := os.Rename(ancient, movedAncient); err != nil {
				return "", fmt.Errorf("moving the old test network freezer aside: %w", err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	moved, err := freeSibling(chaindata, now)
	if err == nil {
		err = os.Rename(chaindata, moved)
	}
	if err != nil {
		if movedAncient != "" {
			// Put the freezer back so the old chain stays whole.
			if rerr := os.Rename(movedAncient, ancient); rerr != nil {
				log.Error("Could not put the old test network freezer back", "from", movedAncient, "to", ancient, "err", rerr)
			}
		}
		return "", fmt.Errorf("moving the old test network chain aside: %w", err)
	}
	if movedAncient != "" {
		log.Warn("The public test network was reset: moved the old chain aside and starting on the new genesis", "old", storedHash, "new", ghost.TestNetGenesisHash, "folder", moved, "freezer", movedAncient)
	} else {
		log.Warn("The public test network was reset: moved the old chain aside and starting on the new genesis", "old", storedHash, "new", ghost.TestNetGenesisHash, "folder", moved)
	}
	return moved, nil
}

// freeSibling returns a dated sibling path of dir that does not exist yet,
// such as chaindata.old-2026-10-27, with a numeric suffix if that is taken.
func freeSibling(dir string, now time.Time) (string, error) {
	base := dir + ".old-" + now.UTC().Format("2006-01-02")
	for i := 1; ; i++ {
		candidate := base
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d", base, i)
		}
		_, err := os.Lstat(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
}

// isWithin reports whether path is dir or lies inside it.
func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
