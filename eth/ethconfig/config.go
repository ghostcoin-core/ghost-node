// Copyright 2021 The go-ethereum Authors
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

// Package ethconfig contains the configuration of the ETH and LES protocols.
package ethconfig

import (
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// FullNodeGPO contains default gasprice oracle settings for full node.
var FullNodeGPO = gasprice.Config{
	Blocks:           20,
	Percentile:       60,
	MaxHeaderHistory: 1024,
	MaxBlockHistory:  1024,
	MaxPrice:         gasprice.DefaultMaxPrice,
	IgnorePrice:      gasprice.DefaultIgnorePrice,
}

// Defaults contains default settings for use on the Ethereum main net.
var Defaults = Config{
	SyncMode: downloader.SnapSync,
	Ethash: ethash.Config{
		CacheDir:         "ethash",
		CachesInMem:      2,
		CachesOnDisk:     3,
		CachesLockMmap:   false,
		DatasetsInMem:    1,
		DatasetsOnDisk:   2,
		DatasetsLockMmap: false,
	},
	NetworkId:          0, // enable auto configuration of networkID == chainID
	ProtocolVersions:   vars.DefaultProtocolVersions,
	TxLookupLimit:      2350000,
	TransactionHistory: 2350000,
	StateHistory:       vars.FullImmutabilityThreshold,
	LightPeers:         100,
	UltraLightFraction: 75,
	DatabaseCache:      512,
	TrieCleanCache:     154,
	TrieDirtyCache:     256,
	TrieTimeout:        60 * time.Minute,
	SnapshotCache:      102,
	FilterLogCacheSize: 32,
	Miner:              miner.DefaultConfig,
	TxPool:             legacypool.DefaultConfig,
	BlobPool:           blobpool.DefaultConfig,
	RPCGasCap:          50000000,
	RPCEVMTimeout:      5 * time.Second,
	GPO:                FullNodeGPO,
	RPCTxFeeCap:        1, // 1 ether
}

func init() {
	home := os.Getenv("HOME")
	if home == "" {
		if user, err := user.Current(); err == nil {
			home = user.HomeDir
		}
	}
	if runtime.GOOS == "darwin" {
		Defaults.Ethash.DatasetDir = filepath.Join(home, "Library", "Ethash")
	} else if runtime.GOOS == "windows" {
		localappdata := os.Getenv("LOCALAPPDATA")
		if localappdata != "" {
			Defaults.Ethash.DatasetDir = filepath.Join(localappdata, "Ethash")
		} else {
			Defaults.Ethash.DatasetDir = filepath.Join(home, "AppData", "Local", "Ethash")
		}
	} else {
		Defaults.Ethash.DatasetDir = filepath.Join(home, ".ethash")
	}
}

//go:generate go run github.com/fjl/gencodec -type Config -formats toml -out gen_config.go

// Config contains configuration options for ETH and LES protocols.
type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the Ethereum main net block is used.
	Genesis *genesisT.Genesis `toml:",omitempty"`

	// Protocol options
	NetworkId        uint64 // Network ID to use for selecting peers to connect to. When 0, chainID is used.
	ProtocolVersions []uint // Protocol versions are the supported versions of the eth protocol (first is primary).
	SyncMode         downloader.SyncMode

	NoPruning  bool // Whether to disable pruning and flush everything to disk
	NoPrefetch bool // Whether to disable prefetching and only load state on demand

	// Deprecated, use 'TransactionHistory' instead.
	TxLookupLimit      uint64 `toml:",omitempty"` // The maximum number of blocks from head whose tx indices are reserved.
	TransactionHistory uint64 `toml:",omitempty"` // The maximum number of blocks from head whose tx indices are reserved.
	StateHistory       uint64 `toml:",omitempty"` // The maximum number of blocks from head whose state histories are reserved.

	// State scheme represents the scheme used to store ethereum states and trie
	// nodes on top. It can be 'hash', 'path', or none which means use the scheme
	// consistent with persistent state.
	StateScheme string `toml:",omitempty"`

	// RequiredBlocks is a set of block number -> hash mappings which must be in the
	// canonical chain of all remote peers. Setting the option makes geth verify the
	// presence of these blocks for every new peer connection.
	RequiredBlocks map[uint64]common.Hash `toml:"-"`

	// Light client options
	LightServ        int  `toml:",omitempty"` // Maximum percentage of time allowed for serving LES requests
	LightIngress     int  `toml:",omitempty"` // Incoming bandwidth limit for light servers
	LightEgress      int  `toml:",omitempty"` // Outgoing bandwidth limit for light servers
	LightPeers       int  `toml:",omitempty"` // Maximum number of LES client peers
	LightNoPrune     bool `toml:",omitempty"` // Whether to disable light chain pruning
	LightNoSyncServe bool `toml:",omitempty"` // Whether to serve light clients before syncing

	// Ultra Light client options
	UltraLightServers      []string `toml:",omitempty"` // List of trusted ultra light servers
	UltraLightFraction     int      `toml:",omitempty"` // Percentage of trusted servers to accept an announcement
	UltraLightOnlyAnnounce bool     `toml:",omitempty"` // Whether to only announce headers, or also serve them

	// Database options
	SkipBcVersionCheck    bool `toml:"-"`
	DatabaseHandles       int  `toml:"-"`
	DatabaseCache         int
	DatabaseFreezer       string
	DatabaseFreezerRemote string

	TrieCleanCache int
	TrieDirtyCache int
	TrieTimeout    time.Duration
	SnapshotCache  int
	Preimages      bool

	// This is the number of blocks for which logs will be cached in the filter system.
	FilterLogCacheSize int

	// Mining options
	Miner miner.Config

	// Ethash options
	Ethash ethash.Config

	// Transaction pool options
	TxPool   legacypool.Config
	BlobPool blobpool.Config

	// Gas Price Oracle options
	GPO gasprice.Config

	// Enables tracking of SHA3 preimages in the VM
	EnablePreimageRecording bool

	// Miscellaneous options
	DocRoot string `toml:"-"`

	// Type of the EWASM interpreter ("" for default)
	EWASMInterpreter string

	// Type of the EVM interpreter ("" for default)
	EVMInterpreter string

	// RPCGasCap is the global gas cap for eth-call variants.
	RPCGasCap uint64

	// RPCEVMTimeout is the global timeout for eth-call.
	RPCEVMTimeout time.Duration

	// RPCTxFeeCap is the global transaction fee(price * gaslimit) cap for
	// send-transaction variants. The unit is ether.
	RPCTxFeeCap float64

	// Checkpoint settings (SyncFromCheckpoint, Checkpoint, CheckpointOracle):
	// see checkpoint.go. Release builds have none, and their TOML decoding in
	// gen_config.go refuses a file that names one. The TOML encoder must not
	// reflect over this unexported field; MarshalTOML writes the settings.
	checkpointConfig `toml:"-"`
}

// ConsensusChainID returns the chain ID that picks a chain's consensus
// parameters: the configuration's chain ID or, for a configuration without
// one, its network ID, as core-geth configurations take one for the other.
// A non-zero networkID, the --networkid flag, overrides the configuration's.
func ConsensusChainID(config ctypes.ChainConfigurator, networkID uint64) *big.Int {
	if id := config.GetChainID(); id != nil {
		return id
	}
	if networkID == 0 {
		if id := config.GetNetworkID(); id != nil {
			networkID = *id
		}
	}
	return new(big.Int).SetUint64(networkID)
}

// consensusParams returns the RandomX consensus constants of a chain, by its
// chain ID. Only the public test network, the internal test network and
// developer mode have them; the launch genesis adds its own entry.
func consensusParams(chainID *big.Int) (ghostrules.Params, error) {
	if chainID != nil && chainID.IsUint64() {
		switch chainID.Uint64() {
		case ghost.TestNetChainID:
			return ghost.TestNetParams(), nil
		case ghost.InternalNetChainID, ghost.DeveloperChainID:
			return ghost.InternalNetParams(), nil
		}
	}
	return ghostrules.Params{}, fmt.Errorf("no consensus parameters for chain ID %v: this node runs only the public test network (%d), the internal network (%d) and developer mode (%d)", chainID, ghost.TestNetChainID, ghost.InternalNetChainID, ghost.DeveloperChainID)
}

// CreateConsensusEngine creates a consensus engine for the given chain
// configuration. A proof-of-work chain runs RandomX with the consensus
// parameters of its chain ID, and a chain ID without parameters is an error.
// The ethash test modes keep their ethash engines, outside release builds.
func CreateConsensusEngine(stack *node.Node, ethashConfig *ethash.Config, cliqueConfig *ctypes.CliqueConfig, chainID *big.Int, notify []string, noverify bool, db ethdb.Database) (consensus.Engine, error) {
	// If proof-of-authority is requested, set it up
	var engine consensus.Engine
	if cliqueConfig != nil {
		engine = clique.New(cliqueConfig, db)
	} else {
		if !ethash.FakeSealsAllowed {
			switch ethashConfig.PowMode {
			case ethash.ModeFake, ethash.ModePoissonFake, ethash.ModeFullFake, ethash.ModeTest:
				log.Crit("Fake and test proof-of-work modes are not available in release builds", "mode", ethashConfig.PowMode)
			}
			if noverify {
				log.Crit("Release builds always verify mined work; --miner.noverify is not available")
			}
		}
		switch ethashConfig.PowMode {
		case ethash.ModeFake:
			log.Warn("Ethash used in fake mode")
			engine = ethash.NewFaker()
		case ethash.ModeTest:
			log.Warn("Ethash used in test mode")
			engine = ethash.NewTester(nil, noverify)
		case ethash.ModeShared:
			log.Warn("Ethash used in shared mode")
			engine = ethash.NewShared()
		case ethash.ModePoissonFake:
			log.Warn("Ethash used in fake Poisson mode")
			engine = ethash.NewPoissonFaker()
		case ethash.ModeFullFake:
			log.Warn("Ethash used in full fake mode")
			engine = ethash.New(ethash.Config{PowMode: ethash.ModeFullFake}, nil, false)
		default:
			params, err := consensusParams(chainID)
			if err != nil {
				return nil, err
			}
			if len(notify) > 0 {
				log.Warn("RandomX has no remote sealer; ignoring the work notification URLs", "urls", notify)
			}
			if noverify {
				log.Warn("RandomX always verifies mined work; ignoring --miner.noverify")
			}
			rx, err := randomx.New(randomx.Config{Params: params})
			if err != nil {
				return nil, err
			}
			rx.SetThreads(-1) // Disable CPU mining
			engine = rx
		}
	}

	return engine, nil
}
