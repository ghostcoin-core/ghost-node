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

//go:build !ghostrelease

package ethconfig

import (
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
)

// CheckpointsAllowed reports whether a sync checkpoint or checkpoint oracle
// can be configured in this build. Release builds, made with the ghostrelease
// build tag, leave the settings out.
const CheckpointsAllowed = true

// checkpointConfig holds the checkpoint settings of Config. Release builds
// replace it with an empty struct, so the fields do not exist there.
type checkpointConfig struct {
	SyncFromCheckpoint bool `toml:",omitempty"` // Whether to sync the header chain from the configured checkpoint

	// Checkpoint is a hardcoded checkpoint which can be nil.
	Checkpoint *ctypes.TrustedCheckpoint `toml:",omitempty"`

	// CheckpointOracle is the configuration for checkpoint oracle.
	CheckpointOracle *ctypes.CheckpointOracleConfig `toml:",omitempty"`
}

// checkpointSettings returns the checkpoint settings, for encoding.
func (c *Config) checkpointSettings() (bool, *ctypes.TrustedCheckpoint, *ctypes.CheckpointOracleConfig) {
	return c.SyncFromCheckpoint, c.Checkpoint, c.CheckpointOracle
}

// setCheckpointSettings stores the checkpoint settings a configuration file
// names; a nil value leaves its setting as it is.
func (c *Config) setCheckpointSettings(sync *bool, checkpoint *ctypes.TrustedCheckpoint, oracle *ctypes.CheckpointOracleConfig) error {
	if sync != nil {
		c.SyncFromCheckpoint = *sync
	}
	if checkpoint != nil {
		c.Checkpoint = checkpoint
	}
	if oracle != nil {
		c.CheckpointOracle = oracle
	}
	return nil
}

// SyncCheckpoint returns the checkpoint the node syncs against: the
// configured one or, without one, the chain configuration's. It can be nil.
func (c *Config) SyncCheckpoint(chain ctypes.ChainConfigurator) (*ctypes.TrustedCheckpoint, error) {
	if c.Checkpoint != nil {
		return c.Checkpoint, nil
	}
	switch p := chain.(type) {
	case *coregeth.CoreGethChainConfig:
		return p.TrustedCheckpoint, nil
	case *goethereum.ChainConfig:
		return p.TrustedCheckpoint, nil
	}
	return nil, nil
}
