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

//go:build ghostrelease

package ethconfig

import (
	"errors"

	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
)

// CheckpointsAllowed reports whether a sync checkpoint or checkpoint oracle
// can be configured in this build. Release builds leave the settings out, so
// the node syncs only by verifying the chain from genesis.
const CheckpointsAllowed = false

// checkpointConfig is empty in release builds: Config has no checkpoint
// settings.
type checkpointConfig struct{}

// errCheckpointConfigured is returned for a configuration that sets a sync
// checkpoint or checkpoint oracle in a release build.
var errCheckpointConfigured = errors.New("release builds take no sync checkpoint: remove SyncFromCheckpoint, Checkpoint and CheckpointOracle from the configuration")

// errChainCheckpointConfigured is returned for a chain configuration that
// sets a trusted checkpoint or checkpoint oracle in a release build.
var errChainCheckpointConfigured = errors.New("release builds take no sync checkpoint: remove trustedCheckpoint and trustedCheckpointOracle from the chain configuration")

// checkpointSettings returns no checkpoint settings: release builds have none.
func (c *Config) checkpointSettings() (bool, *ctypes.TrustedCheckpoint, *ctypes.CheckpointOracleConfig) {
	return false, nil, nil
}

// setCheckpointSettings refuses a configuration file that names any
// checkpoint setting, whatever its value.
func (c *Config) setCheckpointSettings(sync *bool, checkpoint *ctypes.TrustedCheckpoint, oracle *ctypes.CheckpointOracleConfig) error {
	if sync != nil || checkpoint != nil || oracle != nil {
		return errCheckpointConfigured
	}
	return nil
}

// SyncCheckpoint returns no checkpoint, and an error for a chain
// configuration that sets one.
func (c *Config) SyncCheckpoint(chain ctypes.ChainConfigurator) (*ctypes.TrustedCheckpoint, error) {
	switch p := chain.(type) {
	case *coregeth.CoreGethChainConfig:
		if p.TrustedCheckpoint != nil || p.TrustedCheckpointOracle != nil {
			return nil, errChainCheckpointConfigured
		}
	case *goethereum.ChainConfig:
		if p.TrustedCheckpoint != nil || p.TrustedCheckpointOracle != nil {
			return nil, errChainCheckpointConfigured
		}
	}
	return nil, nil
}
