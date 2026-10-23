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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/naoina/toml"
)

// TestCheckpointSettingsOutsideRelease checks that builds other than release
// builds keep reading the checkpoint settings, and prefer the configured
// checkpoint to the chain configuration's.
func TestCheckpointSettingsOutsideRelease(t *testing.T) {
	if !CheckpointsAllowed {
		t.Fatal("checkpoint settings left out of a non-release build")
	}
	cfg := Defaults
	file := "SyncFromCheckpoint = true\n[Checkpoint]\nSectionIndex = 10\n[CheckpointOracle]\nThreshold = 2\n"
	if err := toml.Unmarshal([]byte(file), &cfg); err != nil {
		t.Fatalf("configuration refused: %v", err)
	}
	if !cfg.SyncFromCheckpoint {
		t.Error("SyncFromCheckpoint not set")
	}
	if cfg.Checkpoint == nil || cfg.Checkpoint.SectionIndex != 10 {
		t.Errorf("Checkpoint = %+v, want section 10", cfg.Checkpoint)
	}
	if cfg.CheckpointOracle == nil || cfg.CheckpointOracle.Threshold != 2 {
		t.Errorf("CheckpointOracle = %+v, want threshold 2", cfg.CheckpointOracle)
	}

	chainCheckpoint := &ctypes.TrustedCheckpoint{SectionIndex: 3, SectionHead: common.Hash{3}}
	chain := &coregeth.CoreGethChainConfig{TrustedCheckpoint: chainCheckpoint}
	if got, err := cfg.SyncCheckpoint(chain); err != nil || got != cfg.Checkpoint {
		t.Errorf("SyncCheckpoint = %v, %v; want the configured checkpoint", got, err)
	}
	if got, err := Defaults.SyncCheckpoint(chain); err != nil || got != chainCheckpoint {
		t.Errorf("SyncCheckpoint without a configured one = %v, %v; want the chain's", got, err)
	}
}
