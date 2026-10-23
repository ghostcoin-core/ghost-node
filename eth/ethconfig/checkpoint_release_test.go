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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
	"github.com/naoina/toml"
)

// checkpointFields lists the field names of t, and of the structs it embeds,
// that name a checkpoint. An embedded struct counts by the fields it
// promotes, not by its own type name.
func checkpointFields(t reflect.Type) []string {
	var found []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			found = append(found, checkpointFields(f.Type)...)
			continue
		}
		if strings.Contains(strings.ToLower(f.Name), "checkpoint") {
			found = append(found, f.Name)
		}
	}
	return found
}

// TestReleaseHasNoCheckpointOverride checks that a release build has no way to
// set a sync checkpoint or checkpoint oracle: Config has no such field, a
// configuration file naming one is refused, a chain configuration setting one
// is refused, the encoded configuration names none, and no command-line flag
// sets one.
func TestReleaseHasNoCheckpointOverride(t *testing.T) {
	if CheckpointsAllowed {
		t.Fatal("release build allows checkpoint settings")
	}
	if fields := checkpointFields(reflect.TypeOf(Config{})); len(fields) > 0 {
		t.Errorf("release Config has checkpoint fields: %v", fields)
	}

	// A configuration file that names a checkpoint key is refused, whatever
	// its value.
	files := map[string]string{
		"SyncFromCheckpoint true":  "SyncFromCheckpoint = true\n",
		"SyncFromCheckpoint false": "SyncFromCheckpoint = false\n",
		"Checkpoint":               "[Checkpoint]\nSectionIndex = 10\n",
		"empty Checkpoint":         "[Checkpoint]\n",
		"CheckpointOracle":         "[CheckpointOracle]\nThreshold = 2\n",
		"empty CheckpointOracle":   "[CheckpointOracle]\n",
	}
	for name, file := range files {
		cfg := Defaults
		err := toml.Unmarshal([]byte("NetworkId = 7\n"+file), &cfg)
		if err == nil {
			t.Errorf("%s: configuration accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), errCheckpointConfigured.Error()) {
			t.Errorf("%s: refused with %q, want %q", name, err, errCheckpointConfigured)
		}
	}
	// A configuration without them still loads.
	cfg := Defaults
	if err := toml.Unmarshal([]byte("NetworkId = 7\n"), &cfg); err != nil {
		t.Fatalf("configuration without checkpoint settings refused: %v", err)
	}
	if cfg.NetworkId != 7 {
		t.Errorf("NetworkId = %d, want 7", cfg.NetworkId)
	}

	// The encoded configuration, as dumpconfig writes it (Config as a field,
	// so through MarshalTOML), names no checkpoint. Encoding Config directly
	// reflects over its fields and must name none either.
	for name, v := range map[string]interface{}{
		"as field": &struct{ Eth Config }{Eth: cfg},
		"direct":   &cfg,
	} {
		out, err := toml.Marshal(v)
		if err != nil {
			t.Fatalf("encode configuration %s: %v", name, err)
		}
		if strings.Contains(strings.ToLower(string(out)), "checkpoint") {
			t.Errorf("encoded configuration %s names a checkpoint:\n%s", name, out)
		}
	}

	// A chain configuration's trusted checkpoint or oracle is refused, and a
	// chain configuration without one gives no checkpoint.
	checkpoint := &ctypes.TrustedCheckpoint{SectionIndex: 10, SectionHead: common.Hash{1}}
	oracle := &ctypes.CheckpointOracleConfig{Address: common.Address{1}, Threshold: 2}
	chains := map[string]ctypes.ChainConfigurator{
		"core-geth checkpoint":     &coregeth.CoreGethChainConfig{TrustedCheckpoint: checkpoint},
		"core-geth oracle":         &coregeth.CoreGethChainConfig{TrustedCheckpointOracle: oracle},
		"go-ethereum checkpoint":   &goethereum.ChainConfig{TrustedCheckpoint: checkpoint},
		"go-ethereum oracle":       &goethereum.ChainConfig{TrustedCheckpointOracle: oracle},
		"core-geth empty settings": &coregeth.CoreGethChainConfig{TrustedCheckpoint: &ctypes.TrustedCheckpoint{}, TrustedCheckpointOracle: &ctypes.CheckpointOracleConfig{}},
	}
	for name, chain := range chains {
		got, err := cfg.SyncCheckpoint(chain)
		if err == nil {
			t.Errorf("%s: chain configuration accepted", name)
		}
		if got != nil {
			t.Errorf("%s: sync checkpoint %v, want none", name, got)
		}
	}
	for name, chain := range map[string]ctypes.ChainConfigurator{
		"core-geth":   &coregeth.CoreGethChainConfig{},
		"go-ethereum": &goethereum.ChainConfig{},
	} {
		got, err := cfg.SyncCheckpoint(chain)
		if err != nil || got != nil {
			t.Errorf("%s without checkpoint: got %v, %v; want none and no error", name, got, err)
		}
	}

	// No command-line flag of the node sets a checkpoint.
	flagName := regexp.MustCompile(`(?i)(Name|Aliases)\s*:[^\n]*checkpoint`)
	for _, dir := range []string{"../../cmd/utils", "../../cmd/geth"} {
		sources, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sources) == 0 {
			t.Fatalf("no sources in %s", dir)
		}
		for _, path := range sources {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if loc := flagName.FindIndex(src); loc != nil {
				t.Errorf("%s has a checkpoint flag: %s", path, src[loc[0]:loc[1]])
			}
		}
	}
}
