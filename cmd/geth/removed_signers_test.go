// Copyright 2026 The go-ethereum Authors
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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/node"
)

// TestRemovedSignerFlags checks that geth no longer offers the flags of the
// removed external signer and hardware-wallet backends.
func TestRemovedSignerFlags(t *testing.T) {
	removed := map[string]bool{"signer": true, "usb": true, "usb.pathid": true, "nousb": true, "pcscdpath": true}
	for _, flag := range app.Flags {
		for _, name := range flag.Names() {
			if removed[name] {
				t.Errorf("geth still has the removed flag --%s", name)
			}
		}
	}
}

// TestExternalSignerConfigRefused checks that a configuration still naming an
// external signer is refused instead of silently using another backend.
func TestExternalSignerConfigRefused(t *testing.T) {
	conf := &node.Config{ExternalSigner: "http://localhost:8550", UseLightweightKDF: true}
	am := accounts.NewManager(&accounts.Config{})
	defer am.Close()

	err := setAccountManagerBackends(conf, am, t.TempDir())
	if !errors.Is(err, errExternalSignerRemoved) {
		t.Fatalf("want errExternalSignerRemoved, got %v", err)
	}
	if n := len(am.Backends(keystore.KeyStoreType)); n != 0 {
		t.Fatalf("no backend may be registered when an external signer is configured, got %d", n)
	}
}

// TestLocalBackendOnly checks that without an external signer the node's own
// backend is registered and nothing else brings in wallets.
func TestLocalBackendOnly(t *testing.T) {
	conf := &node.Config{UseLightweightKDF: true}
	am := accounts.NewManager(&accounts.Config{})
	defer am.Close()

	if err := setAccountManagerBackends(conf, am, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if n := len(am.Backends(keystore.KeyStoreType)); n != 1 {
		t.Fatalf("want exactly one local backend, got %d", n)
	}
	if n := len(am.Wallets()); n != 0 {
		t.Fatalf("want no wallets in an empty directory, got %d", n)
	}
}

// TestOldHardwareWalletConfigFields checks that a config file written before
// the hardware-wallet backends were removed still loads.
func TestOldHardwareWalletConfigFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.toml")
	content := "[Node]\nNoUSB = true\nUSB = true\nSmartCardDaemonPath = \"/run/pcscd/pcscd.comm\"\n"
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var cfg gethConfig
	if err := loadConfig(file, &cfg); err != nil {
		t.Fatalf("old config file no longer loads: %v", err)
	}
}
