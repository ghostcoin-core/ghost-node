// Copyright 2017 The go-ethereum Authors
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

// This file contains the code snippets from the developer's guide embedded into
// Go tests. This ensures that any code published in out guides will not break
// accidentally via some code update. If some API changes nonetheless that needs
// modifying this file, please port any modification over into the developer's
// guide wiki pages too!

package guide

import (
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Tests that the account management snippets work correctly.
func TestAccountManagement(t *testing.T) {
	// Create a temporary folder to work with
	workdir := t.TempDir()

	// Create an encrypted keystore (using light scrypt parameters)
	ks := keystore.NewKeyStore(filepath.Join(workdir, "keystore"), keystore.LightScryptN, keystore.LightScryptP)

	// Create a new account with the specified encryption passphrase
	newAcc, err := ks.NewAccount("Creation password")
	if err != nil {
		t.Fatalf("Failed to create new account: %v", err)
	}
	// Export the newly created account with a different passphrase. The returned
	// data from this method invocation is a JSON encoded, encrypted key-file
	jsonAcc, err := ks.Export(newAcc, "Creation password", "Export password")
	if err != nil {
		t.Fatalf("Failed to export account: %v", err)
	}
	// Update the passphrase on the account created above inside the local keystore
	if err := ks.Update(newAcc, "Creation password", "Update password"); err != nil {
		t.Fatalf("Failed to update account: %v", err)
	}
	// Delete the account updated above from the local keystore
	if err := ks.Delete(newAcc, "Update password"); err != nil {
		t.Fatalf("Failed to delete account: %v", err)
	}
	// Import back the account we've exported (and then deleted) above with yet
	// again a fresh passphrase
	if _, err := ks.Import(jsonAcc, "Export password", "Import password"); err != nil {
		t.Fatalf("Failed to import account: %v", err)
	}
	// Import an ML-DSA-44 account key of a fixed seed to sign account
	// transactions with
	seed := make([]byte, keystore.SeedSize)
	for i := range seed {
		seed[i] = 0x71
	}
	signer, err := ks.ImportSeed(seed, "Signer password")
	if err != nil {
		t.Fatalf("Failed to import signer account: %v", err)
	}
	tx := &types.GhostAccountTx{
		ChainID:   big.NewInt(1),
		GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(0),
		To:        &common.Address{},
		Value:     big.NewInt(0),
	}
	// The signature of an account transaction is bound to the genesis hash of
	// its chain.
	chain := types.NewGhostAccountSigner(types.LatestSignerForChainID(big.NewInt(1)), common.HexToHash("0x01"))
	checkSender := func(signed *types.Transaction) {
		t.Helper()
		if from, err := types.Sender(chain, signed); err != nil || from != signer.Address {
			t.Fatalf("Signed transaction sender %x (%v), want %x", from, err, signer.Address)
		}
	}

	// Sign a transaction with a single authorization
	signed, err := ks.SignAccountTxWithPassphrase(signer, "Signer password", chain, tx)
	if err != nil {
		t.Fatalf("Failed to sign with passphrase: %v", err)
	}
	checkSender(signed)
	// Sign a transaction with multiple manually cancelled authorizations
	if err := ks.Unlock(signer, "Signer password"); err != nil {
		t.Fatalf("Failed to unlock account: %v", err)
	}
	if signed, err = ks.SignAccountTx(signer, chain, tx); err != nil {
		t.Fatalf("Failed to sign with unlocked account: %v", err)
	}
	checkSender(signed)
	if err := ks.Lock(signer.Address); err != nil {
		t.Fatalf("Failed to lock account: %v", err)
	}
	if _, err := ks.SignAccountTx(signer, chain, tx); err != keystore.ErrLocked {
		t.Fatalf("Signed with locked account: error %v, want %v", err, keystore.ErrLocked)
	}
	// Sign a transaction with multiple automatically cancelled authorizations
	if err := ks.TimedUnlock(signer, "Signer password", time.Second); err != nil {
		t.Fatalf("Failed to time unlock account: %v", err)
	}
	if signed, err = ks.SignAccountTx(signer, chain, tx); err != nil {
		t.Fatalf("Failed to sign with time unlocked account: %v", err)
	}
	checkSender(signed)
}
