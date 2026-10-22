// Copyright 2026 The go-ethereum Authors
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

package keystore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// testAccountSigner signs account transactions of chain 1 bound to a test
// genesis.
var testAccountSigner = types.NewGhostAccountSigner(types.LatestSignerForChainID(big.NewInt(1)), common.Hash{0x01})

// testAccountTxData is an unsigned account transaction of chain 1.
func testAccountTxData() *types.GhostAccountTx {
	return &types.GhostAccountTx{
		ChainID:   big.NewInt(1),
		Nonce:     7,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       100000,
		To:        &common.Address{0x01},
		Value:     big.NewInt(3),
	}
}

// testMLDSAAccountOf returns the public key and the account address of the
// ML-DSA-44 key of seed, derived without the keystore.
func testMLDSAAccountOf(t *testing.T, seed []byte) ([]byte, common.Address) {
	t.Helper()
	var s [mldsa44.SeedSize]byte
	if copy(s[:], seed) != len(s) {
		t.Fatalf("seed of %d bytes", len(seed))
	}
	pub, _ := mldsa44.NewKeyFromSeed(&s)
	pubBytes := pub.Bytes()
	return pubBytes, types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pubBytes)
}

// fixtureAddress returns the address of the ML-DSA-44 key whose seed is 32
// bytes of b, derived without the keystore. The key files of testdata hold
// the seeds 0x0a (fixtureFileA and dupes/foo), 0x0b (aaa, no-address,
// no-scheme, other-scheme, dupes/1 and dupes/2), 0x0c (zzz), 0x0d (foo/) and
// 0x0e (very-light-scrypt.json, password ""); the others use the password
// "foobar".
func fixtureAddress(b byte) common.Address {
	var seed [mldsa44.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	pub, _ := mldsa44.NewKeyFromSeed(&seed)
	return types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes())
}

var (
	fixtureAddressA = fixtureAddress(0x0a)
	fixtureAddressB = fixtureAddress(0x0b)
	fixtureAddressC = fixtureAddress(0x0c)
	fixtureFileA    = "UTC--2026-10-21T09-00-00.000000000Z--" + hex.EncodeToString(fixtureAddressA[:])
)

// TestKeystoreCreatesMLDSA44Accounts checks that the keystore creates, lists,
// locks, unlocks and signs with ML-DSA-44 accounts: the key file keeps the
// password-encrypted layout around the 32-byte seed with the scheme field set
// to 1, the address is derived from the scheme and the public key, and a
// signed account transaction carries both and has the account as sender.
func TestKeystoreCreatesMLDSA44Accounts(t *testing.T) {
	t.Parallel()
	dir, ks := tmpKeyStore(t, true)

	acc, err := ks.NewMLDSAAccount("pass")
	if err != nil {
		t.Fatal(err)
	}

	// The key file.
	keyjson, err := os.ReadFile(acc.URL.Path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Address string                 `json:"address"`
		Crypto  map[string]interface{} `json:"crypto"`
		Version int                    `json:"version"`
		Scheme  *uint16                `json:"scheme"`
	}
	if err := json.Unmarshal(keyjson, &file); err != nil {
		t.Fatal(err)
	}
	if file.Scheme == nil || *file.Scheme != 1 {
		t.Fatalf("key file scheme field %v, want 1", file.Scheme)
	}
	if file.Version != 3 || file.Crypto["kdf"] != "scrypt" || file.Crypto["cipher"] != "aes-128-ctr" {
		t.Fatalf("key file version %d, KDF %v, cipher %v, want 3, scrypt and aes-128-ctr", file.Version, file.Crypto["kdf"], file.Crypto["cipher"])
	}
	if cipherText, _ := file.Crypto["ciphertext"].(string); len(cipherText) != 2*SeedSize {
		t.Fatalf("key file ciphertext has %d hex digits, want the %d of a seed", len(cipherText), 2*SeedSize)
	}
	if file.Address != hex.EncodeToString(acc.Address[:]) {
		t.Fatalf("key file address %s, want %x", file.Address, acc.Address)
	}
	key, err := DecryptKey(keyjson, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if key.PrivateKey != nil || len(key.Seed) != SeedSize {
		t.Fatalf("decrypted key holds a secp256k1 key or a seed of %d bytes", len(key.Seed))
	}
	pub, wantAddr := testMLDSAAccountOf(t, key.Seed)
	if acc.Address != wantAddr || key.Address != wantAddr {
		t.Fatalf("account address %x, key address %x, want %x", acc.Address, key.Address, wantAddr)
	}
	if _, err := DecryptKey(keyjson, "wrong"); err != ErrDecrypt {
		t.Fatalf("decrypting with a wrong password: error %v, want %v", err, ErrDecrypt)
	}

	// Listing.
	if accs := ks.Accounts(); len(accs) != 1 || accs[0] != acc {
		t.Fatalf("listed accounts %v, want [%v]", accs, acc)
	}
	wallets := ks.Wallets()
	if len(wallets) != 1 {
		t.Fatalf("%d wallets, want 1", len(wallets))
	}

	checkSigned := func(tx *types.Transaction, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if tx.Type() != types.GhostAccountTxType {
			t.Fatalf("signed transaction of type %#x, want %#x", tx.Type(), types.GhostAccountTxType)
		}
		scheme, pubKey, _, ok := tx.GhostAccountAuth()
		if !ok || scheme != types.GhostSchemeMLDSA44 {
			t.Fatalf("signed transaction has scheme %#04x (ok %v), want %#04x", scheme, ok, types.GhostSchemeMLDSA44)
		}
		if !bytes.Equal(pubKey, pub) {
			t.Fatal("signed transaction carries another public key than the account's")
		}
		if from, err := types.Sender(testAccountSigner, tx); err != nil || from != acc.Address {
			t.Fatalf("signed transaction has sender %x (error %v), want %x", from, err, acc.Address)
		}
		if tx.Nonce() != 7 || tx.Gas() != 100000 || tx.Value().Cmp(big.NewInt(3)) != 0 {
			t.Fatal("signed transaction does not carry the fields it was given")
		}
	}

	// Locked: only the password signs, and a wrong one is refused.
	if _, err := ks.SignAccountTx(acc, testAccountSigner, testAccountTxData()); err != ErrLocked {
		t.Fatalf("signing with a locked account: error %v, want %v", err, ErrLocked)
	}
	checkSigned(ks.SignAccountTxWithPassphrase(acc, "pass", testAccountSigner, testAccountTxData()))
	checkSigned(wallets[0].SignAccountTxWithPassphrase(acc, "pass", testAccountSigner, testAccountTxData()))
	if _, err := ks.SignAccountTxWithPassphrase(acc, "wrong", testAccountSigner, testAccountTxData()); err != ErrDecrypt {
		t.Fatalf("signing with a wrong password: error %v, want %v", err, ErrDecrypt)
	}

	// Unlocking and locking.
	if err := ks.Unlock(acc, "wrong"); err != ErrDecrypt {
		t.Fatalf("unlocking with a wrong password: error %v, want %v", err, ErrDecrypt)
	}
	if err := ks.Unlock(acc, "pass"); err != nil {
		t.Fatal(err)
	}
	if status, _ := wallets[0].Status(); status != "Unlocked" {
		t.Fatalf("wallet status %q after unlocking", status)
	}
	checkSigned(ks.SignAccountTx(acc, testAccountSigner, testAccountTxData()))
	checkSigned(wallets[0].SignAccountTx(acc, testAccountSigner, testAccountTxData()))

	// The key signs account transactions only.
	if _, err := ks.SignHash(acc, make([]byte, 32)); !errors.Is(err, ErrSignsAccountTxOnly) {
		t.Fatalf("SignHash: error %v, want %v", err, ErrSignsAccountTxOnly)
	}
	if _, err := wallets[0].SignData(acc, accounts.MimetypeTextPlain, []byte("text")); !errors.Is(err, ErrSignsAccountTxOnly) {
		t.Fatalf("SignData: error %v, want %v", err, ErrSignsAccountTxOnly)
	}
	if _, err := wallets[0].SignDataWithPassphrase(acc, "pass", accounts.MimetypeTextPlain, []byte("text")); !errors.Is(err, ErrSignsAccountTxOnly) {
		t.Fatalf("SignDataWithPassphrase: error %v, want %v", err, ErrSignsAccountTxOnly)
	}

	if err := ks.Lock(acc.Address); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.SignAccountTx(acc, testAccountSigner, testAccountTxData()); err != ErrLocked {
		t.Fatalf("signing after locking: error %v, want %v", err, ErrLocked)
	}

	// The key file survives a reopen of the keystore.
	reopened := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	if accs := reopened.Accounts(); len(accs) != 1 || accs[0] != acc {
		t.Fatalf("reopened keystore lists %v, want [%v]", accs, acc)
	}
	if err := reopened.Unlock(acc, "wrong"); err != ErrDecrypt {
		t.Fatalf("unlocking the reopened account with a wrong password: error %v, want %v", err, ErrDecrypt)
	}
	if err := reopened.Unlock(acc, "pass"); err != nil {
		t.Fatal(err)
	}
	checkSigned(reopened.SignAccountTx(acc, testAccountSigner, testAccountTxData()))

	// A plain key file of the key keeps its seed and scheme.
	_, plain := tmpKeyStoreIface(t, false)
	plainPath := plain.JoinPath("plain")
	if err := plain.StoreKey(plainPath, key, ""); err != nil {
		t.Fatal(err)
	}
	plainKey, err := plain.GetKey(acc.Address, plainPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainKey.Seed, key.Seed) || plainKey.Address != acc.Address {
		t.Fatal("plain key file does not keep the ML-DSA-44 key")
	}
}

// TestKeystoreImportSeedRejectsBadLength checks that ImportSeed refuses a seed
// that is not 32 bytes and stores no key file for it, and that a 32-byte
// seed gives the account derived from it.
func TestKeystoreImportSeedRejectsBadLength(t *testing.T) {
	t.Parallel()
	_, ks := tmpKeyStore(t, true)

	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := ks.ImportSeed(bytes.Repeat([]byte{0x21}, n), "pass"); !errors.Is(err, ErrSeedSize) {
			t.Errorf("seed of %d bytes: error %v, want %v", n, err, ErrSeedSize)
		}
	}
	if _, err := ks.ImportSeed(nil, "pass"); !errors.Is(err, ErrSeedSize) {
		t.Errorf("nil seed: error %v, want %v", err, ErrSeedSize)
	}
	if accs := ks.Accounts(); len(accs) != 0 {
		t.Fatalf("refused seeds left accounts %v", accs)
	}

	seed := bytes.Repeat([]byte{0x21}, SeedSize)
	acc, err := ks.ImportSeed(seed, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, want := testMLDSAAccountOf(t, seed); acc.Address != want {
		t.Fatalf("imported seed has address %x, want %x", acc.Address, want)
	}
	if _, err := ks.ImportSeed(seed, "other"); err != ErrAccountAlreadyExists {
		t.Fatalf("importing the seed twice: error %v, want %v", err, ErrAccountAlreadyExists)
	}
	if !bytes.Equal(seed, bytes.Repeat([]byte{0x21}, SeedSize)) {
		t.Fatal("ImportSeed changed the caller's seed")
	}
	tx, err := ks.SignAccountTxWithPassphrase(acc, "pass", testAccountSigner, testAccountTxData())
	if err != nil {
		t.Fatal(err)
	}
	if from, err := types.Sender(testAccountSigner, tx); err != nil || from != acc.Address {
		t.Fatalf("signed transaction has sender %x (error %v), want %x", from, err, acc.Address)
	}
}
