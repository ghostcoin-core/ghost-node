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

package keystore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
)

// testSigner signs account transactions of chain 1 bound to a test genesis.
var testSigner = types.NewGhostAccountSigner(types.LatestSignerForChainID(big.NewInt(1)), common.Hash{0x01})

// testTxData is an unsigned account transaction of chain 1.
func testTxData() *types.GhostAccountTx {
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

// testSign signs testTxData with the unlocked key of a.
func testSign(ks *KeyStore, a accounts.Account) (*types.Transaction, error) {
	return ks.SignAccountTx(a, testSigner, testTxData())
}

// testSeed returns the test seed of 32 bytes b.
func testSeed(b byte) []byte {
	return bytes.Repeat([]byte{b}, SeedSize)
}

// testKey returns the account key of testSeed(b).
func testKey(b byte) *Key {
	key, err := newKeyFromSeed(testSeed(b), uuid.New())
	if err != nil {
		panic(err)
	}
	return key
}

// writeTestKeyFile writes the encrypted key file of testKey(seed) to path,
// with edit applied to its JSON fields when given.
func writeTestKeyFile(path string, seed byte, pass string, edit func(map[string]interface{})) (accounts.Account, error) {
	key := testKey(seed)
	keyjson, err := EncryptKey(key, pass, veryLightScryptN, veryLightScryptP)
	if err != nil {
		return accounts.Account{}, err
	}
	if edit != nil {
		m := make(map[string]interface{})
		if err := json.Unmarshal(keyjson, &m); err != nil {
			return accounts.Account{}, err
		}
		edit(m)
		if keyjson, err = json.Marshal(m); err != nil {
			return accounts.Account{}, err
		}
	}
	if err := os.WriteFile(path, keyjson, 0600); err != nil {
		return accounts.Account{}, err
	}
	return accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: path}}, nil
}

// TestKeystoreCreatesMLDSA44Accounts checks that the keystore creates, lists,
// unlocks and signs with ML-DSA-44 accounts: the key file keeps the
// password-encrypted layout around the 32-byte seed and carries the scheme
// field set to 1, the address is derived from the scheme and the public key,
// and an unlocked or password-given account signs an account transaction
// that verifies with its key.
func TestKeystoreCreatesMLDSA44Accounts(t *testing.T) {
	t.Parallel()
	dir, ks := tmpKeyStore(t, true)

	acc, err := ks.NewAccount("pass")
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
	if file.Version != 3 || file.Crypto["kdf"] != "scrypt" {
		t.Fatalf("key file version %d, KDF %v, want 3 and scrypt", file.Version, file.Crypto["kdf"])
	}
	cipherText, _ := file.Crypto["ciphertext"].(string)
	if n := len(cipherText); n != 2*SeedSize {
		t.Fatalf("key file ciphertext has %d hex digits, want the %d of a seed", n, 2*SeedSize)
	}
	if file.Address != hex.EncodeToString(acc.Address[:]) {
		t.Fatalf("key file address %s, want %x", file.Address, acc.Address)
	}
	key, err := DecryptKey(keyjson, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(key.PublicKey()) != types.GhostMLDSA44PublicKeySize {
		t.Fatalf("public key of %d bytes, want %d", len(key.PublicKey()), types.GhostMLDSA44PublicKeySize)
	}
	if want := types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, key.PublicKey()); acc.Address != want || key.Address != want {
		t.Fatalf("account address %x, key address %x, want the derived %x", acc.Address, key.Address, want)
	}
	if key.PrivateKey != nil {
		t.Fatal("decrypted key holds a secp256k1 key")
	}

	// Listing, in a second keystore over the same directory.
	ks2 := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	if accs := ks2.Accounts(); len(accs) != 1 || accs[0] != acc {
		t.Fatalf("listed accounts %v, want [%v]", accs, acc)
	}

	// Signing with the password, without unlocking.
	checkSigned := func(tx *types.Transaction, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if tx.Type() != types.GhostAccountTxType {
			t.Fatalf("signed transaction of type %#x, want %#x", tx.Type(), types.GhostAccountTxType)
		}
		scheme, pub, _, ok := tx.GhostAccountAuth()
		if !ok || scheme != types.GhostSchemeMLDSA44 || !bytes.Equal(pub, key.PublicKey()) {
			t.Fatalf("signed transaction has scheme %#04x and another public key", scheme)
		}
		if from, err := types.Sender(testSigner, tx); err != nil || from != acc.Address {
			t.Fatalf("signed transaction has sender %x (error %v), want %x", from, err, acc.Address)
		}
		if tx.Nonce() != 7 || tx.Gas() != 100000 || tx.Value().Cmp(big.NewInt(3)) != 0 {
			t.Fatal("signed transaction does not carry the fields it was given")
		}
	}
	if _, err := testSign(ks, acc); err != ErrLocked {
		t.Fatalf("signing with a locked account: error %v, want %v", err, ErrLocked)
	}
	checkSigned(ks.SignAccountTxWithPassphrase(acc, "pass", testSigner, testTxData()))
	if _, err := ks.SignAccountTxWithPassphrase(acc, "wrong", testSigner, testTxData()); err != ErrDecrypt {
		t.Fatalf("signing with a wrong password: error %v, want %v", err, ErrDecrypt)
	}
	wallets := ks.Wallets()
	if len(wallets) != 1 {
		t.Fatalf("%d wallets, want 1", len(wallets))
	}
	checkSigned(wallets[0].SignAccountTxWithPassphrase(acc, "pass", testSigner, testTxData()))

	// Unlocking and locking.
	if err := ks.Unlock(acc, "wrong"); err != ErrDecrypt {
		t.Fatalf("unlocking with a wrong password: error %v, want %v", err, ErrDecrypt)
	}
	if err := ks.Unlock(acc, "pass"); err != nil {
		t.Fatal(err)
	}
	checkSigned(testSign(ks, acc))
	checkSigned(wallets[0].SignAccountTx(acc, testSigner, testTxData()))
	if err := ks.Lock(acc.Address); err != nil {
		t.Fatal(err)
	}
	if _, err := testSign(ks, acc); err != ErrLocked {
		t.Fatalf("signing after locking: error %v, want %v", err, ErrLocked)
	}

	// A signer that does not take account transactions is refused.
	if err := ks.Unlock(acc, "pass"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.SignAccountTx(acc, types.LatestSignerForChainID(big.NewInt(1)), testTxData()); err == nil {
		t.Fatal("signed with a signer that takes no account transactions")
	}
	// Nothing else is signed.
	if _, err := ks.SignHash(acc, make([]byte, 32)); !errors.Is(err, ErrNotAccountTx) {
		t.Fatalf("SignHash: error %v, want %v", err, ErrNotAccountTx)
	}
	legacy := types.NewTransaction(0, common.Address{}, new(big.Int), 21000, new(big.Int), nil)
	if _, err := ks.SignTx(acc, legacy, big.NewInt(1)); !errors.Is(err, ErrNotAccountTx) {
		t.Fatalf("SignTx: error %v, want %v", err, ErrNotAccountTx)
	}
	if _, err := ks.SignTxWithPassphrase(acc, "pass", legacy, big.NewInt(1)); !errors.Is(err, ErrNotAccountTx) {
		t.Fatalf("SignTxWithPassphrase: error %v, want %v", err, ErrNotAccountTx)
	}
	if _, err := wallets[0].SignData(acc, accounts.MimetypeTextPlain, []byte("text")); !errors.Is(err, ErrNotAccountTx) {
		t.Fatalf("SignData: error %v, want %v", err, ErrNotAccountTx)
	}

	// Importing a seed gives its account; export and import keep it.
	_, ks3 := tmpKeyStore(t, true)
	imported, err := ks3.ImportSeed(testSeed(0x31), "import")
	if err != nil {
		t.Fatal(err)
	}
	if want := testKey(0x31).Address; imported.Address != want {
		t.Fatalf("imported seed has address %x, want %x", imported.Address, want)
	}
	exported, err := ks3.Export(imported, "import", "export")
	if err != nil {
		t.Fatal(err)
	}
	reimported, err := ks.Import(exported, "export", "again")
	if err != nil {
		t.Fatal(err)
	}
	if reimported.Address != imported.Address {
		t.Fatalf("reimported account %x, want %x", reimported.Address, imported.Address)
	}
	checkSignedBy := func(a accounts.Account) {
		t.Helper()
		tx, err := ks.SignAccountTxWithPassphrase(a, "again", testSigner, testTxData())
		if err != nil {
			t.Fatal(err)
		}
		if from, err := types.Sender(testSigner, tx); err != nil || from != a.Address {
			t.Fatalf("sender %x (error %v), want %x", from, err, a.Address)
		}
	}
	checkSignedBy(reimported)
}

// TestKeystoreRefusesECDSAKeys checks that a key file holding a secp256k1
// key is refused: one without the scheme field is not listed, and cannot be
// imported or unlocked; one with a scheme field added is refused when it is
// unlocked or imported, as its address is not the address of the key it
// holds. A key file of another scheme and a version 1 key file are refused
// as well.
func TestKeystoreRefusesECDSAKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// The secp256k1 key file aaa of testdata/keystore, password "foobar".
	ecdsaJSON, err := os.ReadFile(filepath.Join("testdata", "keystore", "aaa"))
	if err != nil {
		t.Fatal(err)
	}
	ecdsaAddr := common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a")
	if err := os.WriteFile(filepath.Join(dir, "ecdsa"), ecdsaJSON, 0600); err != nil {
		t.Fatal(err)
	}
	// The same file with a scheme field set to 1.
	m := make(map[string]interface{})
	if err := json.Unmarshal(ecdsaJSON, &m); err != nil {
		t.Fatal(err)
	}
	m["scheme"] = 1
	withScheme, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	withSchemePath := filepath.Join(dir, "ecdsa-with-scheme")
	if err := os.WriteFile(withSchemePath, withScheme, 0600); err != nil {
		t.Fatal(err)
	}
	// An ML-DSA-44 key file of another scheme.
	otherScheme := func(m map[string]interface{}) { m["scheme"] = 2 }
	other, err := writeTestKeyFile(filepath.Join(dir, "other-scheme"), 0x41, "foobar", otherScheme)
	if err != nil {
		t.Fatal(err)
	}
	// And a good one.
	good, err := writeTestKeyFile(filepath.Join(dir, "good"), 0x42, "foobar", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Listing: the file without a scheme and the one of another scheme are
	// not listed; the one with a scheme field cannot be told apart without
	// its password.
	ks := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	listed := make(map[string]accounts.Account)
	for _, a := range ks.Accounts() {
		listed[filepath.Base(a.URL.Path)] = a
	}
	if _, ok := listed["ecdsa"]; ok {
		t.Error("secp256k1 key file without a scheme is listed")
	}
	if _, ok := listed["other-scheme"]; ok {
		t.Error("key file of scheme 2 is listed")
	}
	if a, ok := listed["good"]; !ok || a != good {
		t.Errorf("ML-DSA-44 key file not listed: %v", listed)
	}
	if _, ok := listed["ecdsa-with-scheme"]; !ok || len(listed) != 2 {
		t.Errorf("listed %v, want the ML-DSA-44 key file and the one with a scheme field", listed)
	}

	// Unlocking.
	if err := ks.Unlock(accounts.Account{Address: ecdsaAddr, URL: accounts.URL{Scheme: KeyStoreScheme, Path: filepath.Join(dir, "ecdsa")}}, "foobar"); err == nil {
		t.Error("unlocked a secp256k1 key file without a scheme")
	}
	if err := ks.Unlock(accounts.Account{Address: ecdsaAddr, URL: accounts.URL{Scheme: KeyStoreScheme, Path: withSchemePath}}, "foobar"); !errors.Is(err, ErrNotAccountKey) {
		t.Errorf("unlocking a secp256k1 key file with a scheme field: error %v, want %v", err, ErrNotAccountKey)
	}
	if err := ks.Unlock(other, "foobar"); err == nil {
		t.Error("unlocked a key file of scheme 2")
	}
	if _, err := ks.SignAccountTxWithPassphrase(accounts.Account{Address: ecdsaAddr, URL: accounts.URL{Scheme: KeyStoreScheme, Path: withSchemePath}}, "foobar", testSigner, testTxData()); !errors.Is(err, ErrNotAccountKey) {
		t.Errorf("signing with a secp256k1 key file: error %v, want %v", err, ErrNotAccountKey)
	}
	if err := ks.Unlock(good, "foobar"); err != nil {
		t.Errorf("unlocking the ML-DSA-44 key file: %v", err)
	}

	// Importing, into an empty keystore.
	_, ks2 := tmpKeyStore(t, true)
	for name, keyjson := range map[string][]byte{"no scheme": ecdsaJSON, "scheme field": withScheme} {
		if _, err := ks2.Import(keyjson, "foobar", "new"); !errors.Is(err, ErrNotAccountKey) {
			t.Errorf("importing a secp256k1 key file (%s): error %v, want %v", name, err, ErrNotAccountKey)
		}
		if _, err := DecryptKey(keyjson, "foobar"); !errors.Is(err, ErrNotAccountKey) {
			t.Errorf("decrypting a secp256k1 key file (%s): error %v, want %v", name, err, ErrNotAccountKey)
		}
	}
	otherJSON, err := os.ReadFile(other.URL.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks2.Import(otherJSON, "foobar", "new"); !errors.Is(err, ErrNotAccountKey) {
		t.Errorf("importing a key file of scheme 2: error %v, want %v", err, ErrNotAccountKey)
	}
	v1JSON, err := os.ReadFile(filepath.Join("testdata", "v1", "cb61d5a9c4896fb9658090b597ef0e7be6f7b67e", "cb61d5a9c4896fb9658090b597ef0e7be6f7b67e"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks2.Import(v1JSON, "g", "new"); !errors.Is(err, ErrNotAccountKey) {
		t.Errorf("importing a version 1 key file: error %v, want %v", err, ErrNotAccountKey)
	}
	if accs := ks2.Accounts(); len(accs) != 0 {
		t.Errorf("refused imports left accounts %v", accs)
	}

	// The plain key store refuses a secp256k1 key as well.
	plainDir := t.TempDir()
	plainFile := filepath.Join(plainDir, "plain")
	plainJSON := `{"address":"` + hex.EncodeToString(ecdsaAddr[:]) + `","privatekey":"` + hex.EncodeToString(testSeed(0x43)) + `","id":"` + uuid.NewString() + `","version":3}`
	if err := os.WriteFile(plainFile, []byte(plainJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (keyStorePlain{plainDir}).GetKey(ecdsaAddr, plainFile, ""); !errors.Is(err, ErrNotAccountKey) {
		t.Errorf("plain secp256k1 key file: error %v, want %v", err, ErrNotAccountKey)
	}
}
