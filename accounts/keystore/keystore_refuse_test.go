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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
)

// ecdsaFixtureAddress is the address of the secp256k1 key of
// testdata/ecdsa-key.json and testdata/ecdsa-key-with-scheme.json (password
// "foobar").
var ecdsaFixtureAddress = common.HexToAddress("f466859ead1932d743d622cb74fc058882e8648a")

// readFixture returns the content of a file of testdata.
func readFixture(t *testing.T, path ...string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, path...)...))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// listDir returns the names of the files in dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestKeystoreRefusesECDSAKeys checks that a secp256k1 key file, a key file
// without the scheme field, a key file of another scheme, a version 1 key file
// and a presale wallet are not listed by the keystore and are refused to
// import and to unlock, next to a valid ML-DSA-44 key file that is listed and
// unlocks.
func TestKeystoreRefusesECDSAKeys(t *testing.T) {
	t.Parallel()

	var (
		ecdsaJSON       = readFixture(t, "ecdsa-key.json")
		ecdsaSchemeJSON = readFixture(t, "ecdsa-key-with-scheme.json")
		noSchemeJSON    = readFixture(t, "keystore", "no-scheme")
		otherSchemeJSON = readFixture(t, "keystore", "other-scheme")
		v1JSON          = readFixture(t, "v1", "cb61d5a9c4896fb9658090b597ef0e7be6f7b67e", "cb61d5a9c4896fb9658090b597ef0e7be6f7b67e")
		validJSON       = readFixture(t, "keystore", "aaa")
		presaleJSON     = []byte(`{"encseed": "26d87f5f2bf9835f9a47eefae571bc09f9107bb13d54ff12a4ec095d01f83897", "ethaddr": "d4584b5f6229b7be90727b0fc8c6b91bb427821f", "email": "test@example.com", "btcaddr": "test"}`)
		plainECDSAJSON  = []byte(`{"address":"f466859ead1932d743d622cb74fc058882e8648a","privatekey":"` + strings.Repeat("11", 32) + `","id":"472e8b3d-afb6-45b5-8111-72c89895099a","version":3}`)
	)
	refused := map[string][]byte{
		"ecdsa":        ecdsaJSON,
		"no-scheme":    noSchemeJSON,
		"other-scheme": otherSchemeJSON,
		"v1":           v1JSON,
		"presale":      presaleJSON,
	}

	// Listing: only the ML-DSA-44 key file is listed.
	dir := t.TempDir()
	for name, content := range refused {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	validPath := filepath.Join(dir, "valid")
	if err := os.WriteFile(validPath, validJSON, 0600); err != nil {
		t.Fatal(err)
	}
	ks := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	valid := accounts.Account{Address: fixtureAddressB, URL: accounts.URL{Scheme: KeyStoreScheme, Path: validPath}}
	if accs := ks.Accounts(); len(accs) != 1 || accs[0] != valid {
		t.Fatalf("listed %v, want only the ML-DSA-44 account %v", accs, valid)
	}
	if ks.HasAddress(ecdsaFixtureAddress) {
		t.Fatal("the secp256k1 key file is listed")
	}
	if n := len(ks.Wallets()); n != 1 {
		t.Fatalf("%d wallets, want 1", n)
	}

	// Unlocking: the refused files are found neither by address nor by path.
	for name := range refused {
		path := filepath.Join(dir, name)
		if err := ks.Unlock(accounts.Account{URL: accounts.URL{Scheme: KeyStoreScheme, Path: path}}, "foobar"); err != ErrNoMatch {
			t.Errorf("unlocking %s by path: error %v, want %v", name, err, ErrNoMatch)
		}
	}
	if err := ks.Unlock(accounts.Account{Address: ecdsaFixtureAddress}, "foobar"); err != ErrNoMatch {
		t.Errorf("unlocking the secp256k1 account by address: error %v, want %v", err, ErrNoMatch)
	}
	if err := ks.Unlock(valid, "foobar"); err != nil {
		t.Fatalf("unlocking the ML-DSA-44 account: %v", err)
	}

	// Reading the files directly is refused before the password is tried.
	storage := ks.storage
	if _, err := storage.GetKey(ecdsaFixtureAddress, filepath.Join(dir, "ecdsa"), "foobar"); !errors.Is(err, ErrNoKeyScheme) {
		t.Errorf("reading the secp256k1 key file: error %v, want %v", err, ErrNoKeyScheme)
	}
	if _, err := storage.GetKey(fixtureAddressB, filepath.Join(dir, "no-scheme"), "foobar"); !errors.Is(err, ErrNoKeyScheme) {
		t.Errorf("reading the key file without scheme: error %v, want %v", err, ErrNoKeyScheme)
	}
	if _, err := storage.GetKey(fixtureAddressB, filepath.Join(dir, "other-scheme"), "foobar"); !errors.Is(err, ErrKeyScheme) {
		t.Errorf("reading the key file of another scheme: error %v, want %v", err, ErrKeyScheme)
	}
	plainDir := t.TempDir()
	plainPath := filepath.Join(plainDir, "plain-ecdsa")
	if err := os.WriteFile(plainPath, plainECDSAJSON, 0600); err != nil {
		t.Fatal(err)
	}
	plain := NewPlaintextKeyStore(plainDir)
	if accs := plain.Accounts(); len(accs) != 0 {
		t.Errorf("plaintext keystore lists the secp256k1 key file: %v", accs)
	}
	if _, err := plain.storage.GetKey(ecdsaFixtureAddress, plainPath, ""); !errors.Is(err, ErrNoKeyScheme) {
		t.Errorf("reading the plain secp256k1 key file: error %v, want %v", err, ErrNoKeyScheme)
	}

	// Importing: every refused file and the secp256k1 key file with a scheme
	// field are refused, and nothing is written.
	importDir := t.TempDir()
	importKs := NewKeyStore(importDir, veryLightScryptN, veryLightScryptP)
	refused["ecdsa-with-scheme"] = ecdsaSchemeJSON
	for name, content := range refused {
		if acc, err := importKs.Import(content, "foobar", "new"); err == nil {
			t.Errorf("importing %s succeeded with account %v", name, acc)
		}
		if key, err := DecryptKey(content, "foobar"); err == nil {
			t.Errorf("decrypting %s succeeded with address %x", name, key.Address)
		}
	}
	for _, name := range []string{"ecdsa", "no-scheme", "presale"} {
		if _, err := importKs.Import(refused[name], "foobar", "new"); !errors.Is(err, ErrNoKeyScheme) {
			t.Errorf("importing %s: error %v, want %v", name, err, ErrNoKeyScheme)
		}
	}
	if names := listDir(t, importDir); len(names) != 0 {
		t.Fatalf("refused imports left files %v", names)
	}
	if accs := importKs.Accounts(); len(accs) != 0 {
		t.Fatalf("refused imports left accounts %v", accs)
	}

	// A secp256k1 key file with a scheme field is listed by its address
	// field, but its key is not the ML-DSA-44 key of that address: unlocking
	// it is refused.
	schemeDir := t.TempDir()
	schemePath := filepath.Join(schemeDir, "ecdsa-with-scheme")
	if err := os.WriteFile(schemePath, ecdsaSchemeJSON, 0600); err != nil {
		t.Fatal(err)
	}
	schemeKs := NewKeyStore(schemeDir, veryLightScryptN, veryLightScryptP)
	if err := schemeKs.Unlock(accounts.Account{Address: ecdsaFixtureAddress}, "foobar"); err == nil {
		t.Fatal("unlocking the secp256k1 key file with a scheme field succeeded")
	}
	if _, err := schemeKs.SignAccountTxWithPassphrase(accounts.Account{Address: ecdsaFixtureAddress}, "foobar", testAccountSigner, testAccountTxData()); err == nil {
		t.Fatal("signing with the secp256k1 key file with a scheme field succeeded")
	}

	// The valid file imports.
	acc, err := importKs.Import(validJSON, "foobar", "new")
	if err != nil {
		t.Fatalf("importing the ML-DSA-44 key file: %v", err)
	}
	if acc.Address != fixtureAddressB {
		t.Fatalf("imported address %x, want %x", acc.Address, fixtureAddressB)
	}
}

// TestKeystoreHasNoECDSAEntryPoints checks that every way the keystore writes
// a key file writes an ML-DSA-44 key file with "scheme":1, that the keystore
// and the wallet interface have no method left that creates, imports or signs
// with a secp256k1 key, and that what remains of the old signing refuses.
func TestKeystoreHasNoECDSAEntryPoints(t *testing.T) {
	t.Parallel()

	// Every new key file has the scheme field set to 1.
	dir := t.TempDir()
	ks := NewKeyStore(dir, veryLightScryptN, veryLightScryptP)
	created, err := ks.NewMLDSAAccount("pass")
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := ks.ImportSeed(bytes.Repeat([]byte{0x42}, SeedSize), "pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Update(seeded, "pass", "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := StoreKey(dir, "pass", veryLightScryptN, veryLightScryptP); err != nil {
		t.Fatal(err)
	}
	exported, err := ks.Export(created, "pass", "new")
	if err != nil {
		t.Fatal(err)
	}
	importDir := t.TempDir()
	if _, err := NewKeyStore(importDir, veryLightScryptN, veryLightScryptP).Import(exported, "new", "new"); err != nil {
		t.Fatal(err)
	}
	plainDir := t.TempDir()
	if _, err := NewPlaintextKeyStore(plainDir).NewMLDSAAccount(""); err != nil {
		t.Fatal(err)
	}

	checkFile := func(path string) {
		t.Helper()
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(content, []byte(`"scheme":1`)) {
			t.Errorf("key file %s has no \"scheme\":1: %s", path, content)
		}
		var file struct {
			Scheme     *uint16 `json:"scheme"`
			PrivateKey string  `json:"privatekey"`
		}
		if err := json.Unmarshal(content, &file); err != nil {
			t.Fatal(err)
		}
		if file.Scheme == nil || *file.Scheme != MLDSAScheme {
			t.Errorf("key file %s has scheme %v, want %d", path, file.Scheme, MLDSAScheme)
		}
		if _, err := DecryptKey(content, "pass"); err != nil && err != ErrDecrypt && filepath.Dir(path) != plainDir {
			t.Errorf("key file %s does not decrypt as an ML-DSA-44 key: %v", path, err)
		}
	}
	var files int
	for _, d := range []string{dir, importDir, plainDir} {
		for _, name := range listDir(t, d) {
			checkFile(filepath.Join(d, name))
			files++
		}
	}
	if files != 5 {
		t.Fatalf("%d key files written, want 5", files)
	}

	// A key without an ML-DSA-44 seed is not written.
	if _, err := EncryptKey(&Key{Address: common.Address{0x01}}, "pass", veryLightScryptN, veryLightScryptP); !errors.Is(err, ErrNotMLDSAKey) {
		t.Errorf("encrypting a key without a seed: error %v, want %v", err, ErrNotMLDSAKey)
	}
	if _, err := json.Marshal(&Key{Address: common.Address{0x01}}); err == nil {
		t.Error("encoding a key without a seed as a plain key file succeeded")
	}

	// No secp256k1 entry point is left on the keystore or the wallet.
	ksType := reflect.TypeOf(&KeyStore{})
	for _, name := range []string{
		"NewAccount", "ImportECDSA", "ImportPreSaleKey",
		"SignHashWithPassphrase", "SignTx", "SignTxWithPassphrase",
		"SignText", "SignTextWithPassphrase",
	} {
		if _, ok := ksType.MethodByName(name); ok {
			t.Errorf("KeyStore has the method %s", name)
		}
	}
	walletType := reflect.TypeOf((*accounts.Wallet)(nil)).Elem()
	for _, name := range []string{"SignTx", "SignTxWithPassphrase", "SignText", "SignTextWithPassphrase"} {
		if _, ok := walletType.MethodByName(name); ok {
			t.Errorf("accounts.Wallet has the method %s", name)
		}
	}
	for _, name := range []string{"NewMLDSAAccount", "ImportSeed", "SignAccountTx", "SignAccountTxWithPassphrase"} {
		if _, ok := ksType.MethodByName(name); !ok {
			t.Errorf("KeyStore lacks the method %s", name)
		}
	}

	// What is left of the old signing refuses, unlocked or not.
	if err := ks.Unlock(created, "pass"); err != nil {
		t.Fatal(err)
	}
	if sig, err := ks.SignHash(created, make([]byte, 32)); !errors.Is(err, ErrSignsAccountTxOnly) || sig != nil {
		t.Errorf("SignHash: signature %x, error %v, want %v", sig, err, ErrSignsAccountTxOnly)
	}
	var wallet accounts.Wallet
	for _, w := range ks.Wallets() {
		if w.Contains(created) {
			wallet = w
		}
	}
	if wallet == nil {
		t.Fatal("no wallet holds the created account")
	}
	if sig, err := wallet.SignData(created, accounts.MimetypeTextPlain, []byte("data")); !errors.Is(err, ErrSignsAccountTxOnly) || sig != nil {
		t.Errorf("SignData: signature %x, error %v, want %v", sig, err, ErrSignsAccountTxOnly)
	}
	if sig, err := wallet.SignDataWithPassphrase(created, "pass", accounts.MimetypeTextPlain, []byte("data")); !errors.Is(err, ErrSignsAccountTxOnly) || sig != nil {
		t.Errorf("SignDataWithPassphrase: signature %x, error %v, want %v", sig, err, ErrSignsAccountTxOnly)
	}
	if ErrSignsAccountTxOnly.Error() != "the keystore signs only account transactions" {
		t.Errorf("refusal error %q", ErrSignsAccountTxOnly)
	}
}
