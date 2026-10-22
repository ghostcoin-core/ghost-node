// Copyright 2016 The go-ethereum Authors
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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cespare/cp"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// These tests are 'smoke tests' for the account related
// subcommands and flags.
//
// For most tests, the test files from package accounts
// are copied into a temporary keystore directory. Its ML-DSA-44 key files
// (password "foobar") hold the seeds 0x0a (the UTC-- file and dupes/foo),
// 0x0b (aaa, dupes/1 and dupes/2) and 0x0c (zzz); its other files, among them
// a secp256k1 key file, are not listed.

// mldsaAddress returns the address of the ML-DSA-44 key of seed, derived
// without the keystore.
func mldsaAddress(seed []byte) common.Address {
	var s [mldsa44.SeedSize]byte
	copy(s[:], seed)
	pub, _ := mldsa44.NewKeyFromSeed(&s)
	return types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes())
}

// fixtureAddress returns the address of the key file fixture whose seed is 32
// bytes of b.
func fixtureAddress(b byte) common.Address {
	return mldsaAddress(bytes.Repeat([]byte{b}, mldsa44.SeedSize))
}

var (
	fixtureA     = fixtureAddress(0x0a)
	fixtureB     = fixtureAddress(0x0b)
	fixtureC     = fixtureAddress(0x0c)
	fixtureFileA = "UTC--2026-10-21T09-00-00.000000000Z--" + hex.EncodeToString(fixtureA[:])
	// hexB is the unprefixed hex address of aaa, as the commands take it.
	hexB = hex.EncodeToString(fixtureB[:])
)

func tmpDatadirWithKeystore(t *testing.T) string {
	datadir := t.TempDir()
	keystore := filepath.Join(datadir, "keystore")
	source := filepath.Join("..", "..", "accounts", "keystore", "testdata", "keystore")
	if err := cp.CopyAll(keystore, source); err != nil {
		t.Fatal(err)
	}
	return datadir
}

func TestAccountListEmpty(t *testing.T) {
	t.Parallel()
	geth := runGeth(t, "account", "list")
	geth.ExpectExit()
}

func TestAccountList(t *testing.T) {
	t.Parallel()
	datadir := tmpDatadirWithKeystore(t)
	sep := "/"
	if runtime.GOOS == "windows" {
		sep = `\`
	}
	want := fmt.Sprintf(`
Account #0: {%x} keystore://{{.Datadir}}%skeystore%s%s
Account #1: {%x} keystore://{{.Datadir}}%skeystore%saaa
Account #2: {%x} keystore://{{.Datadir}}%skeystore%szzz
`, fixtureA, sep, sep, fixtureFileA, fixtureB, sep, sep, fixtureC, sep, sep)
	{
		geth := runGeth(t, "account", "list", "--datadir", datadir)
		geth.Expect(want)
		geth.ExpectExit()
	}
	{
		geth := runGeth(t, "--datadir", datadir, "account", "list")
		geth.Expect(want)
		geth.ExpectExit()
	}
}

func TestAccountNew(t *testing.T) {
	t.Parallel()
	geth := runGeth(t, "account", "new", "--lightkdf")
	geth.Expect(`
Your new account is locked with a password. Please give a password. Do not forget this password.
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}

Your new ML-DSA-44 key was generated
`)
	_, matches := geth.ExpectRegexp(`
Public address of the key:   (0x[0-9a-fA-F]{40})
Path of the secret key file: (.*UTC--.+--[0-9a-f]{40})

- You can share your public address with anyone. Others need it to interact with you.
- You must NEVER share the secret key with anyone! The key controls access to your funds!
- You must BACKUP your key file! Without the key, it's impossible to access account funds!
- You must REMEMBER your password! Without the password, it's impossible to decrypt the key!
`)
	geth.ExpectExit()
	if len(matches) != 3 {
		t.Fatalf("matches %v", matches)
	}
	checkMLDSAKeyFile(t, matches[2], common.HexToAddress(matches[1]))
}

// checkMLDSAKeyFile checks that the key file at path is an ML-DSA-44 key file
// with "scheme":1 for the address.
func checkMLDSAKeyFile(t *testing.T, path string, addr common.Address) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Address string  `json:"address"`
		Scheme  *uint16 `json:"scheme"`
	}
	if err := json.Unmarshal(content, &file); err != nil {
		t.Fatal(err)
	}
	if file.Scheme == nil || *file.Scheme != 1 || common.HexToAddress(file.Address) != addr {
		t.Fatalf("key file %s: scheme %v, address %s; want 1 and %x", path, file.Scheme, file.Address, addr)
	}
}

func TestAccountImport(t *testing.T) {
	t.Parallel()
	seed, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	tests := []struct{ name, key, output string }{
		{
			name:   "correct account",
			key:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			output: fmt.Sprintf("Address: {%x}\n", mldsaAddress(seed)),
		},
		{
			name:   "correct account with a line break",
			key:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
			output: fmt.Sprintf("Address: {%x}\n", mldsaAddress(seed)),
		},
		{
			name:   "invalid character",
			key:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
			output: "Fatal: Failed to load the key seed: invalid seed file: encoding/hex: invalid byte: U+0067 'g'\n",
		},
		{
			name:   "too long",
			key:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef1",
			output: "Fatal: Failed to load the key seed: an ML-DSA-44 key seed is 32 bytes: the seed file holds 65 characters, want 64 hex digits\n",
		},
		{
			name:   "secp256k1 key file",
			key:    readTestFile(t, filepath.Join("..", "..", "accounts", "keystore", "testdata", "ecdsa-key.json")),
			output: "Fatal: Failed to load the key seed: an ML-DSA-44 key seed is 32 bytes: the seed file holds 487 characters, want 64 hex digits\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			importAccountWithExpect(t, test.key, test.output)
		})
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestAccountHelp(t *testing.T) {
	t.Parallel()
	geth := runGeth(t, "account", "-h")
	geth.WaitExit()
	if have, want := geth.ExitStatus(), 0; have != want {
		t.Errorf("exit error, have %d want %d", have, want)
	}

	geth = runGeth(t, "account", "import", "-h")
	geth.WaitExit()
	if have, want := geth.ExitStatus(), 0; have != want {
		t.Errorf("exit error, have %d want %d", have, want)
	}
}

func importAccountWithExpect(t *testing.T, key string, expected string) {
	dir := t.TempDir()
	keyfile := filepath.Join(dir, "seed.hex")
	if err := os.WriteFile(keyfile, []byte(key), 0600); err != nil {
		t.Error(err)
	}
	passwordFile := filepath.Join(dir, "password.txt")
	if err := os.WriteFile(passwordFile, []byte("foobar"), 0600); err != nil {
		t.Error(err)
	}
	geth := runGeth(t, "--lightkdf", "account", "import", "-password", passwordFile, keyfile)
	defer geth.ExpectExit()
	geth.Expect(expected)
}

// TestAccountImportWritesMLDSAKeyFile checks that an imported seed is stored
// as an ML-DSA-44 key file that the keystore then lists.
func TestAccountImportWritesMLDSAKeyFile(t *testing.T) {
	t.Parallel()
	datadir := t.TempDir()
	seed := bytes.Repeat([]byte{0x33}, mldsa44.SeedSize)
	seedFile := filepath.Join(datadir, "seed.hex")
	if err := os.WriteFile(seedFile, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(datadir, "password.txt")
	if err := os.WriteFile(passwordFile, []byte("foobar"), 0600); err != nil {
		t.Fatal(err)
	}
	addr := mldsaAddress(seed)
	geth := runGeth(t, "--lightkdf", "--datadir", datadir, "account", "import", "-password", passwordFile, seedFile)
	geth.Expect(fmt.Sprintf("Address: {%x}\n", addr))
	geth.ExpectExit()

	files, err := os.ReadDir(filepath.Join(datadir, "keystore"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one key file in keystore directory, found %d files (error: %v)", len(files), err)
	}
	checkMLDSAKeyFile(t, filepath.Join(datadir, "keystore", files[0].Name()), addr)

	list := runGeth(t, "account", "list", "--datadir", datadir)
	list.Expect(fmt.Sprintf("Account #0: {%x} keystore://%s\n", addr, filepath.Join(datadir, "keystore", files[0].Name())))
	list.ExpectExit()
}

func TestAccountNewBadRepeat(t *testing.T) {
	t.Parallel()
	geth := runGeth(t, "account", "new", "--lightkdf")
	defer geth.ExpectExit()
	geth.Expect(`
Your new account is locked with a password. Please give a password. Do not forget this password.
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "something"}}
Repeat password: {{.InputLine "something else"}}
Fatal: Passwords do not match
`)
}

func TestAccountUpdate(t *testing.T) {
	t.Parallel()
	datadir := tmpDatadirWithKeystore(t)
	geth := runGeth(t, "account", "update",
		"--datadir", datadir, "--lightkdf", hexB)
	geth.Expect(fmt.Sprintf(`
Unlocking account %s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Please give a new password. Do not forget this password.
Password: {{.InputLine "foobar2"}}
Repeat password: {{.InputLine "foobar2"}}
`, hexB))
	geth.ExpectExit()

	// The updated file is still an ML-DSA-44 key file, unlocked by the new
	// password only.
	checkMLDSAKeyFile(t, filepath.Join(datadir, "keystore", "aaa"), fixtureB)
	again := runGeth(t, "account", "update",
		"--datadir", datadir, "--lightkdf", hexB)
	defer again.ExpectExit()
	again.Expect(fmt.Sprintf(`
Unlocking account %s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Unlocking account %s | Attempt 2/3
Password: {{.InputLine "foobar2"}}
Please give a new password. Do not forget this password.
Password: {{.InputLine "foobar3"}}
Repeat password: {{.InputLine "foobar3"}}
`, hexB, hexB))
}

// TestAccountUpdateRefusesECDSAKey checks that a secp256k1 key file in the
// keystore directory is not found by account update.
func TestAccountUpdateRefusesECDSAKey(t *testing.T) {
	t.Parallel()
	datadir := tmpDatadirWithKeystore(t)
	geth := runGeth(t, "account", "update",
		"--datadir", datadir, "--lightkdf", "f466859ead1932d743d622cb74fc058882e8648a")
	defer geth.ExpectExit()
	geth.Expect(`
Unlocking account f466859ead1932d743d622cb74fc058882e8648a | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Fatal: Failed to unlock account f466859ead1932d743d622cb74fc058882e8648a (no key for given address or file)
`)
}

// TestWalletCommandRemoved checks that the presale wallet import is gone.
func TestWalletCommandRemoved(t *testing.T) {
	t.Parallel()
	for _, cmd := range app.Commands {
		if cmd.Name == "wallet" {
			t.Fatal("geth still has the wallet command")
		}
	}
}

func TestUnlockFlag(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "console", "--exec", "loadScript('testdata/empty.js')")
	geth.Expect(fmt.Sprintf(`
Unlocking account %s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
undefined
`, hexB))
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + fixtureB.Hex(),
	}
	for _, m := range wantMessages {
		if !strings.Contains(geth.StderrText(), m) {
			t.Errorf("stderr text does not contain %q", m)
		}
	}
}

// TestUnlockFlagECDSAKey checks that --unlock does not find a secp256k1 key
// file of the keystore directory.
func TestUnlockFlagECDSAKey(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", "f466859ead1932d743d622cb74fc058882e8648a", "console", "--exec", "loadScript('testdata/empty.js')")
	defer geth.ExpectExit()
	geth.Expect(`
Unlocking account f466859ead1932d743d622cb74fc058882e8648a | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Fatal: Failed to unlock account f466859ead1932d743d622cb74fc058882e8648a (no key for given address or file)
`)
}

func TestUnlockFlagWrongPassword(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "console", "--exec", "loadScript('testdata/empty.js')")

	defer geth.ExpectExit()
	geth.Expect(fmt.Sprintf(`
Unlocking account %[1]s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "wrong1"}}
Unlocking account %[1]s | Attempt 2/3
Password: {{.InputLine "wrong2"}}
Unlocking account %[1]s | Attempt 3/3
Password: {{.InputLine "wrong3"}}
Fatal: Failed to unlock account %[1]s (could not decrypt key with given password)
`, hexB))
}

// https://github.com/ethereum/go-ethereum/issues/1785
func TestUnlockFlagMultiIndex(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "--unlock", "0,2", "console", "--exec", "loadScript('testdata/empty.js')")

	geth.Expect(`
Unlocking account 0 | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Unlocking account 2 | Attempt 1/3
Password: {{.InputLine "foobar"}}
undefined
`)
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + fixtureA.Hex(),
		"=" + fixtureC.Hex(),
	}
	for _, m := range wantMessages {
		if !strings.Contains(geth.StderrText(), m) {
			t.Errorf("stderr text does not contain %q", m)
		}
	}
}

func TestUnlockFlagPasswordFile(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "--password", "testdata/passwords.txt", "--unlock", "0,2", "console", "--exec", "loadScript('testdata/empty.js')")

	geth.Expect(`
undefined
`)
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + fixtureA.Hex(),
		"=" + fixtureC.Hex(),
	}
	for _, m := range wantMessages {
		if !strings.Contains(geth.StderrText(), m) {
			t.Errorf("stderr text does not contain %q", m)
		}
	}
}

func TestUnlockFlagPasswordFileWrongPassword(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "--password",
		"testdata/wrong-passwords.txt", "--unlock", "0,2")
	defer geth.ExpectExit()
	geth.Expect(`
Fatal: Failed to unlock account 0 (could not decrypt key with given password)
`)
}

func TestUnlockFlagAmbiguous(t *testing.T) {
	t.Parallel()
	store := filepath.Join("..", "..", "accounts", "keystore", "testdata", "dupes")
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "--keystore",
		store, "--unlock", hexB,
		"console", "--exec", "loadScript('testdata/empty.js')")
	defer geth.ExpectExit()

	// Helper for the expect template, returns absolute keystore path.
	geth.SetTemplateFunc("keypath", func(file string) string {
		abs, _ := filepath.Abs(filepath.Join(store, file))
		return abs
	})
	geth.Expect(fmt.Sprintf(`
Unlocking account %[1]s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Multiple key files exist for address %[1]s:
   keystore://{{keypath "1"}}
   keystore://{{keypath "2"}}
Testing your password against all of them...
Your password unlocked keystore://{{keypath "1"}}
In order to avoid this warning, you need to remove the following duplicate key files:
   keystore://{{keypath "2"}}
undefined
`, hexB))
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + fixtureB.Hex(),
	}
	for _, m := range wantMessages {
		if !strings.Contains(geth.StderrText(), m) {
			t.Errorf("stderr text does not contain %q", m)
		}
	}
}

func TestUnlockFlagAmbiguousWrongPassword(t *testing.T) {
	t.Parallel()
	store := filepath.Join("..", "..", "accounts", "keystore", "testdata", "dupes")
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hexB, "--keystore",
		store, "--unlock", hexB)

	defer geth.ExpectExit()

	// Helper for the expect template, returns absolute keystore path.
	geth.SetTemplateFunc("keypath", func(file string) string {
		abs, _ := filepath.Abs(filepath.Join(store, file))
		return abs
	})
	geth.Expect(fmt.Sprintf(`
Unlocking account %[1]s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "wrong"}}
Multiple key files exist for address %[1]s:
   keystore://{{keypath "1"}}
   keystore://{{keypath "2"}}
Testing your password against all of them...
Fatal: None of the listed files could be unlocked.
`, hexB))
	geth.ExpectExit()
}
