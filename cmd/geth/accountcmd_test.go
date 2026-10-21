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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cespare/cp"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
)

// These tests are 'smoke tests' for the account related
// subcommands and flags.
//
// For most tests, the secp256k1 key files of package accounts, which must not
// be listed, are copied into a temporary keystore directory next to three
// ML-DSA-44 key files of fixed seeds, with the password "foobar".

// seedAddress returns the account address of a 32-byte ML-DSA-44 seed.
func seedAddress(seed []byte) common.Address {
	var s [keystore.SeedSize]byte
	copy(s[:], seed)
	pub, _ := mldsa44.NewKeyFromSeed(&s)
	return types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pub.Bytes())
}

// testAccountSeed returns the seed of 32 bytes b of a test account.
func testAccountSeed(b byte) []byte {
	return bytes.Repeat([]byte{b}, keystore.SeedSize)
}

var (
	accountA = seedAddress(testAccountSeed(0x0a))
	accountB = seedAddress(testAccountSeed(0x0b))
	accountC = seedAddress(testAccountSeed(0x0c))

	accountAFile = "UTC--2026-10-21T00-00-00.000000000Z--" + hex.EncodeToString(accountA[:])
)

// writeTestKeyFile writes the key file of an ML-DSA-44 seed, encrypted with
// the password "foobar".
func writeTestKeyFile(t *testing.T, path string, seed []byte) {
	t.Helper()
	key := &keystore.Key{Id: uuid.New(), Address: seedAddress(seed)}
	copy(key.Seed[:], seed)
	keyjson, err := keystore.EncryptKey(key, "foobar", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, keyjson, 0600); err != nil {
		t.Fatal(err)
	}
}

func tmpDatadirWithKeystore(t *testing.T) string {
	datadir := t.TempDir()
	keystoreDir := filepath.Join(datadir, "keystore")
	source := filepath.Join("..", "..", "accounts", "keystore", "testdata", "keystore")
	if err := cp.CopyAll(keystoreDir, source); err != nil {
		t.Fatal(err)
	}
	writeTestKeyFile(t, filepath.Join(keystoreDir, accountAFile), testAccountSeed(0x0a))
	writeTestKeyFile(t, filepath.Join(keystoreDir, "mldsa-b"), testAccountSeed(0x0b))
	writeTestKeyFile(t, filepath.Join(keystoreDir, "mldsa-c"), testAccountSeed(0x0c))
	return datadir
}

// tmpDupesKeystore returns a keystore directory with two key files of
// account B and one of account A.
func tmpDupesKeystore(t *testing.T) string {
	dir := t.TempDir()
	writeTestKeyFile(t, filepath.Join(dir, "1"), testAccountSeed(0x0b))
	writeTestKeyFile(t, filepath.Join(dir, "2"), testAccountSeed(0x0b))
	writeTestKeyFile(t, filepath.Join(dir, "foo"), testAccountSeed(0x0a))
	return dir
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
Account #1: {%x} keystore://{{.Datadir}}%skeystore%smldsa-b
Account #2: {%x} keystore://{{.Datadir}}%skeystore%smldsa-c
`, accountA, sep, sep, accountAFile, accountB, sep, sep, accountC, sep, sep)
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
	defer geth.ExpectExit()
	geth.Expect(`
Your new account is locked with a password. Please give a password. Do not forget this password.
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Repeat password: {{.InputLine "foobar"}}

Your new key was generated
`)
	geth.ExpectRegexp(`
Public address of the key:   0x[0-9a-fA-F]{40}
Path of the secret key file: .*UTC--.+--[0-9a-f]{40}

- You can share your public address with anyone. Others need it to interact with you.
- You must NEVER share the secret key with anyone! The key controls access to your funds!
- You must BACKUP your key file! Without the key, it's impossible to access account funds!
- You must REMEMBER your password! Without the password, it's impossible to decrypt the key!
`)
}

func TestAccountImport(t *testing.T) {
	t.Parallel()
	seed, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	tests := []struct{ name, key, output string }{
		{
			name:   "correct account",
			key:    hex.EncodeToString(seed),
			output: fmt.Sprintf("Address: {%x}\n", seedAddress(seed)),
		},
		{
			name:   "invalid character",
			key:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
			output: "Fatal: Failed to load the key seed: encoding/hex: invalid byte: U+0067 'g'\n",
		},
		{
			name:   "short seed",
			key:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
			output: "Fatal: Failed to load the key seed: a key seed is 32 bytes, have 31\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			importAccountWithExpect(t, test.key, test.output)
		})
	}
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
	keyfile := filepath.Join(dir, "key.prv")
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
		"--datadir", datadir, "--lightkdf",
		hex.EncodeToString(accountB[:]))
	defer geth.ExpectExit()
	geth.Expect(fmt.Sprintf(`
Unlocking account %x | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
Please give a new password. Do not forget this password.
Password: {{.InputLine "foobar2"}}
Repeat password: {{.InputLine "foobar2"}}
`, accountB))
}

// TestUnlockFlagSecp256k1Refused checks that the address of a secp256k1 key
// file of the keystore cannot be unlocked: the file is not listed.
func TestUnlockFlagSecp256k1Refused(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", "f466859ead1932d743d622cb74fc058882e8648a", "--password", "testdata/passwords.txt")
	defer geth.ExpectExit()
	geth.Expect(`
Fatal: Failed to unlock account f466859ead1932d743d622cb74fc058882e8648a (no key for given address or file)
`)
}

func TestUnlockFlag(t *testing.T) {
	t.Parallel()
	b := hex.EncodeToString(accountB[:])
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", b, "console", "--exec", "loadScript('testdata/empty.js')")
	geth.Expect(fmt.Sprintf(`
Unlocking account %s | Attempt 1/3
!! Unsupported terminal, password will be echoed.
Password: {{.InputLine "foobar"}}
undefined
`, b))
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + accountB.Hex(),
	}
	for _, m := range wantMessages {
		if !strings.Contains(geth.StderrText(), m) {
			t.Errorf("stderr text does not contain %q", m)
		}
	}
}

func TestUnlockFlagWrongPassword(t *testing.T) {
	t.Parallel()
	b := hex.EncodeToString(accountB[:])
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", b, "console", "--exec", "loadScript('testdata/empty.js')")

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
`, b))
}

// https://github.com/ethereum/go-ethereum/issues/1785
func TestUnlockFlagMultiIndex(t *testing.T) {
	t.Parallel()
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", hex.EncodeToString(accountB[:]), "--unlock", "0,2", "console", "--exec", "loadScript('testdata/empty.js')")

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
		"=" + accountA.Hex(),
		"=" + accountC.Hex(),
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
		"--unlock", hex.EncodeToString(accountB[:]), "--password", "testdata/passwords.txt", "--unlock", "0,2", "console", "--exec", "loadScript('testdata/empty.js')")

	geth.Expect(`
undefined
`)
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + accountA.Hex(),
		"=" + accountC.Hex(),
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
		"--unlock", hex.EncodeToString(accountB[:]), "--password",
		"testdata/wrong-passwords.txt", "--unlock", "0,2")
	defer geth.ExpectExit()
	geth.Expect(`
Fatal: Failed to unlock account 0 (could not decrypt key with given password)
`)
}

func TestUnlockFlagAmbiguous(t *testing.T) {
	t.Parallel()
	store := tmpDupesKeystore(t)
	b := hex.EncodeToString(accountB[:])
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", b, "--keystore",
		store, "--unlock", b,
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
`, b))
	geth.ExpectExit()

	wantMessages := []string{
		"Unlocked account",
		"=" + accountB.Hex(),
	}
	for _, m := range wantMessages {
		if !strings.Contains(geth.StderrText(), m) {
			t.Errorf("stderr text does not contain %q", m)
		}
	}
}

func TestUnlockFlagAmbiguousWrongPassword(t *testing.T) {
	t.Parallel()
	store := tmpDupesKeystore(t)
	b := hex.EncodeToString(accountB[:])
	geth := runMinimalGeth(t, "--port", "0", "--ipcdisable", "--datadir", tmpDatadirWithKeystore(t),
		"--unlock", b, "--keystore",
		store, "--unlock", b)

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
`, b))
	geth.ExpectExit()
}
