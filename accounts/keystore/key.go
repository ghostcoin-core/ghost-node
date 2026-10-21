// Copyright 2014 The go-ethereum Authors
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
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
)

const (
	version = 3

	// KeyScheme is the signature scheme of every account key of the
	// keystore: ML-DSA-44 (scheme 0x0001). A key file names it in its
	// scheme field.
	KeyScheme = types.GhostSchemeMLDSA44

	// SeedSize is the size of an account key seed, from which
	// mldsa44.NewKeyFromSeed derives the key pair.
	SeedSize = mldsa44.SeedSize
)

// ErrNotAccountKey is returned for a key file or a key that is not an
// ML-DSA-44 account key: a file without the scheme field, of another scheme,
// of the version 1 format or holding a secp256k1 key.
var ErrNotAccountKey = errors.New("not an ML-DSA-44 account key (scheme 0x0001)")

// Key is an account key: an ML-DSA-44 key pair, held as the seed it is
// derived from. The address is types.GhostAccountAddressOf(scheme, public
// key).
type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// to simplify lookups we also store the address
	Address common.Address
	// Seed is the ML-DSA-44 key seed, always in plaintext in this struct.
	Seed [SeedSize]byte
	// PrivateKey is always nil: the keystore holds no secp256k1 keys. The
	// field is kept for callers built against the secp256k1 key API.
	PrivateKey *ecdsa.PrivateKey
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	GetKey(addr common.Address, filename string, auth string) (*Key, error)
	// Writes and encrypts the key.
	StoreKey(filename string, k *Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	JoinPath(filename string) string
}

type plainKeyJSON struct {
	Address    string  `json:"address"`
	PrivateKey string  `json:"privatekey"`
	Id         string  `json:"id"`
	Version    int     `json:"version"`
	Scheme     *uint16 `json:"scheme,omitempty"`
}

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
	Scheme  *uint16    `json:"scheme,omitempty"`
}

type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

// checkScheme refuses a key file whose scheme field is missing or names
// another scheme than ML-DSA-44.
func checkScheme(scheme *uint16) error {
	if scheme == nil {
		return fmt.Errorf("%w: the key file has no scheme", ErrNotAccountKey)
	}
	if *scheme != KeyScheme {
		return fmt.Errorf("%w: the key file is of scheme %#04x", ErrNotAccountKey, *scheme)
	}
	return nil
}

// PublicKey returns the ML-DSA-44 public key of the key.
func (k *Key) PublicKey() []byte {
	pub, _ := k.keyPair()
	return pub.Bytes()
}

// keyPair derives the ML-DSA-44 key pair from the seed.
func (k *Key) keyPair() (*mldsa44.PublicKey, *mldsa44.PrivateKey) {
	seed := k.Seed
	defer clear(seed[:])
	return mldsa44.NewKeyFromSeed(&seed)
}

func (k *Key) MarshalJSON() (j []byte, err error) {
	scheme := KeyScheme
	jStruct := plainKeyJSON{
		hex.EncodeToString(k.Address[:]),
		hex.EncodeToString(k.Seed[:]),
		k.Id.String(),
		version,
		&scheme,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}
	if err := checkScheme(keyJSON.Scheme); err != nil {
		return err
	}
	id, err := uuid.Parse(keyJSON.Id)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(keyJSON.PrivateKey)
	if err != nil {
		return err
	}
	defer clear(seed)
	key, err := newKeyFromSeed(seed, id)
	if err != nil {
		return err
	}
	if err := checkAddress(keyJSON.Address, key); err != nil {
		zeroKey(key)
		return err
	}
	*k = *key
	zeroKey(key)
	return nil
}

// checkAddress refuses a key file whose address is not the address of the
// key it holds, as a secp256k1 key under a scheme field would be.
func checkAddress(fileAddr string, key *Key) error {
	addr, err := hex.DecodeString(fileAddr)
	if err != nil {
		return err
	}
	if common.BytesToAddress(addr) != key.Address || len(addr) != common.AddressLength {
		return fmt.Errorf("%w: the key file address %x is not the address of its key", ErrNotAccountKey, addr)
	}
	return nil
}

// newKeyFromSeed returns the account key of a 32-byte ML-DSA-44 seed.
func newKeyFromSeed(seed []byte, id uuid.UUID) (*Key, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%w: a key seed is %d bytes, have %d", ErrNotAccountKey, SeedSize, len(seed))
	}
	key := &Key{Id: id}
	copy(key.Seed[:], seed)
	key.Address = types.GhostAccountAddressOf(KeyScheme, key.PublicKey())
	return key, nil
}

func newKey(rand io.Reader) (*Key, error) {
	var seed [SeedSize]byte
	defer clear(seed[:])
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("could not create random uuid: %w", err)
	}
	return newKeyFromSeed(seed[:], id)
}

func storeNewKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKey(key)
		return nil, a, err
	}
	return key, a, err
}

func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}
