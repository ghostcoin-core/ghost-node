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
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
)

const (
	// MLDSAScheme is the scheme field of an ML-DSA-44 key file, and the scheme
	// its account address is derived under.
	MLDSAScheme = types.GhostSchemeMLDSA44

	// SeedSize is the size of an ML-DSA-44 key seed, from which
	// mldsa44.NewKeyFromSeed derives the key pair.
	SeedSize = mldsa44.SeedSize
)

var (
	// ErrSeedSize is returned for an ML-DSA-44 key seed that is not 32 bytes.
	ErrSeedSize = fmt.Errorf("an ML-DSA-44 key seed is %d bytes", SeedSize)

	// ErrKeyScheme is returned for a key file whose scheme field names a
	// scheme the keystore does not hold.
	ErrKeyScheme = errors.New("unsupported key file scheme")

	// ErrNoKeyScheme is returned for a key file without the scheme field: a
	// version 1, presale or secp256k1 key file, which the keystore refuses.
	ErrNoKeyScheme = errors.New("key file has no scheme field: only ML-DSA-44 key files are supported")

	// ErrNotMLDSAKey is returned for a key that holds no ML-DSA-44 seed.
	ErrNotMLDSAKey = errors.New("account key is not an ML-DSA-44 key")

	// ErrSignsAccountTxOnly is returned when a hash or data is to be signed:
	// the ML-DSA-44 account keys of the keystore sign account transactions
	// only.
	ErrSignsAccountTxOnly = errors.New("the keystore signs only account transactions")
)

// isMLDSA reports whether k is an ML-DSA-44 account key.
func (k *Key) isMLDSA() bool {
	return k.Seed != nil
}

// mldsaKeyPair derives the ML-DSA-44 key pair of k from its seed.
func (k *Key) mldsaKeyPair() (*mldsa44.PublicKey, *mldsa44.PrivateKey) {
	var seed [SeedSize]byte
	defer clear(seed[:])
	copy(seed[:], k.Seed)
	return mldsa44.NewKeyFromSeed(&seed)
}

// newMLDSAKey returns an ML-DSA-44 account key of a seed read from rand.
func newMLDSAKey(rand io.Reader) (*Key, error) {
	seed := make([]byte, SeedSize)
	defer clear(seed)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("could not create random uuid: %w", err)
	}
	return newMLDSAKeyFromSeed(seed, id)
}

// newMLDSAKeyFromSeed returns the ML-DSA-44 account key of seed, whose
// address is types.GhostAccountAddressOf(MLDSAScheme, public key). The key
// holds a copy of seed.
func newMLDSAKeyFromSeed(seed []byte, id uuid.UUID) (*Key, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%w, have %d", ErrSeedSize, len(seed))
	}
	key := &Key{Id: id, Seed: bytes.Clone(seed)}
	pub, _ := key.mldsaKeyPair()
	key.Address = types.GhostAccountAddressOf(MLDSAScheme, pub.Bytes())
	return key, nil
}

// NewRandomMLDSAKey returns a new ML-DSA-44 account key of a random seed and
// a random id, for tools that write a key file outside a keystore directory.
func NewRandomMLDSAKey() (*Key, error) {
	return newMLDSAKey(crand.Reader)
}

// NewMLDSAKeyFromSeed returns the ML-DSA-44 account key of the 32-byte seed
// with a random id. The key holds a copy of seed.
func NewMLDSAKeyFromSeed(seed []byte) (*Key, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("could not create random uuid: %w", err)
	}
	return newMLDSAKeyFromSeed(seed, id)
}

// LoadSeed reads the 32-byte seed of an ML-DSA-44 account key from a file
// holding it as 64 hex digits, optionally followed by a line break.
func LoadSeed(file string) ([]byte, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	defer clear(content)
	text := bytes.TrimRight(content, "\r\n")
	if len(text) != 2*SeedSize {
		return nil, fmt.Errorf("%w: the seed file holds %d characters, want %d hex digits", ErrSeedSize, len(text), 2*SeedSize)
	}
	seed := make([]byte, SeedSize)
	if _, err := hex.Decode(seed, text); err != nil {
		clear(seed)
		return nil, fmt.Errorf("invalid seed file: %w", err)
	}
	return seed, nil
}

// MLDSAPublicKey returns the encoded ML-DSA-44 public key of k.
func (k *Key) MLDSAPublicKey() ([]byte, error) {
	if !k.isMLDSA() {
		return nil, ErrNotMLDSAKey
	}
	pub, _ := k.mldsaKeyPair()
	return pub.Bytes(), nil
}

// checkMLDSAScheme refuses a scheme field other than the ML-DSA-44 one.
func checkMLDSAScheme(scheme uint16) error {
	if scheme != MLDSAScheme {
		return fmt.Errorf("%w: %#04x", ErrKeyScheme, scheme)
	}
	return nil
}

// checkMLDSAAddress refuses a key file whose address field is not the address
// of the ML-DSA-44 key it holds.
func checkMLDSAAddress(fileAddr string, key *Key) error {
	addr, err := hex.DecodeString(fileAddr)
	if err != nil {
		return err
	}
	if len(addr) != common.AddressLength || common.BytesToAddress(addr) != key.Address {
		return fmt.Errorf("key file address %x is not the address %x of its ML-DSA-44 key", addr, key.Address)
	}
	return nil
}

// marshalMLDSAJSON encodes the ML-DSA-44 key k as a plain key file, with its
// seed as the private key and the scheme field set.
func (k *Key) marshalMLDSAJSON() ([]byte, error) {
	scheme := MLDSAScheme
	return json.Marshal(plainKeyJSON{
		Address:    hex.EncodeToString(k.Address[:]),
		PrivateKey: hex.EncodeToString(k.Seed),
		Id:         k.Id.String(),
		Version:    version,
		Scheme:     &scheme,
	})
}

// unmarshalMLDSAJSON decodes the plain key file of an ML-DSA-44 key into k.
func (k *Key) unmarshalMLDSAJSON(keyJSON *plainKeyJSON) error {
	if err := checkMLDSAScheme(*keyJSON.Scheme); err != nil {
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
	key, err := newMLDSAKeyFromSeed(seed, id)
	if err != nil {
		return err
	}
	if err := checkMLDSAAddress(keyJSON.Address, key); err != nil {
		zeroKey(key)
		return err
	}
	*k = *key
	return nil
}

// encryptMLDSAKey encrypts the seed of the ML-DSA-44 key into a key file of
// the version 3 layout with the scheme field set.
func encryptMLDSAKey(key *Key, auth string, scryptN, scryptP int) ([]byte, error) {
	cryptoStruct, err := EncryptDataV3(key.Seed, []byte(auth), scryptN, scryptP)
	if err != nil {
		return nil, err
	}
	scheme := MLDSAScheme
	return json.Marshal(encryptedKeyJSONV3{
		Address: hex.EncodeToString(key.Address[:]),
		Crypto:  cryptoStruct,
		Id:      key.Id.String(),
		Version: version,
		Scheme:  &scheme,
	})
}

// decryptMLDSAKey decrypts the seed of an ML-DSA-44 key file. The scheme is
// checked before the password is tried.
func decryptMLDSAKey(k *encryptedKeyJSONV3, auth string) (*Key, error) {
	if err := checkMLDSAScheme(*k.Scheme); err != nil {
		return nil, err
	}
	seed, keyId, err := decryptKeyV3(k, auth)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	id, err := uuid.FromBytes(keyId)
	if err != nil {
		return nil, fmt.Errorf("invalid UUID: %w", err)
	}
	key, err := newMLDSAKeyFromSeed(seed, id)
	if err != nil {
		return nil, err
	}
	if err := checkMLDSAAddress(k.Address, key); err != nil {
		zeroKey(key)
		return nil, err
	}
	return key, nil
}

// signAccountTx signs tx for the chain of signer with the ML-DSA-44 key, and
// refuses a key without a seed.
func signAccountTx(key *Key, signer types.Signer, tx *types.GhostAccountTx) (*types.Transaction, error) {
	if !key.isMLDSA() {
		return nil, ErrNotMLDSAKey
	}
	_, priv := key.mldsaKeyPair()
	return types.SignGhostAccountTx(signer, priv, tx)
}

// NewMLDSAAccount generates a new ML-DSA-44 account key and stores it into the
// key directory, encrypting it with the passphrase.
func (ks *KeyStore) NewMLDSAAccount(passphrase string) (accounts.Account, error) {
	key, err := newMLDSAKey(crand.Reader)
	if err != nil {
		return accounts.Account{}, err
	}
	defer zeroKey(key)
	_, account, err := storeKey(ks.storage, key, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}

// ImportSeed stores the ML-DSA-44 account key of the 32-byte seed into the key
// directory, encrypting it with the passphrase.
func (ks *KeyStore) ImportSeed(seed []byte, passphrase string) (accounts.Account, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return accounts.Account{}, fmt.Errorf("could not create random uuid: %w", err)
	}
	key, err := newMLDSAKeyFromSeed(seed, id)
	if err != nil {
		return accounts.Account{}, err
	}
	defer zeroKey(key)

	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}
	return ks.importKey(key, passphrase)
}

// SignAccountTx signs the account transaction with the unlocked ML-DSA-44 key
// of the requested account, for the chain of signer, which comes from
// types.NewGhostAccountSigner. The scheme and public key are set from the key.
func (ks *KeyStore) SignAccountTx(a accounts.Account, signer types.Signer, tx *types.GhostAccountTx) (*types.Transaction, error) {
	// Look up the key to sign with and abort if it cannot be found
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	return signAccountTx(unlockedKey.Key, signer, tx)
}

// SignAccountTxWithPassphrase signs the account transaction if the ML-DSA-44
// key of the given account can be decrypted with the given passphrase.
func (ks *KeyStore) SignAccountTxWithPassphrase(a accounts.Account, passphrase string, signer types.Signer, tx *types.GhostAccountTx) (*types.Transaction, error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key)
	return signAccountTx(key, signer, tx)
}
