// Copyright 2016 The go-ethereum Authors
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

package types

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestEIP155Signing checks that a validly signed EIP-155 transaction has no
// sender: the signer signs but recovers nothing.
func TestEIP155Signing(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewEIP155Signer(big.NewInt(18))
	tx, err := SignTx(NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	if v, r, s := tx.RawSignatureValues(); v.Sign() == 0 || r.Sign() == 0 || s.Sign() == 0 {
		t.Fatal("transaction not signed")
	}
	if from, err := Sender(signer, tx); !errors.Is(err, ErrSecp256k1TxType) || from != (common.Address{}) {
		t.Fatalf("sender %x, error %v, want %v", from, err, ErrSecp256k1TxType)
	}
}

func TestEIP155ChainId(t *testing.T) {
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	signer := NewEIP155Signer(big.NewInt(18))
	tx, err := SignTx(NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	if !tx.Protected() {
		t.Fatal("expected tx to be protected")
	}

	if tx.ChainId().Cmp(signer.chainId) != 0 {
		t.Error("expected chainId to be", signer.chainId, "got", tx.ChainId())
	}

	tx = NewTransaction(0, addr, new(big.Int), 0, new(big.Int), nil)
	tx, err = SignTx(tx, HomesteadSigner{}, key)
	if err != nil {
		t.Fatal(err)
	}

	if tx.Protected() {
		t.Error("didn't expect tx to be protected")
	}

	if tx.ChainId().Sign() != 0 {
		t.Error("expected chain id to be 0 got", tx.ChainId())
	}
}

// TestSecp256k1SignersRecoverNothing checks that every secp256k1 signer
// refuses a transaction of each secp256k1 type it signs, by its type byte,
// whatever its chain ID, and that the account signer passes the refusal on.
func TestSecp256k1SignersRecoverNothing(t *testing.T) {
	key, _ := defaultTestKey()
	chainID := big.NewInt(1)
	to := common.Address{0x01}
	txdata := []TxData{
		&LegacyTx{Gas: vars.TxGas, GasPrice: big.NewInt(1), To: &to},
		&AccessListTx{ChainID: chainID, Gas: vars.TxGas, GasPrice: big.NewInt(1), To: &to},
		&DynamicFeeTx{ChainID: chainID, Gas: vars.TxGas, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), To: &to},
		createEmptyBlobTxInner(false),
	}
	signers := []Signer{
		NewCancunSigner(chainID),
		NewEIP1559Signer(chainID),
		NewEIP2930Signer(chainID),
		NewEIP155Signer(chainID),
		HomesteadSigner{},
		FrontierSigner{},
		NewGhostAccountSigner(NewCancunSigner(chainID), common.Hash{0x01}),
		NewCancunSigner(big.NewInt(2)),
	}
	for _, data := range txdata {
		tx, err := SignNewTx(key, LatestSignerForChainID(chainID), data)
		if err != nil {
			t.Fatalf("type %#x: %v", data.txType(), err)
		}
		for _, signer := range signers {
			if from, err := signer.Sender(tx); !errors.Is(err, ErrSecp256k1TxType) || from != (common.Address{}) {
				t.Errorf("type %#x, signer %T: sender %x, error %v, want %v", tx.Type(), signer, from, err, ErrSecp256k1TxType)
			}
			if _, err := Sender(signer, tx); !errors.Is(err, ErrSecp256k1TxType) {
				t.Errorf("type %#x, signer %T: Sender error %v, want %v", tx.Type(), signer, err, ErrSecp256k1TxType)
			}
		}
	}
}

func TestCheckTxType(t *testing.T) {
	for typ := 0; typ < 256; typ++ {
		err := checkTxTypeByte(byte(typ))
		switch typ {
		case GhostRevealTxType, GhostDataRevealTxType, GhostAccountTxType:
			if err != nil {
				t.Errorf("type %#x refused: %v", typ, err)
			}
		case LegacyTxType, AccessListTxType, DynamicFeeTxType, BlobTxType, 0x04:
			if !errors.Is(err, ErrSecp256k1TxType) {
				t.Errorf("type %#x: error %v, want %v", typ, err, ErrSecp256k1TxType)
			}
		default:
			if !errors.Is(err, ErrTxTypeNotSupported) || errors.Is(err, ErrSecp256k1TxType) {
				t.Errorf("type %#x: error %v, want %v", typ, err, ErrTxTypeNotSupported)
			}
		}
	}
}

// typeOnlyTx is a TxData of any type byte, for TestCheckTxType.
type typeOnlyTx struct {
	LegacyTx
	typ byte
}

func (tx *typeOnlyTx) txType() byte { return tx.typ }

func checkTxTypeByte(typ byte) error {
	return CheckTxType(&Transaction{inner: &typeOnlyTx{typ: typ}})
}

type nilSigner struct {
	v, r, s *big.Int
	Signer
}

func (ns *nilSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	return ns.v, ns.r, ns.s, nil
}

// TestNilSigner ensures a faulty Signer implementation does not result in nil signature values or panics.
func TestNilSigner(t *testing.T) {
	key, _ := crypto.GenerateKey()
	innerSigner := LatestSignerForChainID(big.NewInt(1))
	for i, signer := range []Signer{
		&nilSigner{v: nil, r: nil, s: nil, Signer: innerSigner},
		&nilSigner{v: big.NewInt(1), r: big.NewInt(1), s: nil, Signer: innerSigner},
		&nilSigner{v: big.NewInt(1), r: nil, s: big.NewInt(1), Signer: innerSigner},
		&nilSigner{v: nil, r: big.NewInt(1), s: big.NewInt(1), Signer: innerSigner},
	} {
		t.Run(fmt.Sprintf("signer_%d", i), func(t *testing.T) {
			t.Run("legacy", func(t *testing.T) {
				legacyTx := createTestLegacyTxInner()
				_, err := SignNewTx(key, signer, legacyTx)
				if !errors.Is(err, ErrInvalidSig) {
					t.Fatal("expected signature values error, no nil result or panic")
				}
			})
			// test Blob tx specifically, since the signature value types changed
			t.Run("blobtx", func(t *testing.T) {
				blobtx := createEmptyBlobTxInner(false)
				_, err := SignNewTx(key, signer, blobtx)
				if !errors.Is(err, ErrInvalidSig) {
					t.Fatal("expected signature values error, no nil result or panic")
				}
			})
		})
	}
}

func createTestLegacyTxInner() *LegacyTx {
	return &LegacyTx{
		Nonce:    uint64(0),
		To:       nil,
		Value:    big.NewInt(0),
		Gas:      vars.TxGas,
		GasPrice: big.NewInt(vars.GWei),
		Data:     nil,
	}
}
