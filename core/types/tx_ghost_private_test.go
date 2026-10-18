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

package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

func testRevealEnvelope() []byte {
	env := make([]byte, GhostRevealEnvelopeSize)
	env[0] = GhostRevealTxType
	for i := 1; i < 400; i++ {
		env[i] = byte(i)
	}
	env[GhostRevealEnvelopeSize-1] = 0xee
	return env
}

// TestPrivateTxRoundTrip wraps a reveal envelope into a transaction and
// checks its hash, size and every encoding round trip, that it has no sender
// under any signer, and that its receipt round-trips as a typed receipt.
func TestPrivateTxRoundTrip(t *testing.T) {
	env := testRevealEnvelope()
	tx, err := NewGhostRevealTx(env)
	if err != nil {
		t.Fatal(err)
	}
	env[5] ^= 0xff // the transaction holds its own copy
	env[5] ^= 0xff

	if tx.Type() != GhostRevealTxType {
		t.Fatalf("type %#x", tx.Type())
	}
	if want := crypto.Keccak256Hash(env); tx.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x50 || payload) %x", tx.Hash(), want)
	}
	if tx.Size() != GhostRevealEnvelopeSize {
		t.Fatalf("size %d, want %d", tx.Size(), GhostRevealEnvelopeSize)
	}
	if tx.Gas() != GhostRevealGas || tx.To() != nil || tx.Nonce() != 0 || tx.Value().Sign() != 0 {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", tx.Gas(), tx.To(), tx.Nonce(), tx.Value())
	}
	if !bytes.Equal(tx.GhostRevealEnvelope(), env) {
		t.Fatal("envelope differs")
	}

	// Binary.
	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bin, env) {
		t.Fatal("MarshalBinary is not the envelope")
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatal(err)
	}
	if dec.Hash() != tx.Hash() || !bytes.Equal(dec.GhostRevealEnvelope(), env) {
		t.Fatal("binary round trip changed the transaction")
	}

	// RLP, alone and in a list as in a block body.
	enc, err := rlp.EncodeToBytes(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromRLP Transaction
	if err := rlp.DecodeBytes(enc, &fromRLP); err != nil {
		t.Fatal(err)
	}
	if fromRLP.Hash() != tx.Hash() {
		t.Fatal("RLP round trip changed the hash")
	}
	list, err := rlp.EncodeToBytes(Transactions{tx})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 1 || txs[0].Hash() != tx.Hash() {
		t.Fatalf("list round trip: %v", err)
	}

	// JSON.
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Transaction
	if err := json.Unmarshal(js, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Hash() != tx.Hash() {
		t.Fatal("JSON round trip changed the hash")
	}

	// No sender under any signer, and no signature.
	for _, signer := range []Signer{
		NewCancunSigner(big.NewInt(1)), NewEIP1559Signer(big.NewInt(1)), NewEIP2930Signer(big.NewInt(1)),
		NewEIP155Signer(big.NewInt(1)), HomesteadSigner{}, FrontierSigner{},
	} {
		if addr, err := Sender(signer, tx); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: sender %x, error %v", signer, addr, err)
		}
		if _, err := signer.Sender(tx); err == nil {
			t.Errorf("%T: signer gave a sender", signer)
		}
	}
	key, _ := crypto.GenerateKey()
	if _, err := SignTx(tx, NewCancunSigner(big.NewInt(1)), key); err == nil {
		t.Error("a reveal was signed")
	}

	// Wrong envelopes.
	for name, bad := range map[string][]byte{
		"empty":      {},
		"type only":  {GhostRevealTxType},
		"short":      env[:len(env)-1],
		"long":       append(append([]byte{}, env...), 0),
		"other type": append([]byte{DynamicFeeTxType}, env[1:]...),
	} {
		if _, err := NewGhostRevealTx(bad); err == nil {
			t.Errorf("%s envelope accepted", name)
		}
		if name != "empty" && name != "other type" {
			var d Transaction
			if err := d.UnmarshalBinary(bad); err == nil {
				t.Errorf("%s envelope decoded", name)
			}
		}
	}

	// The receipt: typed, status 1, cumulative gas and one log.
	r := &Receipt{
		Type:              GhostRevealTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: GhostRevealGas,
		Logs:              []*Log{{Address: common.Address{1}, Topics: []common.Hash{{2}, {3}}, Data: []byte{4}}},
	}
	r.Bloom = CreateBloom(Receipts{r})
	rbin, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if rbin[0] != GhostRevealTxType {
		t.Fatalf("receipt type byte %#x", rbin[0])
	}
	var rdec Receipt
	if err := rdec.UnmarshalBinary(rbin); err != nil {
		t.Fatal(err)
	}
	if rdec.Type != GhostRevealTxType || rdec.Status != ReceiptStatusSuccessful || rdec.CumulativeGasUsed != GhostRevealGas || len(rdec.Logs) != 1 {
		t.Fatalf("receipt round trip: %+v", rdec)
	}
	renc, err := rlp.EncodeToBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	var rfromRLP Receipt
	if err := rlp.DecodeBytes(renc, &rfromRLP); err != nil || rfromRLP.Type != GhostRevealTxType {
		t.Fatalf("receipt RLP round trip: %v", err)
	}
	var buf bytes.Buffer
	Receipts{r}.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), rbin) {
		t.Fatal("receipt trie encoding differs from the binary encoding")
	}

	// Derived fields: no contract address, no sender needed.
	rs := Receipts{{Type: GhostRevealTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: GhostRevealGas}}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{tx}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != GhostRevealGas || rs[0].TxHash != tx.Hash() {
		t.Fatalf("derived fields: %+v", rs[0])
	}
}
