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
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// testPublicRootEnvelope is a public root envelope of count bindings with a
// recognisable header, proof and bindings; its fields are not checked here.
func testPublicRootEnvelope(count int) []byte {
	env := make([]byte, 1+GhostPublicRootPayloadSize(count))
	env[0] = GhostPublicRootTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[0:], 1)
	binary.BigEndian.PutUint64(p[2:], 0x0102030405060708)
	binary.BigEndian.PutUint16(p[10:], uint16(count))
	for i := 0; i < 64; i++ {
		p[GhostPublicRootHeaderSize+i] = byte(i*5 + 3)
	}
	for i := range count {
		b := p[GhostPublicRootFixedSize+i*GhostBindingSize:]
		b[0] = byte(i + 1)
		b[GhostBindingSize-1] = byte(i + 1)
	}
	return env
}

// testBindingTx is a binding transaction of ML-DSA-44 scheme with a
// recognisable binding; to nil makes it a contract creation.
func testBindingTx(to *common.Address) *GhostBindingTx {
	binding := NewGhostBinding(common.Address{0xaa, 0x57}, common.Hash{0xbb, 0x57}, common.Hash{0xcc, 0x57})
	return &GhostBindingTx{
		ChainID:    big.NewInt(1),
		Nonce:      7,
		GasTipCap:  big.NewInt(2),
		GasFeeCap:  big.NewInt(30),
		Gas:        100_000,
		To:         to,
		Value:      big.NewInt(5),
		Data:       []byte{1, 2, 3},
		AccessList: AccessList{{Address: common.Address{9}, StorageKeys: []common.Hash{{8}}}},
		Scheme:     GhostScheme(GhostSchemeMLDSA44),
		Binding:    binding,
	}
}

// TestGhostPublicRootTxRoundTrip checks the public root type 0x56 and the
// binding transaction type 0x57: their layout constants, the 84-byte binding
// and its parts, that neither has a sender under any signer, their hashes,
// sizes and fields, every encoding round trip, the strict decoders and the
// typed receipts. An account transaction with its raw signature (0x52) in
// the same list stays valid and unchanged.
func TestGhostPublicRootTxRoundTrip(t *testing.T) {
	if GhostPublicRootTxType != 0x56 || GhostBindingTxType != 0x57 {
		t.Fatalf("types %#x and %#x", GhostPublicRootTxType, GhostBindingTxType)
	}
	if GhostBindingSize != 84 || GhostPublicRootHeaderSize != 12 || GhostPublicRootProofSize != 1_310_720 {
		t.Fatalf("binding %d, header %d, proof %d", GhostBindingSize, GhostPublicRootHeaderSize, GhostPublicRootProofSize)
	}
	if GhostPublicRootFixedSize != 1_310_732 || GhostPublicRootPayloadSize(3) != 1_310_732+3*84 {
		t.Fatalf("fixed %d, payload of 3 %d", GhostPublicRootFixedSize, GhostPublicRootPayloadSize(3))
	}

	// The binding: account, key identity and transaction hash, 84 bytes.
	account, identity, hash := common.Address{0x11, 0x22}, common.Hash{0x33, 0x44}, common.Hash{0x55, 0x66}
	b := NewGhostBinding(account, identity, hash)
	if b.Account() != account || b.KeyIdentity() != identity || b.TxHash() != hash {
		t.Fatal("binding parts differ")
	}
	if !bytes.Equal(b[:20], account[:]) || !bytes.Equal(b[20:52], identity[:]) || !bytes.Equal(b[52:], hash[:]) {
		t.Fatal("binding layout is not account | key identity | transaction hash")
	}

	// The public root.
	env := testPublicRootEnvelope(3)
	root, err := NewGhostPublicRootTx(env)
	if err != nil {
		t.Fatal(err)
	}
	if root.Type() != GhostPublicRootTxType || root.IsGhostReveal() {
		t.Fatalf("type %#x, reveal %v", root.Type(), root.IsGhostReveal())
	}
	if err := CheckTxType(root); err != nil {
		t.Fatalf("type check: %v", err)
	}
	if want := crypto.Keccak256Hash(env); root.Hash() != want {
		t.Fatalf("hash %x, want keccak256(0x56 || payload) %x", root.Hash(), want)
	}
	if root.Size() != uint64(len(env)) {
		t.Fatalf("size %d, want %d", root.Size(), len(env))
	}
	if root.Gas() != 0 || root.To() != nil || root.Nonce() != 0 || root.Value().Sign() != 0 || root.GasPrice().Sign() != 0 || root.Data() != nil {
		t.Fatalf("unexpected fields: gas %d to %v nonce %d value %v", root.Gas(), root.To(), root.Nonce(), root.Value())
	}
	if root.ChainId().Uint64() != 0x0102030405060708 {
		t.Fatalf("chain id %v", root.ChainId())
	}
	if !bytes.Equal(root.GhostPublicRootEnvelope(), env) || root.GhostBundleEnvelope() != nil {
		t.Fatal("envelopes differ")
	}
	env[100] ^= 0xff
	if bytes.Equal(root.GhostPublicRootEnvelope(), env) {
		t.Fatal("the root shares the caller's envelope")
	}
	env[100] ^= 0xff

	// The binding transaction.
	to := common.Address{0x70}
	inner := testBindingTx(&to)
	btx := NewTx(inner)
	if btx.Type() != GhostBindingTxType || btx.IsGhostReveal() {
		t.Fatalf("binding tx type %#x", btx.Type())
	}
	if err := CheckTxType(btx); err != nil {
		t.Fatalf("binding tx type check: %v", err)
	}
	if err := btx.CheckGhostBindingShape(); err != nil {
		t.Fatalf("binding tx shape: %v", err)
	}
	scheme, carried, ok := btx.GhostBinding()
	if !ok || scheme != GhostSchemeMLDSA44 || carried != inner.Binding {
		t.Fatal("binding of the binding tx differs")
	}
	if _, _, ok := root.GhostBinding(); ok {
		t.Fatal("a root has a binding")
	}
	if btx.Nonce() != 7 || btx.Gas() != 100_000 || *btx.To() != to || btx.Value().Int64() != 5 || !bytes.Equal(btx.Data(), []byte{1, 2, 3}) {
		t.Fatal("binding tx fields differ")
	}
	if _, _, _, ok := btx.GhostAccountAuth(); ok {
		t.Fatal("a binding tx carries a public key and signature")
	}

	// The transaction hash a binding binds covers every field but the
	// binding, and the genesis; the transaction's Hash covers the binding.
	genesis := common.Hash{0x0e}
	txHash, ok := btx.GhostBindingTxHash(genesis)
	if !ok {
		t.Fatal("no binding tx hash")
	}
	otherBinding := testBindingTx(&to)
	otherBinding.Binding[0] ^= 1
	if h, _ := NewTx(otherBinding).GhostBindingTxHash(genesis); h != txHash {
		t.Fatal("the bound transaction hash covers the binding")
	}
	if NewTx(otherBinding).Hash() == btx.Hash() {
		t.Fatal("the transaction hash does not cover the binding")
	}
	if h, _ := btx.GhostBindingTxHash(common.Hash{0x0f}); h == txHash {
		t.Fatal("the bound transaction hash does not cover the genesis")
	}
	for name, change := range map[string]func(tx *GhostBindingTx){
		"nonce":  func(tx *GhostBindingTx) { tx.Nonce++ },
		"value":  func(tx *GhostBindingTx) { tx.Value = big.NewInt(6) },
		"data":   func(tx *GhostBindingTx) { tx.Data = []byte{1, 2, 4} },
		"to":     func(tx *GhostBindingTx) { tx.To = &common.Address{0x71} },
		"scheme": func(tx *GhostBindingTx) { tx.Scheme = GhostScheme(GhostSchemeSLHDSA) },
		"chain":  func(tx *GhostBindingTx) { tx.ChainID = big.NewInt(2) },
		"gas":    func(tx *GhostBindingTx) { tx.Gas++ },
	} {
		changed := testBindingTx(&to)
		change(changed)
		if h, _ := NewTx(changed).GhostBindingTxHash(genesis); h == txHash {
			t.Errorf("%s: the bound transaction hash did not change", name)
		}
	}

	// A raw-signature account transaction beside them.
	var seed [mldsa44.SeedSize]byte
	seed[0] = 0x52
	_, key := mldsa44.NewKeyFromSeed(&seed)
	signer := NewGhostAccountSigner(NewCancunSigner(big.NewInt(1)), genesis)
	raw, err := SignGhostAccountTx(signer, key, &GhostAccountTx{
		ChainID: big.NewInt(1), Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 50_000, To: &to, Value: big.NewInt(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	rawFrom, err := Sender(signer, raw)
	if err != nil || rawFrom != GhostAccountAddressOf(GhostSchemeMLDSA44, key.Public().(*mldsa44.PublicKey).Bytes()) {
		t.Fatalf("raw-signature sender %x: %v", rawFrom, err)
	}

	// Binary, RLP in a block body list and JSON, for both new types and the
	// raw-signature transaction.
	for _, tx := range []*Transaction{root, btx} {
		bin, err := tx.MarshalBinary()
		if err != nil || bin[0] != tx.Type() {
			t.Fatalf("type %#x: MarshalBinary: %v", tx.Type(), err)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(bin); err != nil || dec.Type() != tx.Type() || dec.Hash() != tx.Hash() || dec.Size() != uint64(len(bin)) {
			t.Fatalf("type %#x: binary round trip: %v", tx.Type(), err)
		}
		js, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		var fromJSON Transaction
		if err := json.Unmarshal(js, &fromJSON); err != nil || fromJSON.Hash() != tx.Hash() || fromJSON.Type() != tx.Type() {
			t.Fatalf("type %#x: JSON round trip: %v", tx.Type(), err)
		}
	}
	if bin, _ := root.MarshalBinary(); !bytes.Equal(bin, env) {
		t.Fatal("the root's MarshalBinary is not its envelope")
	}
	list, err := rlp.EncodeToBytes(Transactions{root, btx, raw})
	if err != nil {
		t.Fatal(err)
	}
	var txs Transactions
	if err := rlp.DecodeBytes(list, &txs); err != nil || len(txs) != 3 {
		t.Fatalf("list round trip: %v", err)
	}
	if txs[0].Hash() != root.Hash() || txs[1].Hash() != btx.Hash() || txs[2].Hash() != raw.Hash() || txs[2].Type() != GhostAccountTxType {
		t.Fatal("list round trip changed a transaction")
	}
	if _, b, _ := txs[1].GhostBinding(); b != inner.Binding {
		t.Fatal("list round trip changed the binding")
	}
	if from, err := Sender(signer, txs[2]); err != nil || from != rawFrom {
		t.Fatalf("decoded raw-signature sender %x: %v", from, err)
	}

	// No sender under any signer: a root has no account, and a binding
	// transaction's account is proved by its block's root only.
	for _, s := range []Signer{NewCancunSigner(big.NewInt(1)), HomesteadSigner{}, signer} {
		if addr, err := Sender(s, root); !errors.Is(err, ErrNoSender) || addr != (common.Address{}) {
			t.Errorf("%T: root sender %x, error %v", s, addr, err)
		}
		if addr, err := Sender(s, NewTx(inner)); !errors.Is(err, ErrGhostBindingSender) || addr != (common.Address{}) {
			t.Errorf("%T: binding tx sender %x, error %v", s, addr, err)
		}
	}
	if _, err := GhostAccountAddress(signer, btx); err == nil {
		t.Error("a binding tx has an account transaction address")
	}

	// The strict decoders: a root of count 0 or of a length that is not its
	// count's, a binding of other than 84 bytes and an unknown scheme are
	// refused.
	for name, bad := range map[string][]byte{
		"count 0": func() []byte {
			e := testPublicRootEnvelope(1)
			binary.BigEndian.PutUint16(e[11:], 0)
			return e[:1+GhostPublicRootFixedSize]
		}(),
		"count 2 of 1":  func() []byte { e := testPublicRootEnvelope(1); binary.BigEndian.PutUint16(e[11:], 2); return e }(),
		"one byte more": append(testPublicRootEnvelope(1), 0),
		"one byte less": testPublicRootEnvelope(1)[:1+GhostPublicRootPayloadSize(1)-1],
		"header only":   testPublicRootEnvelope(1)[:1+GhostPublicRootHeaderSize],
	} {
		if _, err := NewGhostPublicRootTx(bad); !errors.Is(err, ErrGhostPublicRootLength) {
			t.Errorf("root %s: %v, want %v", name, err, ErrGhostPublicRootLength)
		}
		var dec Transaction
		if err := dec.UnmarshalBinary(bad); err == nil {
			t.Errorf("root %s decoded", name)
		}
	}
	short := struct {
		ChainID    *big.Int
		Nonce      uint64
		GasTipCap  *big.Int
		GasFeeCap  *big.Int
		Gas        uint64
		To         *common.Address `rlp:"nil"`
		Value      *big.Int
		Data       []byte
		AccessList AccessList
		Scheme     [2]byte
		Binding    []byte
	}{inner.ChainID, inner.Nonce, inner.GasTipCap, inner.GasFeeCap, inner.Gas, inner.To, inner.Value, inner.Data, inner.AccessList, inner.Scheme, inner.Binding[:83]}
	payload, err := rlp.EncodeToBytes(short)
	if err != nil {
		t.Fatal(err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(append([]byte{GhostBindingTxType}, payload...)); err == nil {
		t.Error("a binding of 83 bytes decoded")
	}
	short.Binding = append(inner.Binding[:], 0)
	payload, _ = rlp.EncodeToBytes(short)
	if err := dec.UnmarshalBinary(append([]byte{GhostBindingTxType}, payload...)); err == nil {
		t.Error("a binding of 85 bytes decoded")
	}
	unknown := testBindingTx(&to)
	unknown.Scheme = GhostScheme(0x0009)
	bin, _ := NewTx(unknown).MarshalBinary()
	if err := dec.UnmarshalBinary(bin); !errors.Is(err, ErrGhostAccountScheme) {
		t.Errorf("an unknown scheme decoded: %v", err)
	}
	if err := NewTx(unknown).CheckGhostBindingShape(); !errors.Is(err, ErrGhostAccountScheme) {
		t.Errorf("an unknown scheme passed the shape check: %v", err)
	}
	js, _ := json.Marshal(btx)
	var obj map[string]interface{}
	if err := json.Unmarshal(js, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["publicKey"]; ok {
		t.Error("a binding tx's JSON has a public key")
	}
	obj["binding"] = "0x00"
	js, _ = json.Marshal(obj)
	if err := json.Unmarshal(js, &dec); err == nil {
		t.Error("a JSON binding of one byte decoded")
	}

	// The receipts: typed 0x56 and 0x57, round trip in every encoding.
	for _, typ := range []byte{GhostPublicRootTxType, GhostBindingTxType} {
		r := &Receipt{Type: typ, Status: ReceiptStatusSuccessful, CumulativeGasUsed: 21_000, Logs: []*Log{{Address: common.Address{1}, Topics: []common.Hash{{2}}, Data: []byte{3}}}}
		r.Bloom = CreateBloom(Receipts{r})
		rbin, err := r.MarshalBinary()
		if err != nil || rbin[0] != typ {
			t.Fatalf("receipt %#x: %v", typ, err)
		}
		var rdec Receipt
		if err := rdec.UnmarshalBinary(rbin); err != nil || rdec.Type != typ || rdec.CumulativeGasUsed != 21_000 || len(rdec.Logs) != 1 {
			t.Fatalf("receipt %#x round trip: %v", typ, err)
		}
		var buf bytes.Buffer
		Receipts{r}.EncodeIndex(0, &buf)
		if !bytes.Equal(buf.Bytes(), rbin) {
			t.Fatalf("receipt %#x trie encoding differs from the binary encoding", typ)
		}
	}
	// A creating binding transaction creates at its binding's account; a
	// root creates nothing.
	create := NewTx(testBindingTx(nil))
	rs := Receipts{
		{Type: GhostPublicRootTxType, Status: ReceiptStatusSuccessful},
		{Type: GhostBindingTxType, Status: ReceiptStatusSuccessful, CumulativeGasUsed: 60_000},
	}
	if err := rs.DeriveFields(params.TestChainConfig, common.Hash{9}, 4, 0, big.NewInt(7), nil, Transactions{root, create}); err != nil {
		t.Fatal(err)
	}
	if rs[0].ContractAddress != (common.Address{}) || rs[0].GasUsed != 0 {
		t.Fatalf("root derived fields: %+v", rs[0])
	}
	if want := crypto.CreateAddress(inner.Binding.Account(), 7); rs[1].ContractAddress != want || rs[1].GasUsed != 60_000 {
		t.Fatalf("binding tx contract address %x, want %x", rs[1].ContractAddress, want)
	}
}
