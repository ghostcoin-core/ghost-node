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

package ghostpriv_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// TestNote380Commit checks the commit data of spec 10, section 3.2: version
// 3, F, the salt and a 380-byte note, 430 bytes, accepted for a coin commit
// and a data commit with the version 2 commitment types; version 2 (206
// bytes, or 430), version 1 and 429 or 431 bytes are ErrCommitData. The
// receipt logs of both commits carry the whole 380-byte note, and
// HistoryRecords returns it, as it returns the whole 380-byte remainder note
// of a version 2 reveal; a version 1 reveal's 156-byte remainder note, and
// the 156-byte note of the 244-byte log of an old salted commit, are recorded
// zero-padded to 380 bytes.
func TestNote380Commit(t *testing.T) {
	if ghostpriv.NoteSize != 380 {
		t.Fatalf("NoteSize %d, want 380", ghostpriv.NoteSize)
	}
	if ghosttree.NoteBytes != 380 {
		t.Fatalf("ghosttree.NoteBytes %d, want 380", ghosttree.NoteBytes)
	}
	if ghostpriv.SaltedCommitDataSize != 2+32+16+380 {
		t.Fatalf("SaltedCommitDataSize %d, want 430", ghostpriv.SaltedCommitDataSize)
	}
	if ghostpriv.SaltedCommitVersion != 0x0003 {
		t.Fatalf("SaltedCommitVersion %#x, want 0x0003", ghostpriv.SaltedCommitVersion)
	}

	c := testCoin("note 380", oneGhost)
	salt := testSalt(0x38)
	if len(c.note) != 380 || c.note[379] == 0 {
		t.Fatalf("test note of %d bytes", len(c.note))
	}
	data, err := ghostpriv.SaltedCommitData(c.f, salt, c.note)
	if err != nil {
		t.Fatal(err)
	}
	want := binary.BigEndian.AppendUint16(nil, 0x0003)
	want = append(append(append(want, c.f[:]...), salt...), c.note...)
	if len(data) != 430 || !bytes.Equal(data, want) {
		t.Fatalf("commit data of %d bytes\n%x\nwant\n%x", len(data), data, want)
	}
	if _, err := ghostpriv.SaltedCommitData(c.f, salt, c.note[:156]); err == nil {
		t.Fatal("built commit data with a 156-byte note")
	}

	// Version 3 is accepted for a coin commit and a data commit, and the
	// commitment keeps the version 2 types.
	word, reserveWord := c.value.Bytes32(), ghostpriv.DataReserve.Bytes32()
	cc, err := ghostpriv.ParseCommit(data, oneGhost)
	if err != nil {
		t.Fatalf("coin commit of version 3: %v", err)
	}
	if cc.CommitVersion() != 3 || !bytes.Equal(cc.Note[:], c.note) || cc.Salt == nil || !bytes.Equal(cc.Salt[:], salt) {
		t.Fatalf("parsed coin commit %+v", cc)
	}
	if got, want := cc.Commitment(), ghosttree.K("ghost/coin-commitment/v1", []byte{0x02, 0x01}, c.f[:], word[:]); got != want {
		t.Fatalf("coin commitment %x, want %x", got, want)
	}
	dc, err := ghostpriv.ParseDataCommit(data, ghostpriv.DataReserve.ToBig())
	if err != nil {
		t.Fatalf("data commit of version 3: %v", err)
	}
	if dc.CommitVersion() != 3 || !bytes.Equal(dc.Note[:], c.note) || dc.Salt == nil || !bytes.Equal(dc.Salt[:], salt) {
		t.Fatalf("parsed data commit %+v", dc)
	}
	if got, want := dc.Commitment(), ghosttree.K("ghost/data-commitment/v1", []byte{0x02, 0x02}, reserveWord[:], c.f[:]); got != want {
		t.Fatalf("data commitment %x, want %x", got, want)
	}

	// Every other version or length is ErrCommitData.
	with := func(change func([]byte) []byte) []byte { return change(append([]byte{}, data...)) }
	wrong := []struct {
		name string
		data []byte
	}{
		{"206 bytes of version 2", versionTwoCommitData(c.f, salt, c.note[:156])},
		{"430 bytes of version 2", with(func(d []byte) []byte { d[1] = 2; return d })},
		{"430 bytes of version 1", with(func(d []byte) []byte { d[1] = 1; return d })},
		{"version 1 layout", versionOneCommitData(c.f, c.note)},
		{"version 1 layout with a 156-byte note", versionOneCommitData(c.f, c.note[:156])},
		{"429 bytes", data[:429]},
		{"431 bytes", with(func(d []byte) []byte { return append(d, 0) })},
	}
	for _, w := range wrong {
		if _, err := ghostpriv.ParseCommit(w.data, oneGhost); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("%s: coin commit %v, want %v", w.name, err, ghostpriv.ErrCommitData)
		}
		if _, err := ghostpriv.ParseDataCommit(w.data, ghostpriv.DataReserve.ToBig()); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("%s: data commit %v, want %v", w.name, err, ghostpriv.ErrCommitData)
		}
	}

	// On the chain: the 430 bytes commit, the 206 bytes of version 2 do not.
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	for _, to := range []struct {
		name  string
		addr  common.Address
		value *big.Int
	}{
		{"coin commit", ghost.CommitEntryAddress, oneGhost},
		{"data commit", ghost.DataCommitEntryAddress, ghostpriv.DataReserve.ToBig()},
	} {
		r, err := applyTx(chain, st.Copy(), env.Header, f.callTx(keyA, 0, to.addr, to.value, data, 60_000))
		if err != nil || r.Status != types.ReceiptStatusSuccessful || len(r.Logs) != 1 {
			t.Fatalf("%s of 430 bytes: %v", to.name, err)
		}
		if _, err := applyTx(chain, st.Copy(), env.Header, f.callTx(keyA, 0, to.addr, to.value, wrong[0].data, 60_000)); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("%s of 206 bytes of version 2: %v, want %v", to.name, err, ghostpriv.ErrCommitData)
		}
	}

	// The receipt logs carry the 380-byte note, then the salt.
	height := env.Header.Number.Uint64()
	coinState := &logState{StateDB: st.Copy()}
	if err := ghostpriv.ApplyCommit(coinState, height, addrA, cc); err != nil {
		t.Fatal(err)
	}
	dataState := &logState{StateDB: st.Copy()}
	if err := ghostpriv.ApplyDataCommit(dataState, height, addrA, dc); err != nil {
		t.Fatal(err)
	}
	if len(coinState.logs) != 1 || len(dataState.logs) != 1 {
		t.Fatalf("%d coin and %d data logs", len(coinState.logs), len(dataState.logs))
	}
	coinLog, dataLog := coinState.logs[0], dataState.logs[0]
	if len(coinLog.Data) != 8+32+32+380+16 || !bytes.Equal(coinLog.Data[72:452], c.note) || !bytes.Equal(coinLog.Data[452:], salt) {
		t.Fatalf("commit log of %d bytes\n%x", len(coinLog.Data), coinLog.Data)
	}
	if len(dataLog.Data) != 8+32+380+16 || !bytes.Equal(dataLog.Data[40:420], c.note) || !bytes.Equal(dataLog.Data[420:], salt) {
		t.Fatalf("data commit log of %d bytes\n%x", len(dataLog.Data), dataLog.Data)
	}

	// A version 2 reveal's log carries its 380-byte note.
	remainder := ghostpriv.CommitmentVersion(ghostpriv.SaltedCommitVersion, ghosttree.K("ghost/test-coin-f", []byte("rest")), uint256.NewInt(5))
	revealLogData := func(note []byte) []byte {
		d := binary.BigEndian.AppendUint32(nil, 0)
		d = binary.BigEndian.AppendUint32(d, 1)
		d = append(d, remainder[:]...)
		d = append(d, note...)
		d = append(d, common.Address{0x7a}.Bytes()...)
		return append(d, make([]byte, 32)...)
	}
	revealLog := &types.Log{
		Address: ghosttree.TreeAccount(ghosttree.Coin),
		Topics:  []common.Hash{ghosttree.K(ghostpriv.TagRevealReceipt), testMarker("note 380")},
		Data:    revealLogData(c.note),
	}

	// HistoryRecords returns the whole note of each commit and of the reveal
	// remainder.
	records, err := ghostpriv.HistoryRecords(types.Receipts{{Logs: []*types.Log{coinLog}}, {Logs: []*types.Log{dataLog, revealLog}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("%d history records, want 4", len(records))
	}
	for i, kind := range []ghosttree.Kind{ghosttree.Coin, ghosttree.Data} {
		r := records[i]
		if r.Kind != kind || len(r.Note) != 380 || !bytes.Equal(r.Note[:], c.note) || r.Salt == nil || !bytes.Equal(r.Salt[:], salt) {
			t.Errorf("record %d: kind %v note %x salt %v", i, r.Kind, r.Note[:], r.Salt)
		}
	}
	if r := records[2]; r.Kind != ghosttree.Coin || r.Leaf != remainder || !bytes.Equal(r.Note[:], c.note) || r.Salt != nil {
		t.Errorf("reveal remainder record: kind %v leaf %x note %x", r.Kind, r.Leaf, r.Note[:])
	}
	if r := records[3]; r.Kind != ghosttree.CoinMarkers || r.Leaf != testMarker("note 380") {
		t.Errorf("reveal marker record %+v", r)
	}

	// The 244-byte log of a salted commit made with the old 156-byte note,
	// which the test chain holds, is read: the record keeps its leaf and
	// salt, with the note zero-padded on the right to 380 bytes.
	old := &types.Log{Address: coinLog.Address, Topics: coinLog.Topics, Data: append(append([]byte{}, coinLog.Data[:72+156]...), salt...)}
	if len(old.Data) != 244 {
		t.Fatalf("old commit log of %d bytes, want 244", len(old.Data))
	}
	records, err = ghostpriv.HistoryRecords(types.Receipts{{Logs: []*types.Log{old}}})
	if err != nil || len(records) != 1 {
		t.Fatalf("commit log of a 156-byte note: %d records, %v", len(records), err)
	}
	if r := records[0]; r.Kind != ghosttree.Coin || r.Leaf != cc.Commitment() || !bytes.Equal(r.Note[:156], c.note[:156]) || !bytes.Equal(r.Note[156:], make([]byte, 380-156)) || r.Salt == nil || !bytes.Equal(r.Salt[:], salt) {
		t.Errorf("old commit record: kind %v leaf %x note %x salt %v", r.Kind, r.Leaf, r.Note[:], r.Salt)
	}
	// A version 1 reveal's log keeps its 156-byte note, which the record
	// holds zero-padded on the right to 380 bytes. A note of any other
	// length is no receipt.
	v1Reveal := &types.Log{Address: revealLog.Address, Topics: revealLog.Topics, Data: revealLogData(c.note[:ghostpriv.RevealNoteSize])}
	records, err = ghostpriv.HistoryRecords(types.Receipts{{Logs: []*types.Log{v1Reveal}}})
	if err != nil || len(records) != 2 {
		t.Fatalf("version 1 reveal log: %d records, %v", len(records), err)
	}
	if r := records[0]; r.Kind != ghosttree.Coin || r.Leaf != remainder || !bytes.Equal(r.Note[:156], c.note[:156]) || !bytes.Equal(r.Note[156:], make([]byte, 380-156)) || r.Salt != nil {
		t.Errorf("version 1 reveal remainder record: kind %v leaf %x note %x", r.Kind, r.Leaf, r.Note[:])
	}
	if r := records[1]; r.Kind != ghosttree.CoinMarkers || r.Leaf != testMarker("note 380") {
		t.Errorf("version 1 reveal marker record %+v", r)
	}
	for _, n := range []int{155, 157, 379} {
		odd := &types.Log{Address: revealLog.Address, Topics: revealLog.Topics, Data: revealLogData(c.note[:n])}
		if _, err := ghostpriv.HistoryRecords(types.Receipts{{Logs: []*types.Log{odd}}}); !errors.Is(err, ghostpriv.ErrReceiptLog) {
			t.Errorf("reveal log of a %d-byte note: %v, want %v", n, err, ghostpriv.ErrReceiptLog)
		}
	}
}

// TestDataRevealNoteSlot checks that the data reveal keeps its 156-byte note
// slot (spec 10, section 10.5) whatever the length of a commitment's note: cf
// in the first 32 bytes and 124 bytes that must be zero, closing a payload of
// 1,311,066 bytes.
func TestDataRevealNoteSlot(t *testing.T) {
	if ghostpriv.DataNoteSlot != 156 {
		t.Fatalf("DataNoteSlot %d, want 156", ghostpriv.DataNoteSlot)
	}
	var r ghostpriv.DataReveal
	if len(r.Note) != 124 {
		t.Fatalf("data reveal note of %d bytes, want 124", len(r.Note))
	}
	if types.GhostDataRevealPayloadSize != 1_311_066 || 190+ghostpriv.ProofSize+ghostpriv.DataNoteSlot != 1_311_066 {
		t.Fatalf("data reveal payload of %d bytes", types.GhostDataRevealPayloadSize)
	}
	r = ghostpriv.DataReveal{
		Version: ghostpriv.Version,
		ChainID: 7,
		Purpose: ghostpriv.PurposeField(ghostpriv.PurposeReveal),
		Proof:   []byte{0x01, 0x02},
		Cf:      ghosttree.K("ghost/test-cf", []byte("slot")),
	}
	r.Note[0], r.Note[123] = 0xa1, 0xb2
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1_311_067 {
		t.Fatalf("data reveal envelope of %d bytes", len(env))
	}
	slot := env[1+190+ghostpriv.ProofSize:]
	if len(slot) != 156 || !bytes.Equal(slot[:32], r.Cf[:]) || slot[32] != 0xa1 || slot[155] != 0xb2 {
		t.Fatalf("note slot of %d bytes: %x", len(slot), slot)
	}
	dec, err := ghostpriv.DecodeDataReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Cf != r.Cf || dec.Note != r.Note {
		t.Fatalf("decoded cf %x note %x", dec.Cf, dec.Note)
	}
}

// TestRevealKeepsNoteSlot checks that the version 2 coin reveal carries a
// 380-byte remainder note: the payload field, the verifier's input and the
// end of the binding digest input, and the envelope is 1,311,291 bytes.
func TestRevealKeepsNoteSlot(t *testing.T) {
	var (
		r  ghostpriv.Reveal
		in ghostpriv.VerifyInputs
	)
	if len(r.Note) != 380 || len(in.Note) != 380 {
		t.Fatalf("reveal note of %d bytes, verifier note of %d", len(r.Note), len(in.Note))
	}
	if ghostpriv.EnvelopeSize != 1_311_291 || ghostpriv.PayloadSize != 1_311_290 || 190+ghostpriv.ProofSize+ghostpriv.NoteSize != 1_311_290 {
		t.Fatalf("reveal envelope %d, payload %d", ghostpriv.EnvelopeSize, ghostpriv.PayloadSize)
	}
	note := testNote(0x41)
	r = ghostpriv.Reveal{
		Version: ghostpriv.RevealVersion,
		ChainID: 7,
		Out:     uint256.NewInt(1),
		Fee:     uint256.NewInt(2),
		Proof:   []byte{0x03},
	}
	copy(r.Note[:], note)
	env, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1_311_291 || !bytes.Equal(env[len(env)-380:], note) {
		t.Fatalf("reveal envelope of %d bytes ends %x", len(env), env[len(env)-380:])
	}
	if ghostpriv.BindingSize != 607 {
		t.Fatalf("BindingSize %d, want 607", ghostpriv.BindingSize)
	}
	if b := r.BindingInput(7, common.Hash{0x01}); len(b) != 607 || !bytes.Equal(b[len(b)-380:], note) {
		t.Fatalf("binding input of %d bytes", len(b))
	}
	dec, err := ghostpriv.DecodeReveal(env)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Note != r.Note {
		t.Fatalf("decoded note %x", dec.Note)
	}
}
