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
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// lookupTestTag is the tag of decision 0004's vector lookup-tag for i.
func lookupTestTag(i uint64) ghosttree.LookupTag {
	return ghosttree.DeriveLookupTag(common.HexToHash("35136c4a7bdccb4b26159c15f86567a483ac58e1b2c40dca49a5d099272c4181"), i)
}

// TestLookupTagPayload checks the lookup tag of decision 0004 in the commit
// payloads: 16 bytes after the note of a coin commit and of a data commit,
// carried by the parsed commit into its leaf's entry of the lookup index,
// with 16 zero bytes and a tag of any other width refused. On a chain, a
// commit's leaf and a coin reveal's remainder take their positions in the
// coin tree, the commit's with its tag in the coin lookup index; the
// remainder, whose reveal carries no tag yet, takes no entry, and the
// spent marker's leaf in the coin marker set names it.
func TestLookupTagPayload(t *testing.T) {
	c := testCoin("lookup tag", oneGhost)
	salt := testSalt(0x46)
	tag := lookupTestTag(1)
	data, err := ghostpriv.LookupCommitData(c.f, salt, c.note, tag[:])
	if err != nil {
		t.Fatal(err)
	}
	if ghostpriv.SaltedCommitDataSize != 2+32+ghostpriv.SaltSize+ghostpriv.NoteSize+ghostpriv.LookupTagSize || ghostpriv.LookupTagSize != 16 {
		t.Fatalf("SaltedCommitDataSize %d", ghostpriv.SaltedCommitDataSize)
	}
	if len(data) != ghostpriv.SaltedCommitDataSize {
		t.Fatalf("commit data of %d bytes", len(data))
	}
	noteAt := 2 + 32 + ghostpriv.SaltSize
	if !bytes.Equal(data[noteAt:noteAt+ghostpriv.NoteSize], c.note) || !bytes.Equal(data[noteAt+ghostpriv.NoteSize:], tag[:]) {
		t.Fatal("the tag is not the 16 bytes after the note")
	}
	cc, err := ghostpriv.ParseCommit(data, oneGhost)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Tag != tag || !bytes.Equal(cc.Note[:], c.note) {
		t.Errorf("coin commit tag %x, want %x", cc.Tag, tag)
	}
	dc, err := ghostpriv.ParseDataCommit(data, ghostpriv.DataReserve.ToBig())
	if err != nil {
		t.Fatal(err)
	}
	if dc.Tag != tag || !bytes.Equal(dc.Note[:], c.note) {
		t.Errorf("data commit tag %x, want %x", dc.Tag, tag)
	}
	// SaltedCommitData gives a sender without a lookup key a tag of F.
	plain, err := ghostpriv.SaltedCommitData(c.f, salt, c.note)
	if err != nil {
		t.Fatal(err)
	}
	if fallback := ghostpriv.FallbackLookupTag(c.f); fallback.IsZero() || !bytes.Equal(plain[noteAt+ghostpriv.NoteSize:], fallback[:]) {
		t.Errorf("SaltedCommitData carries %x, want the fallback tag %x", plain[noteAt+ghostpriv.NoteSize:], fallback)
	}

	// 16 zero bytes are refused by both parsers and by the builder.
	zero := append(append([]byte{}, data[:noteAt+ghostpriv.NoteSize]...), make([]byte, ghostpriv.LookupTagSize)...)
	if _, err := ghostpriv.ParseCommit(zero, oneGhost); !errors.Is(err, ghostpriv.ErrCommitLookupTag) {
		t.Errorf("coin commit with the zero tag: %v, want %v", err, ghostpriv.ErrCommitLookupTag)
	}
	if _, err := ghostpriv.ParseDataCommit(zero, ghostpriv.DataReserve.ToBig()); !errors.Is(err, ghostpriv.ErrCommitLookupTag) {
		t.Errorf("data commit with the zero tag: %v, want %v", err, ghostpriv.ErrCommitLookupTag)
	}
	if _, err := ghostpriv.LookupCommitData(c.f, salt, c.note, make([]byte, ghostpriv.LookupTagSize)); !errors.Is(err, ghostpriv.ErrCommitLookupTag) {
		t.Errorf("building with the zero tag: %v", err)
	}
	// A tag of another width is another length of data.
	for _, width := range []int{0, 1, 15, 17, 32} {
		bad := append(append([]byte{}, data[:noteAt+ghostpriv.NoteSize]...), bytes.Repeat([]byte{0x5a}, width)...)
		if _, err := ghostpriv.ParseCommit(bad, oneGhost); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("coin commit with a %d-byte tag: %v, want %v", width, err, ghostpriv.ErrCommitData)
		}
		if _, err := ghostpriv.ParseDataCommit(bad, ghostpriv.DataReserve.ToBig()); !errors.Is(err, ghostpriv.ErrCommitData) {
			t.Errorf("data commit with a %d-byte tag: %v, want %v", width, err, ghostpriv.ErrCommitData)
		}
		if _, err := ghostpriv.LookupCommitData(c.f, salt, c.note, bytes.Repeat([]byte{0x5a}, width)); err == nil {
			t.Errorf("built commit data with a %d-byte tag", width)
		}
	}

	// On a chain: the zero tag is refused at the entry addresses and
	// appends nothing; a tagged commit and data commit put their tags into
	// the indices.
	f := newFixture(t, ghost.InternalNetGasLimit, nil)
	chain := f.newChain()
	env, st := nextEnv(t, chain, chain.CurrentBlock(), common.Address{0xcb})
	for _, to := range []struct {
		addr  common.Address
		value *big.Int
	}{{ghost.CommitEntryAddress, oneGhost}, {ghost.DataCommitEntryAddress, ghostpriv.DataReserve.ToBig()}} {
		cp := st.Copy()
		if _, err := applyTx(chain, cp, env.Header, f.callTx(keyA, 0, to.addr, to.value, zero, 60_000)); !errors.Is(err, ghostpriv.ErrCommitLookupTag) {
			t.Errorf("zero tag to %x: %v, want %v", to.addr, err, ghostpriv.ErrCommitLookupTag)
		}
		if coinLeafCount(cp) != 0 {
			t.Errorf("zero tag to %x appended a leaf", to.addr)
		}
	}
	dtag := lookupTestTag(2)
	ddata, err := ghostpriv.LookupCommitData(ghosttree.K("ghost/test-data-f", []byte("lookup")), salt, c.note, dtag[:])
	if err != nil {
		t.Fatal(err)
	}
	cp := st.Copy()
	if r, err := applyTx(chain, cp, env.Header, f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, data, 60_000)); err != nil || r.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("tagged commit: %v", err)
	}
	if r, err := applyTx(chain, cp, env.Header, f.callTx(keyA, 1, ghost.DataCommitEntryAddress, ghostpriv.DataReserve.ToBig(), ddata, 60_000)); err != nil || r.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("tagged data commit: %v", err)
	}
	if got, ok, err := ghosttree.LookupEntry(cp, ghosttree.Coin, 0); err != nil || !ok || got != tag {
		t.Errorf("coin entry of position 0: %x %v %v, want %x", got, ok, err, tag)
	}
	if got, ok, err := ghosttree.LookupEntry(cp, ghosttree.Data, 0); err != nil || !ok || got != dtag {
		t.Errorf("data entry of position 0: %x %v %v, want %x", got, ok, err, dtag)
	}
	root, err := ghosttree.LookupRoot(cp, ghosttree.Coin)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ghosttree.LookupMembershipWitness(cp, ghosttree.Coin, 0)
	if err != nil || !ghosttree.VerifyLookupMembership(ghosttree.Coin, root, tag, 0, w) {
		t.Errorf("membership of the commit's tag (%v)", err)
	}
	b, err := ghosttree.ReadBlockLookup(cp, env.Header.Number.Uint64())
	if err != nil {
		t.Fatal(err)
	}
	if b.CoinStart != 0 || len(b.CoinTags) != 1 || b.CoinTags[0] != tag || b.DataStart != 0 || len(b.DataTags) != 1 || b.DataTags[0] != dtag {
		t.Errorf("block lists %+v", b)
	}

	// The coin reveal: its remainder takes the next position and no entry,
	// and the marker's leaf names the remainder.
	useStub(t)
	marker := testMarker("lookup tag")
	out := u256(ghostAmount(1, 4))
	var revealAt int
	blocks, _ := f.generate(3, func(i int, b *core.BlockGen) {
		switch i {
		case 0:
			b.AddTx(f.callTx(keyA, 0, ghost.CommitEntryAddress, oneGhost, data, 60_000))
		case 2:
			fee := genWindowFee(t, b).Total
			rest := new(uint256.Int).Sub(c.value, out)
			rest.Sub(rest, fee)
			b.AddTx(revealTx(t, f.newReveal(genParentRoot(b), marker, testCoin("lookup tag rest", rest.ToBig()), common.Address{0x9e}, out, fee)))
			revealAt = i + 1
		}
	})
	fresh := f.newChain()
	f.insert(fresh, blocks)
	head, err := fresh.State()
	if err != nil {
		t.Fatal(err)
	}
	if !ghosttree.IsSpent(head, ghosttree.Coin, marker) {
		t.Fatal("the reveal did not spend its marker")
	}
	if got, ok, err := ghosttree.LookupEntry(head, ghosttree.Coin, 0); err != nil || !ok || got != tag {
		t.Errorf("commit entry %x %v %v", got, ok, err)
	}
	if _, ok, err := ghosttree.LookupEntry(head, ghosttree.Coin, 1); ok || err != nil {
		t.Errorf("the remainder has an entry (%v)", err)
	}
	if n := ghosttree.CoinMarkerSetCount(head); n != 2 {
		t.Fatalf("coin marker set count %d, want 2", n)
	}
	if v, _, _, appended, err := ghosttree.CoinMarkerSetLeaf(head, 1); err != nil || v != marker || appended != 1 {
		t.Errorf("marker leaf (%x, appended %d) %v, want (%x, appended 1)", v, appended, err, marker)
	}
	rb, err := ghosttree.ReadBlockLookup(head, uint64(revealAt))
	if err != nil {
		t.Fatal(err)
	}
	if rb.CoinStart != 1 || len(rb.CoinTags) != 1 || !rb.CoinTags[0].IsZero() || len(rb.CoinMarkers) != 1 || rb.CoinMarkers[0] != marker {
		t.Errorf("reveal block lists %+v", rb)
	}
	// The zero coin marker, the coin marker set's sentinel, is refused.
	renv, rst := nextEnv(t, fresh, fresh.CurrentBlock(), common.Address{0xcc})
	fee := chainWindowFee(t, fresh, renv.Header).Total
	zr := f.newReveal(*fresh.CurrentBlock().CoinTreeRoot, common.Hash{}, testCoin("lookup zero marker", oneGhost), common.Address{0x9f}, out, fee)
	if _, _, err := ghostpriv.CheckReveal(rst, renv, nil, envelope(t, zr)); !errors.Is(err, ghostpriv.ErrRevealMarker) || !errors.Is(err, ghosttree.ErrZeroMarker) {
		t.Errorf("zero coin marker: %v, want %v", err, ghosttree.ErrZeroMarker)
	}
}
