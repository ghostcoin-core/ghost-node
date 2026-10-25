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

//go:build cgo && (ghostrelease || ghostproofs) && (linux || darwin)

package ghostpriv

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// TestGhostDataStatementCarriesFingerprint checks the data reveal statement
// passed through ghost_data.h: ghostDataRevealBytes, 193 bytes, the purpose,
// root, marker, party, fee and rule, then cf at 161..193, and that changing
// cf changes only those bytes.
func TestGhostDataStatementCarriesFingerprint(t *testing.T) {
	if ghostDataRevealBytes != 193 {
		t.Fatalf("GHOST_DATA_REVEAL_BYTES is %d, want 193", ghostDataRevealBytes)
	}
	in := &VerifyInputs{
		Kind:      ghosttree.Data,
		Purpose:   PurposeRevoke,
		Root:      common.Hash{0: 0x22, 31: 0x22},
		Marker:    common.Hash{0: 0x11, 31: 0x11},
		Recipient: common.Address{0: 0x44, 19: 0x44},
		Out:       new(uint256.Int),
		Fee:       uint256.NewInt(0x6666),
		Cf:        common.Hash{0: 0xcf, 15: 0x0f, 31: 0xcf},
	}
	s := ghostDataStatement(in)
	if len(s) != ghostDataRevealBytes {
		t.Fatalf("data statement of %d bytes, want %d", len(s), ghostDataRevealBytes)
	}
	party := common.BytesToHash(in.Recipient[:])
	var want []byte
	want = append(want, 0x03) // GHOST_DATA_PURPOSE_REVOKE
	want = append(want, in.Root[:]...)
	want = append(want, in.Marker[:]...)
	want = append(want, party[:]...)
	want = append(want, amountWord(in.Fee)...)
	want = append(want, in.Rule[:]...)
	want = append(want, in.Cf[:]...)
	if !bytes.Equal(s, want) {
		t.Fatalf("data statement\n%x\nwant\n%x", s, want)
	}
	if !bytes.Equal(s[161:193], in.Cf[:]) {
		t.Fatalf("statement bytes 161..193 are %x, want cf %x", s[161:193], in.Cf)
	}

	// Changing cf changes bytes 161..193 and nothing else.
	for _, cf := range []common.Hash{{}, {31: 0x01}, {0: 0xff}, common.HexToHash("0x5d")} {
		other := *in
		other.Cf = cf
		o := ghostDataStatement(&other)
		if len(o) != ghostDataRevealBytes || !bytes.Equal(o[:161], s[:161]) {
			t.Fatalf("cf %x changed the statement before byte 161", cf)
		}
		if !bytes.Equal(o[161:], cf[:]) {
			t.Fatalf("cf %x: statement bytes 161..193 are %x", cf, o[161:])
		}
		if bytes.Equal(o, s) {
			t.Fatalf("cf %x left the statement as it was", cf)
		}
	}
}
