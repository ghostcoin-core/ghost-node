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

package ghosttree

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
)

// fullNote is a 380-byte note whose every byte, the last 224 past the old
// 156-byte note included, is non-zero and differs from note to note.
func fullNote(seed byte) (note [NoteBytes]byte) {
	for i := range note {
		note[i] = seed ^ byte(i*7+1) | 0x01
	}
	return note
}

// TestNoteBytes380 checks that every commitment's note is 380 bytes (12
// nonce, 352 plaintext, 16 tag), that the history stores a leaf record of 8 +
// 32 + 380 bytes (16 more with a salt) and reads it back byte for byte, that
// a record of the old 156-byte note is corrupt, and that the pages and note
// buckets serve each leaf with all 380 bytes of its note.
func TestNoteBytes380(t *testing.T) {
	if NoteBytes != 12+352+16 {
		t.Fatalf("NoteBytes %d, want 380", NoteBytes)
	}
	if storedSize != 420 || storedSaltedSize != 436 {
		t.Fatalf("stored record of %d bytes, salted %d, want 420 and 436", storedSize, storedSaltedSize)
	}

	// A history record round trip, with and without a salt.
	for _, salt := range []*[SaltBytes]byte{nil, testSalt(7)} {
		rec := &stored{number: 0x0102030405060708, leaf: testLeaf(380), note: fullNote(0x5c), salt: salt}
		enc := rec.encode()
		want := 8 + 32 + 380
		if salt != nil {
			want += SaltBytes
		}
		if len(enc) != want {
			t.Fatalf("encoded record of %d bytes, want %d", len(enc), want)
		}
		if !bytes.Equal(enc[40:420], rec.note[:]) {
			t.Fatal("the note is not stored as bytes 40 to 420 of the record")
		}
		dec, err := decodeStored(enc)
		if err != nil {
			t.Fatal(err)
		}
		if dec.number != rec.number || dec.leaf != rec.leaf || dec.note != rec.note {
			t.Fatalf("record round trip: %+v, want %+v", dec, rec)
		}
		if (dec.salt == nil) != (salt == nil) || (salt != nil && *dec.salt != *salt) {
			t.Fatalf("salt round trip: %v, want %v", dec.salt, salt)
		}
	}
	for _, size := range []int{8 + 32 + 156, 8 + 32 + 156 + SaltBytes, 419, 421, 437} {
		if _, err := decodeStored(make([]byte, size)); !errors.Is(err, ErrCorruptHistory) {
			t.Errorf("record of %d bytes: %v, want %v", size, err, ErrCorruptHistory)
		}
	}

	// A block of coin and data leaves with full 380-byte notes, one salted.
	c := newTestChain(t)
	b := c.next(c.head(), 3, 3, 2)
	for i := range b.records {
		b.records[i].Note = fullNote(byte(0x20 + i))
	}
	b.records[1].Salt = testSalt(9)
	c.insert(b)
	byPos := map[Kind][]Record{}
	for _, r := range b.records {
		byPos[r.Kind] = append(byPos[r.Kind], r)
	}
	for kind, recs := range byPos {
		for _, r := range recs {
			enc, err := rawdb.ReadGhostTreeLeaf(c.db, uint8(kind), 0, r.Position)
			if err != nil || enc == nil {
				t.Fatalf("%v position %d not stored: %v", kind, r.Position, err)
			}
			want := 420
			if r.Salt != nil {
				want = 436
			}
			if len(enc) != want || !bytes.Equal(enc[40:420], r.Note[:]) {
				t.Errorf("%v position %d stored in %d bytes, want %d with the whole note", kind, r.Position, len(enc), want)
			}
		}

		// The page serves every byte of every note.
		page, err := c.h.Page(kind, 0, 0, b.hash())
		if err != nil {
			t.Fatal(err)
		}
		if int(page.Filled) != len(recs) {
			t.Fatalf("%v page of %d entries, want %d", kind, page.Filled, len(recs))
		}
		for i, e := range page.Entries {
			if len(e.Note) != 380 || e.Note != recs[i].Note || e.Leaf != recs[i].Leaf {
				t.Errorf("%v page entry %d: note of %d bytes %x, want %x", kind, i, len(e.Note), e.Note[:], recs[i].Note[:])
			}
			if e.Note[NoteBytes-1] == 0 || !bytes.Equal(e.Note[156:], recs[i].Note[156:]) {
				t.Errorf("%v page entry %d lost the note past byte 156", kind, i)
			}
		}

		// The bucket of the whole tree (0 bits) serves the same notes.
		bucket, err := ReadNoteBucket(c.h, kind, 0, 0, 0, b.hash())
		if err != nil {
			t.Fatal(err)
		}
		if len(bucket.Entries) != len(recs) {
			t.Fatalf("%v bucket of %d entries, want %d", kind, len(bucket.Entries), len(recs))
		}
		for i, e := range bucket.Entries {
			if e.Position != recs[i].Position || len(e.Note) != 380 || e.Note != recs[i].Note {
				t.Errorf("%v bucket entry %d: position %d note %x, want %d %x", kind, i, e.Position, e.Note[:], recs[i].Position, recs[i].Note[:])
			}
		}
	}
	if len(byPos[Coin]) != 3 || len(byPos[Data]) != 2 {
		t.Fatalf("block records %d coin and %d data", len(byPos[Coin]), len(byPos[Data]))
	}
	if page, err := c.h.Page(Coin, 0, 0, b.hash()); err != nil || page.Entries[1].Salt == nil || *page.Entries[1].Salt != *testSalt(9) {
		t.Fatalf("the salted 380-byte note lost its salt: %v", err)
	}
}
