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
	"errors"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// oldNoteBytes is the size of the note before the version 3 note.
const oldNoteBytes = 156

// rewriteOldSize stores every record of the history again in the layout of
// the old note size: the block number, the leaf, the first oldNoteBytes of
// the note and the salt of a salted commit after it, as a node wrote them
// before the note grew. It returns how many records of each length it wrote.
func rewriteOldSize(t *testing.T, c *syncChain) map[int]int {
	t.Helper()
	prefix := []byte("ghost-tree-leaf-")
	type kv struct{ key, value []byte }
	var old []kv
	it := c.db.NewIterator(prefix, nil)
	for it.Next() {
		rec, err := decodeStored(it.Value())
		if err != nil {
			t.Fatalf("record %x before the rewrite: %v", it.Key(), err)
		}
		value := make([]byte, 0, 8+common.HashLength+oldNoteBytes+SaltBytes)
		value = append(value, it.Value()[:8]...)
		value = append(value, rec.leaf[:]...)
		value = append(value, rec.note[:oldNoteBytes]...)
		if rec.salt != nil {
			value = append(value, rec.salt[:]...)
		}
		old = append(old, kv{common.CopyBytes(it.Key()), value})
	}
	it.Release()
	if err := it.Error(); err != nil {
		t.Fatal(err)
	}
	sizes := make(map[int]int)
	for _, e := range old {
		if err := c.db.Put(e.key, e.value); err != nil {
			t.Fatal(err)
		}
		sizes[len(e.value)]++
	}
	return sizes
}

// TestSyncRebuildsOnCorruptOldSizeRecord starts a node on a tree history
// written with the old note size, as the test network node had after the
// note grew: Sync must build the history again from genesis, both when the
// chain head moves on and when it is still the stored head, instead of
// failing with a corrupt record on every block.
func TestSyncRebuildsOnCorruptOldSizeRecord(t *testing.T) {
	c := newSyncChain(t)
	chain := c.branch(c.genesis, 1, 4, 30, 30, 20, 20)
	// Salted commits too, whose old record is 56 bytes and the note longer.
	for _, b := range chain {
		for i := range b.records {
			if b.records[i].Kind.valid() && i%2 == 0 {
				b.records[i].Salt = testSalt(byte(i))
			}
		}
	}
	c.setHead(chain[1])

	oldPlain := 8 + common.HashLength + oldNoteBytes
	sizes := rewriteOldSize(t, c)
	if sizes[oldPlain] == 0 || sizes[oldPlain+SaltBytes] == 0 {
		t.Fatalf("old-size history has records of lengths %v, want both %d and %d", sizes, oldPlain, oldPlain+SaltBytes)
	}
	// The old history cannot be served as it stands.
	if _, err := c.h.Page(Coin, 0, 0, chain[1].hash()); !errors.Is(err, ErrCorruptHistory) {
		t.Fatalf("coin page on the old-size history: %v, want %v", err, ErrCorruptHistory)
	}

	// The chain moves on: the next sync rebuilds instead of failing.
	c.setHead(chain[2])
	c.checkServed(chain[2])

	// A node restarted on an old-size history at its own head rebuilds it
	// too, rather than keeping a history it cannot serve.
	rewriteOldSize(t, c)
	c.setHead(chain[2])
	c.checkServed(chain[2])

	// And the rebuilt store is the one a node that never had the old
	// history keeps, which the next blocks extend as usual.
	c.setHead(chain[3])
	c.checkServed(chain[3])
	ref := newSyncChain(t)
	for _, b := range c.ancestry(chain[3]) {
		ref.add(b)
	}
	ref.setHead(chain[3])
	got, want := historyContents(t, c.db), historyContents(t, ref.db)
	// Block entries of blocks above a rebuilt head are not removed by a
	// rebuild; here every block is on the chain, so the stores are equal.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("history after the rebuild has %d entries, a fresh store %d", len(got), len(want))
	}
}
