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

package snapshot

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/holiman/uint256"
)

// shutdownDB wraps a key-value store, holds the snapshot generator at its first
// iterator until the gate opens, and counts every access made after the store
// was marked closed.
type shutdownDB struct {
	ethdb.KeyValueStore

	gate    chan struct{} // Closed to let the generator proceed
	entered chan struct{} // Closed when the generator reached the gate
	once    sync.Once

	closed     atomic.Bool  // Set once the owner considers the store closed
	lateAccess atomic.Int32 // Number of accesses after the store was closed
}

func (db *shutdownDB) touch() {
	if db.closed.Load() {
		db.lateAccess.Add(1)
	}
}

func (db *shutdownDB) Get(key []byte) ([]byte, error) {
	db.touch()
	return db.KeyValueStore.Get(key)
}

func (db *shutdownDB) Has(key []byte) (bool, error) {
	db.touch()
	return db.KeyValueStore.Has(key)
}

func (db *shutdownDB) Put(key []byte, value []byte) error {
	db.touch()
	return db.KeyValueStore.Put(key, value)
}

func (db *shutdownDB) Delete(key []byte) error {
	db.touch()
	return db.KeyValueStore.Delete(key)
}

func (db *shutdownDB) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	db.once.Do(func() {
		close(db.entered)
		<-db.gate
	})
	db.touch()
	return db.KeyValueStore.NewIterator(prefix, start)
}

func (db *shutdownDB) NewBatch() ethdb.Batch {
	return &shutdownBatch{Batch: db.KeyValueStore.NewBatch(), db: db}
}

func (db *shutdownDB) NewBatchWithSize(size int) ethdb.Batch {
	return &shutdownBatch{Batch: db.KeyValueStore.NewBatchWithSize(size), db: db}
}

type shutdownBatch struct {
	ethdb.Batch
	db *shutdownDB
}

func (b *shutdownBatch) Write() error {
	b.db.touch()
	return b.Batch.Write()
}

// TestSnapshotShutdownRace checks that releasing a disk layer during shutdown
// stops a running snapshot generator and waits for it to exit, so it cannot
// touch the database after the node has closed it.
func TestSnapshotShutdownRace(t *testing.T) {
	for _, scheme := range []string{rawdb.HashScheme, rawdb.PathScheme} {
		t.Run(scheme, func(t *testing.T) {
			testSnapshotShutdownRace(t, scheme)
		})
	}
}

func testSnapshotShutdownRace(t *testing.T, scheme string) {
	helper := newHelper(scheme)
	for i := 0; i < 64; i++ {
		helper.addTrieAccount(fmt.Sprintf("acc-%d", i), &types.StateAccount{Balance: uint256.NewInt(uint64(i + 1)), Root: types.EmptyRootHash, CodeHash: types.EmptyCodeHash.Bytes()})
	}
	root := helper.Commit()

	db := &shutdownDB{
		KeyValueStore: helper.diskdb,
		gate:          make(chan struct{}),
		entered:       make(chan struct{}),
	}
	snap := generateSnapshot(db, helper.triedb, 16, root)

	select {
	case <-db.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("snapshot generator did not start")
	}
	// Shut down the way the node does: release the snapshot, then close the
	// database underneath it.
	released := make(chan struct{})
	go func() {
		snap.Release()
		db.closed.Store(true)
		close(released)
	}()
	select {
	case <-released:
	case <-time.After(100 * time.Millisecond):
	}
	close(db.gate)

	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("releasing the disk layer did not return")
	}
	// Give a generator that survived the release time to run to completion.
	select {
	case <-snap.genPending:
	case <-time.After(time.Second):
	}
	if n := db.lateAccess.Load(); n != 0 {
		t.Fatalf("snapshot generator accessed the database %d times after it was closed", n)
	}
	select {
	case <-snap.done:
	default:
		t.Fatal("snapshot generator goroutine still running after release")
	}
	// Stopping an already stopped generator again must not block.
	finished := make(chan struct{})
	go func() {
		snap.Release()
		snap.stopGeneration()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("stopping the generator twice blocked")
	}
}
