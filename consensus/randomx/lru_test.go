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

package randomx

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// TestCacheLimit uses four distinct keys in the process-wide cache set: the
// two keys of the shared test chain and two new ones. At most three caches
// stay resident, a cache in use is never evicted (a caller needing a fourth
// waits instead), and the evicted cache is freed. It runs last in the
// package so the other tests find their caches resident.
func TestCacheLimit(t *testing.T) {
	f := sealedChain(t)
	set := sharedCaches()
	if set.limit != 3 {
		t.Fatalf("cache limit %d, want 3", set.limit)
	}
	keys := []common.Hash{f.key(1), f.key(testChainLength), {0x01}, {0x02}}
	input := []byte("cache limit test input")

	checkResident := func(step string, want ...common.Hash) {
		t.Helper()
		resident := set.resident()
		if len(resident) > 3 {
			t.Fatalf("%s: %d caches resident", step, len(resident))
		}
		for _, k := range want {
			if !resident[k] {
				t.Errorf("%s: cache %x is not resident", step, k[:4])
			}
		}
	}
	acquire := func(key common.Hash) *cacheEntry {
		t.Helper()
		e, err := set.acquire(key)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}

	// Hold the first key throughout, as a long verification would.
	held := acquire(keys[0])
	heldHash, err := set.hash(held, input)
	if err != nil {
		t.Fatal(err)
	}
	second := acquire(keys[1])
	third := acquire(keys[2])
	checkResident("three keys", keys[0], keys[1], keys[2])

	set.mu.Lock()
	frees := set.frees
	set.mu.Unlock()

	// All three caches are in use: the fourth key waits.
	got := make(chan *cacheEntry)
	go func() {
		e, err := set.acquire(keys[3])
		if err != nil {
			t.Error(err)
		}
		got <- e
	}()
	select {
	case <-got:
		t.Fatal("a fourth cache was built while three were in use")
	case <-time.After(300 * time.Millisecond):
	}
	checkResident("fourth key waiting", keys[0], keys[1], keys[2])

	// Releasing the second key lets the fourth evict it, the least
	// recently used free cache, and nothing else.
	set.release(second)
	var fourth *cacheEntry
	select {
	case fourth = <-got:
	case <-time.After(time.Minute):
		t.Fatal("the fourth key never got a cache")
	}
	checkResident("after eviction", keys[0], keys[2], keys[3])
	if set.resident()[keys[1]] {
		t.Error("the released cache was not the one evicted")
	}
	set.mu.Lock()
	if set.frees != frees+1 {
		t.Errorf("%d caches freed, want 1", set.frees-frees)
	}
	set.mu.Unlock()
	if second.cache != nil || second.idle != nil {
		t.Error("the evicted cache and its VMs were not freed")
	}

	// The cache held throughout still hashes as before.
	if again, err := set.hash(held, input); err != nil || again != heldHash {
		t.Errorf("held cache changed: %x then %x (%v)", heldHash, again, err)
	}
	if other, err := set.hash(fourth, input); err != nil || other == heldHash {
		t.Errorf("the new key hashes like the old one: %x (%v)", other, err)
	}
	set.release(fourth)
	set.release(third)
	set.release(held)
	checkResident("released", keys[0], keys[2], keys[3])
}
