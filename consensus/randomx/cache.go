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
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// cacheSet keeps at most limit RandomX caches resident. A cache is held by
// every verification or sealer using it and is never evicted while held;
// when all are held, a caller needing another key waits for a release. The
// least recently used free cache is evicted and freed through the library.
type cacheSet struct {
	limit int
	flags rxFlags

	mu      sync.Mutex
	cond    *sync.Cond
	entries map[common.Hash]*cacheEntry
	tick    uint64

	builds int // caches built, for tests
	frees  int // caches freed, for tests
}

// cacheEntry is one resident cache and the idle VMs bound to it.
type cacheEntry struct {
	key   common.Hash
	ready chan struct{} // closed once the cache is built or failed
	cache *rxCache
	err   error
	refs  int    // holders; guarded by the set's mu
	used  uint64 // last use tick; guarded by the set's mu
	idle  []*rxVM
}

func newCacheSet(limit int, flags rxFlags) *cacheSet {
	s := &cacheSet{limit: limit, flags: flags, entries: make(map[common.Hash]*cacheEntry)}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// acquire returns the cache for key, building it if needed, and holds it
// until release. Building happens outside the lock so other keys proceed.
func (s *cacheSet) acquire(key common.Hash) (*cacheEntry, error) {
	s.mu.Lock()
	var victim *cacheEntry
	for {
		if e, ok := s.entries[key]; ok {
			e.refs++
			s.tick++
			e.used = s.tick
			s.mu.Unlock()
			<-e.ready
			if e.err != nil {
				s.release(e)
				return nil, e.err
			}
			return e, nil
		}
		if len(s.entries) < s.limit {
			break
		}
		if victim = s.oldestFree(); victim != nil {
			delete(s.entries, victim.key)
			break
		}
		s.cond.Wait()
	}
	s.tick++
	e := &cacheEntry{key: key, ready: make(chan struct{}), refs: 1, used: s.tick}
	s.entries[key] = e
	s.mu.Unlock()

	if victim != nil {
		s.free(victim)
	}
	cache, err := newRxCache(s.flags, key[:])

	s.mu.Lock()
	e.cache, e.err = cache, err
	if err == nil {
		s.builds++
	} else {
		delete(s.entries, key)
	}
	close(e.ready)
	s.mu.Unlock()
	if err != nil {
		s.release(e)
		return nil, err
	}
	return e, nil
}

// oldestFree returns the least recently used built cache no one holds.
func (s *cacheSet) oldestFree() *cacheEntry {
	var oldest *cacheEntry
	for _, e := range s.entries {
		if e.refs > 0 {
			continue
		}
		if oldest == nil || e.used < oldest.used {
			oldest = e
		}
	}
	return oldest
}

// release ends one hold on the entry.
func (s *cacheSet) release(e *cacheEntry) {
	s.mu.Lock()
	e.refs--
	if e.refs == 0 {
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

// free destroys an evicted entry's VMs and then its cache.
func (s *cacheSet) free(e *cacheEntry) {
	for _, vm := range e.idle {
		vm.free()
	}
	e.idle = nil
	if e.cache != nil {
		e.cache.free()
		e.cache = nil
	}
	s.mu.Lock()
	s.frees++
	s.mu.Unlock()
}

// vm returns a VM bound to the entry's cache for one worker; the caller must
// hold the entry and hand the VM back with putVM.
func (s *cacheSet) vm(e *cacheEntry) (*rxVM, error) {
	s.mu.Lock()
	if n := len(e.idle); n > 0 {
		vm := e.idle[n-1]
		e.idle = e.idle[:n-1]
		s.mu.Unlock()
		return vm, nil
	}
	s.mu.Unlock()
	return newRxVM(s.flags, e.cache)
}

// putVM returns a worker's VM to the entry for reuse.
func (s *cacheSet) putVM(e *cacheEntry, vm *rxVM) {
	s.mu.Lock()
	e.idle = append(e.idle, vm)
	s.mu.Unlock()
}

// hash computes one RandomX hash with a VM from the held entry.
func (s *cacheSet) hash(e *cacheEntry, input []byte) ([32]byte, error) {
	vm, err := s.vm(e)
	if err != nil {
		return [32]byte{}, err
	}
	out := vm.hash(input)
	s.putVM(e, vm)
	return out, nil
}

// resident returns the keys of the caches currently in the set.
func (s *cacheSet) resident() map[common.Hash]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make(map[common.Hash]bool, len(s.entries))
	for k := range s.entries {
		keys[k] = true
	}
	return keys
}
