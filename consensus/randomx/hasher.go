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

// Hasher computes Ghost's RandomX hash under one key with its own cache and
// VM, outside any engine: what a remote miner computes for a work package.
// A Hasher is used by one goroutine at a time.
type Hasher struct {
	cache *rxCache
	vm    *rxVM
}

// NewHasher builds a light-mode cache for key and a VM over it.
func NewHasher(key []byte) (*Hasher, error) {
	if err := available(); err != nil {
		return nil, err
	}
	flags := detectFlags()
	cache, err := newRxCache(flags, key)
	if err != nil {
		return nil, err
	}
	vm, err := newRxVM(flags, cache)
	if err != nil {
		cache.free()
		return nil, err
	}
	return &Hasher{cache: cache, vm: vm}, nil
}

// Hash returns the RandomX hash of input.
func (h *Hasher) Hash(input []byte) [32]byte {
	return h.vm.hash(input)
}

// Close frees the VM and the cache.
func (h *Hasher) Close() {
	h.vm.free()
	h.cache.free()
}
