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

//go:build cgo

package randomx

// The rx_*.c, rx_*.cpp and rx_*.S files beside this one each include one
// vendored source file, so cgo builds the library from source with the flags
// below, which follow the library's own CMake build. Linux and Windows link
// the C++ runtime statically; macOS uses its system libraries.

/*
#cgo CFLAGS: -std=gnu99
#cgo CXXFLAGS: -std=c++11
#cgo linux darwin CFLAGS: -DHAVE_POSIX_MEMALIGN
#cgo linux darwin CXXFLAGS: -DHAVE_POSIX_MEMALIGN
#cgo amd64 CFLAGS: -maes
#cgo amd64 CXXFLAGS: -maes
#cgo arm64 CFLAGS: -march=armv8-a+crypto
#cgo arm64 CXXFLAGS: -march=armv8-a+crypto
#cgo linux,arm64 CFLAGS: -DHAVE_HWCAP
#cgo linux,arm64 CXXFLAGS: -DHAVE_HWCAP
#cgo linux LDFLAGS: -static-libstdc++ -static-libgcc -lm
#cgo windows LDFLAGS: -static -ladvapi32

#include "librandomx/src/randomx.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// rxFlags are the library's randomx_flags.
type rxFlags = C.randomx_flags

// interpreterFlags select the portable interpreter and software AES.
const interpreterFlags rxFlags = C.RANDOMX_FLAG_DEFAULT

var (
	errAllocCache = errors.New("randomx: cannot allocate a cache")
	errCreateVM   = errors.New("randomx: cannot create a virtual machine")
)

func available() error { return nil }

// detectFlags returns the flags the engine uses on this machine: the JIT,
// hardware AES and W^X pages wherever the library reports them. Light mode,
// no large pages and RandomX v1 are fixed by leaving the other flags off.
func detectFlags() rxFlags {
	return C.randomx_get_flags() & (C.RANDOMX_FLAG_JIT | C.RANDOMX_FLAG_HARD_AES | C.RANDOMX_FLAG_SECURE)
}

// rxCache is a RandomX cache initialised with one key.
type rxCache struct {
	ptr *C.randomx_cache
}

// newRxCache allocates a cache and initialises it with key.
func newRxCache(flags rxFlags, key []byte) (*rxCache, error) {
	ptr := C.randomx_alloc_cache(flags)
	if ptr == nil {
		return nil, errAllocCache
	}
	C.randomx_init_cache(ptr, unsafe.Pointer(unsafe.SliceData(key)), C.size_t(len(key)))
	return &rxCache{ptr: ptr}, nil
}

// free releases the cache. No VM may use it afterwards.
func (c *rxCache) free() {
	C.randomx_release_cache(c.ptr)
	c.ptr = nil
}

// rxVM is a light-mode RandomX virtual machine bound to one cache. A VM is
// used by one goroutine at a time.
type rxVM struct {
	ptr *C.randomx_vm
}

// newRxVM creates a light-mode VM over the cache.
func newRxVM(flags rxFlags, c *rxCache) (*rxVM, error) {
	ptr := C.randomx_create_vm(flags, c.ptr, nil)
	if ptr == nil {
		return nil, errCreateVM
	}
	return &rxVM{ptr: ptr}, nil
}

// hash returns the RandomX hash of input.
func (vm *rxVM) hash(input []byte) (out [32]byte) {
	C.randomx_calculate_hash(vm.ptr, unsafe.Pointer(unsafe.SliceData(input)), C.size_t(len(input)), unsafe.Pointer(&out[0]))
	return out
}

// free destroys the VM.
func (vm *rxVM) free() {
	C.randomx_destroy_vm(vm.ptr)
	vm.ptr = nil
}
