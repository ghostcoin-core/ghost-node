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

//go:build !cgo

package randomx

// Without cgo the library cannot be built: New returns ErrCgoRequired and
// nothing below is ever reached.

type rxFlags uint32

const interpreterFlags rxFlags = 0

func available() error { return ErrCgoRequired }

func detectFlags() rxFlags { return interpreterFlags }

type rxCache struct{}

func newRxCache(rxFlags, []byte) (*rxCache, error) { return nil, ErrCgoRequired }

func (c *rxCache) free() {}

type rxVM struct{}

func newRxVM(rxFlags, *rxCache) (*rxVM, error) { return nil, ErrCgoRequired }

func (vm *rxVM) hash([]byte) (out [32]byte) { return out }

func (vm *rxVM) free() {}
