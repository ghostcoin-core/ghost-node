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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// HeaderFields are the seven Ghost fields of a header, items 16 to 22: the
// coin and data tree roots and the data marker root of spec 05, and the
// coin and data lookup roots, the coin marker root and the block lookup
// digest of decision 0004.
type HeaderFields struct {
	CoinTreeRoot   common.Hash
	DataTreeRoot   common.Hash
	DataMarkerRoot common.Hash
	CoinLookupRoot common.Hash
	DataLookupRoot common.Hash
	CoinMarkerRoot common.Hash
	LookupDigest   common.Hash
}

// ReadHeaderFields returns the Ghost fields of the block at height from the
// state after it. The engine sets them on the header it assembles, and block
// validation compares them with the header it imports.
func ReadHeaderFields(st StateDB, height uint64) (*HeaderFields, error) {
	var (
		f   HeaderFields
		err error
	)
	if f.CoinTreeRoot, err = Root(st, Coin); err != nil {
		return nil, err
	}
	if f.DataTreeRoot, err = Root(st, Data); err != nil {
		return nil, err
	}
	if f.DataMarkerRoot, err = DataMarkerRoot(st); err != nil {
		return nil, err
	}
	if f.CoinLookupRoot, err = LookupRoot(st, Coin); err != nil {
		return nil, err
	}
	if f.DataLookupRoot, err = LookupRoot(st, Data); err != nil {
		return nil, err
	}
	if f.CoinMarkerRoot, err = CoinMarkerRoot(st); err != nil {
		return nil, err
	}
	if f.LookupDigest, err = LookupDigest(st, height); err != nil {
		return nil, err
	}
	return &f, nil
}

// GenesisHeaderFields returns the Ghost fields of every Ghost genesis: the
// empty trees and sets, and the digest of empty lists starting at 0.
func GenesisHeaderFields() *HeaderFields {
	return &HeaderFields{
		CoinTreeRoot:   EmptyRoot(Coin),
		DataTreeRoot:   EmptyRoot(Data),
		DataMarkerRoot: EmptyMarkerSetRoot,
		CoinLookupRoot: EmptyLookupRoot(Coin),
		DataLookupRoot: EmptyLookupRoot(Data),
		CoinMarkerRoot: EmptyCoinMarkerSetRoot,
		LookupDigest:   EmptyLookupDigest,
	}
}

// SetOn sets the seven fields on a header, each its own copy.
func (f *HeaderFields) SetOn(h *types.Header) {
	c := *f
	h.CoinTreeRoot, h.DataTreeRoot, h.DataMarkerRoot = &c.CoinTreeRoot, &c.DataTreeRoot, &c.DataMarkerRoot
	h.CoinLookupRoot, h.DataLookupRoot, h.CoinMarkerRoot, h.LookupDigest = &c.CoinLookupRoot, &c.DataLookupRoot, &c.CoinMarkerRoot, &c.LookupDigest
}
