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

import "github.com/ethereum/go-ethereum/common"

// EmptyMarkerSetRoot is the root of the empty data spent-marker set, spec 05
// vector marker-set-empty. Every Ghost header carries a data marker root at
// index 18 (spec 05, section 10).
var EmptyMarkerSetRoot = common.HexToHash("0ef484d17824d5fefb2533c70af81a3267af1169dd091395ad7607762aeee0a3")

// EmptyCoinMarkerSetRoot is the root of the empty coin spent-marker set,
// decision 0004 vector coin-marker-set-empty, the coinMarkerRoot of every
// Ghost genesis.
var EmptyCoinMarkerSetRoot = common.HexToHash("84e7c602ab3870f46bf300eff5581ae88029f7c58afb3758a652e0129e9e85cc")

// DataMarkerRoot returns the root of the data spent-marker set of a state
// (spec 05, section 6): the stored root node of the data marker-set tree
// (markerset.go), one slot read, or EmptyMarkerSetRoot while no data marker
// is spent.
func DataMarkerRoot(st StateDB) (common.Hash, error) {
	if err := Release.Check(); err != nil {
		return common.Hash{}, err
	}
	return newMarkerSet(st).root(), nil
}

// CoinMarkerRoot returns the root of the coin spent-marker set of a state
// (decision 0004): the stored root node of the coin marker-set tree, or
// EmptyCoinMarkerSetRoot while no coin marker is spent.
func CoinMarkerRoot(st StateDB) (common.Hash, error) {
	if err := Release.Check(); err != nil {
		return common.Hash{}, err
	}
	return newISet(coinMarkerSpec, st).root(), nil
}
