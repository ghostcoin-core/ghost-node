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

package ethapi

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TestRPCMarshalHeaderLookupFields checks that both header marshalers carry
// the four lookup fields of a header that has them, under their names, and
// leave the keys out for one that has none.
func TestRPCMarshalHeaderLookupFields(t *testing.T) {
	t.Parallel()
	coin, data, marker := common.Hash{1}, common.Hash{2}, common.Hash{3}
	want := map[string]common.Hash{
		"coinLookupRoot": {4}, "dataLookupRoot": {5}, "coinMarkerRoot": {6}, "lookupDigest": {7},
	}
	coinLookup, dataLookup, coinMarker, digest := want["coinLookupRoot"], want["dataLookupRoot"], want["coinMarkerRoot"], want["lookupDigest"]
	ghostHeader := &types.Header{
		Number:         big.NewInt(1),
		Difficulty:     big.NewInt(1),
		BaseFee:        big.NewInt(1),
		CoinTreeRoot:   &coin,
		DataTreeRoot:   &data,
		DataMarkerRoot: &marker,
		CoinLookupRoot: &coinLookup,
		DataLookupRoot: &dataLookup,
		CoinMarkerRoot: &coinMarker,
		LookupDigest:   &digest,
	}
	baseHeader := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), BaseFee: big.NewInt(1)}

	fields := RPCMarshalHeader(ghostHeader)
	base := RPCMarshalHeader(baseHeader)
	for name, w := range want {
		if got, ok := fields[name]; !ok || *got.(*common.Hash) != w {
			t.Errorf("RPCMarshalHeader %s %v, want %x", name, got, w)
		}
		if _, ok := base[name]; ok {
			t.Errorf("RPCMarshalHeader sets %s for a header without it", name)
		}
	}

	for _, c := range []struct {
		name   string
		header *types.Header
		has    bool
	}{
		{"ghost header", ghostHeader, true},
		{"base header", baseHeader, false},
	} {
		enc, err := json.Marshal(NewRPCMarshalHeaderTFromHeader(c.header))
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(enc, &obj); err != nil {
			t.Fatal(err)
		}
		for name, w := range want {
			raw, ok := obj[name]
			if !c.has {
				if ok {
					t.Errorf("%s: %s %s, want no key", c.name, name, raw)
				}
				continue
			}
			var got common.Hash
			if !ok || json.Unmarshal(raw, &got) != nil || got != w {
				t.Errorf("%s: %s %s, want %x", c.name, name, raw, w)
			}
		}
	}
}
