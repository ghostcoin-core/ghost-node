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

package ghost

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestTreeAccountAddressesAreDistinct checks that the four reserved accounts
// are distinct, non-zero and outside the precompile range 0x01 to 0xff.
func TestTreeAccountAddressesAreDistinct(t *testing.T) {
	accounts := map[string]common.Address{
		"coin tree":    CoinTreeAccount,
		"data tree":    DataTreeAccount,
		"coin markers": CoinMarkerAccount,
		"data markers": DataMarkerAccount,
	}
	seen := make(map[common.Address]string)
	for name, addr := range accounts {
		if other, ok := seen[addr]; ok {
			t.Errorf("%s and %s share the address %x", name, other, addr)
		}
		seen[addr] = name
		if addr == (common.Address{}) {
			t.Errorf("%s is the zero address", name)
		}
		if n := new(big.Int).SetBytes(addr[:]); n.Cmp(big.NewInt(0xff)) <= 0 {
			t.Errorf("%s is %x, in the precompile range", name, addr)
		}
	}
	if len(seen) != 4 {
		t.Errorf("%d distinct addresses, want 4", len(seen))
	}
}
