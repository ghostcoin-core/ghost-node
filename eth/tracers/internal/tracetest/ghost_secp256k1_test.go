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

package tracetest

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// skipSecp256k1Fixture skips a fixture whose transaction is of a type Ghost
// refuses (legacy, EIP-2930, EIP-1559, EIP-4844 or EIP-7702; spec 09, section
// 12, QS-1). The fixtures are Ethereum transactions signed with secp256k1, no
// signer recovers their sender, and their recorded traces depend on it, so they
// are skipped, not rewritten.
func skipSecp256k1Fixture(t testing.TB, tx *types.Transaction) {
	if err := types.CheckTxType(tx); errors.Is(err, types.ErrSecp256k1TxType) {
		t.Skipf("Ghost refuses this fixture's secp256k1 transaction type %#x", tx.Type())
	}
}
