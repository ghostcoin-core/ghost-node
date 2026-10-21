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

import "testing"

// TestSigVerifyWordGas checks that SIGVERIFY_WORD_GAS is set: a message word
// is never free, so a long message cannot be verified for the price of a
// short one.
func TestSigVerifyWordGas(t *testing.T) {
	if SigVerifyWordGas == 0 {
		t.Fatal("SigVerifyWordGas is zero; it must be at least 1")
	}
	// The per-word charge is far below the verification itself: one word of
	// a message costs less than the verification of its signature.
	if SigVerifyWordGas >= AccountTxVerifyGasMLDSA44 {
		t.Errorf("SigVerifyWordGas is %d, not below the verification gas %d", SigVerifyWordGas, AccountTxVerifyGasMLDSA44)
	}
}
