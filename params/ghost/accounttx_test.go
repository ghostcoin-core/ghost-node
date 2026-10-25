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

// TestMLRescueSunsetHeight checks ML_RESCUE_HEIGHT: none at genesis, so no
// block is past it; once set to H, scheme 0x0003 ends at H and not before;
// and restore puts back the height it replaced.
func TestMLRescueSunsetHeight(t *testing.T) {
	if h, ok := MLRescueHeight(); ok {
		t.Fatalf("ML_RESCUE_HEIGHT is %d by default, want none", h)
	}
	for _, n := range []uint64{0, 1, 1_000_000, ^uint64(0)} {
		if MLRescueSunset(n) {
			t.Errorf("block %d is past the sunset with no height set", n)
		}
	}
	const height = 100
	h := uint64(height)
	restore := SetMLRescueHeight(&h)
	h = 7 // the setter keeps its own copy
	if got, ok := MLRescueHeight(); !ok || got != height {
		t.Fatalf("ML_RESCUE_HEIGHT %d %v, want %d", got, ok, height)
	}
	for n, want := range map[uint64]bool{0: false, height - 1: false, height: true, height + 1: true, ^uint64(0): true} {
		if got := MLRescueSunset(n); got != want {
			t.Errorf("block %d: sunset %v, want %v", n, got, want)
		}
	}
	// A nested change and its restore.
	zero := uint64(0)
	restoreZero := SetMLRescueHeight(&zero)
	if !MLRescueSunset(0) {
		t.Error("block 0 is not past a sunset at height 0")
	}
	restoreZero()
	if got, ok := MLRescueHeight(); !ok || got != height {
		t.Fatalf("after the nested restore: %d %v, want %d", got, ok, height)
	}
	// nil clears the height.
	restoreNil := SetMLRescueHeight(nil)
	if _, ok := MLRescueHeight(); ok || MLRescueSunset(height) {
		t.Error("nil does not clear ML_RESCUE_HEIGHT")
	}
	restoreNil()
	restore()
	if h, ok := MLRescueHeight(); ok {
		t.Fatalf("after restore ML_RESCUE_HEIGHT is %d, want none", h)
	}
	if MLRescueSunset(height) {
		t.Error("after restore block H is past the sunset")
	}
}

// TestAccountTxVerifyGasRescueReuse checks that the rescue schemes take the
// verification gas of the algorithm they verify with: 0x0003 that of
// ML-DSA-44, 0x0004 that of SLH-DSA-SHAKE-128s; the IDs after them have none.
func TestAccountTxVerifyGasRescueReuse(t *testing.T) {
	for scheme, want := range map[uint16]uint64{
		0x0001: AccountTxVerifyGasMLDSA44,
		0x0002: AccountTxVerifyGasSLHDSA,
		0x0003: AccountTxVerifyGasMLDSA44,
		0x0004: AccountTxVerifyGasSLHDSA,
		0x0000: 0,
		0x0005: 0,
		0xffff: 0,
	} {
		if got := AccountTxVerifyGas(scheme); got != want {
			t.Errorf("scheme %#04x: VERIFY_GAS %d, want %d", scheme, got, want)
		}
	}
	if AccountTxVerifyGasMLDSA44 == AccountTxVerifyGasSLHDSA {
		t.Fatal("the two verification gases are equal; the reuse rules cannot be told apart")
	}
}
