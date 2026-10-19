// Copyright 2017 The go-ethereum Authors
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

package math

import (
	"testing"
)

type operation byte

const (
	sub operation = iota
	add
	mul
)

func TestOverflow(t *testing.T) {
	for i, test := range []struct {
		x        uint64
		y        uint64
		overflow bool
		op       operation
	}{
		// add operations
		{MaxUint64, 1, true, add},
		{MaxUint64 - 1, 1, false, add},

		// sub operations
		{0, 1, true, sub},
		{0, 0, false, sub},

		// mul operations
		{0, 0, false, mul},
		{10, 10, false, mul},
		{MaxUint64, 2, true, mul},
		{MaxUint64, 1, false, mul},
	} {
		var overflows bool
		switch test.op {
		case sub:
			_, overflows = SafeSub(test.x, test.y)
		case add:
			_, overflows = SafeAdd(test.x, test.y)
		case mul:
			_, overflows = SafeMul(test.x, test.y)
		}

		if test.overflow != overflows {
			t.Errorf("%d failed. Expected test to be %v, got %v", i, test.overflow, overflows)
		}
	}
}

func TestHexOrDecimal64(t *testing.T) {
	tests := []struct {
		input string
		num   uint64
		ok    bool
	}{
		{"", 0, true},
		{"0", 0, true},
		{"0x0", 0, true},
		{"12345678", 12345678, true},
		{"0x12345678", 0x12345678, true},
		{"0X12345678", 0x12345678, true},
		// Tests for leading zero behaviour:
		{"0123456789", 123456789, true}, // note: not octal
		{"0x00", 0, true},
		{"0x012345678abc", 0x12345678abc, true},
		// Invalid syntax:
		{"abcdef", 0, false},
		{"0xgg", 0, false},
		// Doesn't fit into 64 bits:
		{"18446744073709551617", 0, false},
	}
	for _, test := range tests {
		var num HexOrDecimal64
		err := num.UnmarshalText([]byte(test.input))
		if (err == nil) != test.ok {
			t.Errorf("ParseUint64(%q) -> (err == nil) = %t, want %t", test.input, err == nil, test.ok)
			continue
		}
		if err == nil && uint64(num) != test.num {
			t.Errorf("ParseUint64(%q) -> %d, want %d", test.input, num, test.num)
		}
	}
}

func TestMustParseUint64(t *testing.T) {
	if v := MustParseUint64("12345"); v != 12345 {
		t.Errorf(`MustParseUint64("12345") = %d, want 12345`, v)
	}
}

func TestMustParseUint64Panic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("MustParseBig should've panicked")
		}
	}()
	MustParseUint64("ggg")
}

// TestHexOrDecimalLoneQuote checks that a JSON value made of a single quote
// character is rejected instead of slicing out of bounds.
func TestHexOrDecimalLoneQuote(t *testing.T) {
	input := []byte(`"`)
	if err := new(HexOrDecimal64).UnmarshalJSON(input); err == nil {
		t.Error("HexOrDecimal64: expected error for lone quote")
	}
	if err := new(HexOrDecimal256).UnmarshalJSON(input); err == nil {
		t.Error("HexOrDecimal256: expected error for lone quote")
	}
	if err := new(HexOrDecimalUint256).UnmarshalJSON(input); err == nil {
		t.Error("HexOrDecimalUint256: expected error for lone quote")
	}

	// Quoted values must still decode.
	var i64 HexOrDecimal64
	if err := i64.UnmarshalJSON([]byte(`"0x10"`)); err != nil || i64 != 16 {
		t.Errorf("HexOrDecimal64: got %d, %v; want 16", i64, err)
	}
	var i256 HexOrDecimal256
	if err := i256.UnmarshalJSON([]byte(`"0x10"`)); err != nil || i256.ToInt().Uint64() != 16 {
		t.Errorf("HexOrDecimal256: got %v, %v; want 16", i256.ToInt(), err)
	}
	var u256 HexOrDecimalUint256
	if err := u256.UnmarshalJSON([]byte(`"0x10"`)); err != nil || u256.ToInt().Uint64() != 16 {
		t.Errorf("HexOrDecimalUint256: got %v, %v; want 16", u256.ToInt(), err)
	}
}
