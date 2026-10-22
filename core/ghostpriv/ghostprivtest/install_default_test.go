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

//go:build !ghosttreetest14

package ghostprivtest_test

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// Without the test-depth tag, importing the package installs nothing: the
// active verifier is not the stub and rejects the stub proof of a binding.
func TestReleaseBuildInstallsNoVerifier(t *testing.T) {
	v := ghostpriv.ActiveVerifier()
	if _, ok := v.(ghostprivtest.Verifier); ok {
		t.Fatal("the stub is the active verifier")
	}
	for _, in := range []*ghostpriv.VerifyInputs{
		{Kind: ghosttree.Coin, Purpose: ghostpriv.PurposeReveal, Binding: common.HexToHash("0x01")},
		{Kind: ghosttree.Data, Purpose: ghostpriv.PurposeReveal, Binding: common.HexToHash("0x02")},
	} {
		if err := v.VerifyReveal(in, ghostprivtest.Proof(in.Binding)); err == nil {
			t.Errorf("kind %v: stub proof accepted", in.Kind)
		}
	}
}
