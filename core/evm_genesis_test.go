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

package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// TestEVMBlockContextGenesis checks that the block context carries the
// genesis hash of a chain that gives its genesis block, and the zero hash,
// without a panic, for no chain and for a nil chain pointer, as the chain
// makers pass.
func TestEVMBlockContextGenesis(t *testing.T) {
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), GasLimit: 1_000_000}
	author := common.Address{0x01}

	if ctx := NewEVMBlockContext(header, nil, &author); ctx.Genesis != (common.Hash{}) {
		t.Fatalf("no chain: genesis %x, want zero", ctx.Genesis)
	}
	var none *BlockChain
	if ctx := NewEVMBlockContext(header, none, &author); ctx.Genesis != (common.Hash{}) {
		t.Fatalf("nil chain pointer: genesis %x, want zero", ctx.Genesis)
	}

	gspec := &genesisT.Genesis{Config: params.TestChainConfig}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	want := chain.Genesis().Hash()
	if ctx := NewEVMBlockContext(header, chain, &author); ctx.Genesis != want || want == (common.Hash{}) {
		t.Fatalf("chain: genesis %x, want %x", ctx.Genesis, want)
	}
}
