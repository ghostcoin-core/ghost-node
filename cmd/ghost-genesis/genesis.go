// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rlp"
)

// Derivation is the result of the rule: the selected Bitcoin block and the
// Ghost genesis derived from it.
type Derivation struct {
	BitcoinHash   [32]byte // the selected block's hash, in internal byte order
	BitcoinHeight int      // its Bitcoin height
	Confirmations int      // its depth on the heaviest branch, counting itself
	MedianTime    uint32   // its median time past

	Genesis *genesisT.Genesis
	Block   *types.Block
}

// Encoded returns the RLP encoding of the genesis block.
func (d *Derivation) Encoded() ([]byte, error) {
	return rlp.EncodeToBytes(d.Block)
}

// Derive applies the genesis Bitcoin-block rule to T_L and a file of raw
// Bitcoin mainnet headers starting at the mainnet checkpoint, and builds the
// Ghost genesis of the selected block. It reads nothing but its arguments.
func Derive(tl uint64, headers []byte) (*Derivation, error) {
	return deriveOn(mainnetChain(), tl, headers)
}

// deriveOn is Derive for headers of the chain c.
func deriveOn(c chain, tl uint64, headers []byte) (*Derivation, error) {
	tree, err := readHeaders(c, headers)
	if err != nil {
		return nil, err
	}
	sel, err := selectBlock(tree, tl)
	if err != nil {
		return nil, err
	}
	g, err := genesisOf(sel.block.hash, sel.block.mtp)
	if err != nil {
		return nil, err
	}
	block, err := genesisBlock(g)
	if err != nil {
		return nil, err
	}
	return &Derivation{
		BitcoinHash:   sel.block.hash,
		BitcoinHeight: sel.block.height,
		Confirmations: sel.confirmations,
		MedianTime:    sel.block.mtp,
		Genesis:       g,
		Block:         block,
	}, nil
}

// presetParams returns the chain preset of GenesisBlockTime.
func presetParams() (ghostrules.Params, error) {
	for _, p := range []ghostrules.Params{ghostrules.Launch30s(), ghostrules.Launch60s()} {
		if p.BlockTime == GenesisBlockTime {
			return p, nil
		}
	}
	return ghostrules.Params{}, fmt.Errorf("no chain preset has %d-second blocks", GenesisBlockTime)
}

// genesisOf is the genesis of a selected Bitcoin block: its time is the
// block's median time past, which is at or above T_L, plus GenesisOffset
// seconds, and its extra data is the block's hash as Bitcoin prints it, so
// anyone can check the anchor. The difficulty is the preset's starting
// difficulty, the base fee the initial one, and nothing is allocated: value
// enters only by block rewards and reveals.
//
// The chain configuration only shapes the header here (London from block 0,
// no withdrawals, blob or beacon root fields); the header does not carry the
// chain ID. The built-in chain configuration is not part of this rule.
func genesisOf(bitcoinHash [32]byte, medianTime uint32) (*genesisT.Genesis, error) {
	p, err := presetParams()
	if err != nil {
		return nil, err
	}
	anchor := Display(bitcoinHash)
	return &genesisT.Genesis{
		Config:     ghost.InternalNetGenesis().Config,
		Timestamp:  genesisTime(medianTime),
		ExtraData:  anchor[:],
		GasLimit:   GenesisGasLimit,
		Difficulty: new(big.Int).Set(p.StartDifficulty),
		BaseFee:    big.NewInt(vars.InitialBaseFee),
		Alloc:      genesisT.GenesisAlloc{},
	}, nil
}

// genesisTime is the genesis timestamp of a block with the given median time
// past: MTP(B) + GenesisOffset.
func genesisTime(medianTime uint32) uint64 {
	return uint64(medianTime) + GenesisOffset
}

// genesisBlock builds the block of a genesis, with the roots of the empty
// coin and data trees in its header.
func genesisBlock(g *genesisT.Genesis) (*types.Block, error) {
	if len(g.Alloc) != 0 {
		return nil, fmt.Errorf("genesis allocates to %d accounts, want none", len(g.Alloc))
	}
	header := core.GenesisToBlock(g, nil).Header()
	if header.Root != types.EmptyRootHash {
		return nil, fmt.Errorf("genesis state root %x, want the empty root", header.Root)
	}
	coin, data := ghosttree.EmptyRoot(ghosttree.Coin), ghosttree.EmptyRoot(ghosttree.Data)
	header.CoinTreeRoot, header.DataTreeRoot = &coin, &data
	return types.NewBlockWithHeader(header), nil
}
