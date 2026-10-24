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
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// The Bitcoin mainnet checkpoint a header file must start at, and the
// mainnet difficulty rules every later header must follow. A header file
// that does not start at the checkpoint, or whose bits are not the ones the
// network requires, is not Bitcoin's chain, whatever its proof of work.
const (
	// The checkpoint is mainnet block 971712, the first block of a
	// difficulty period, so its time starts the period of the next retarget.
	// The hash is in the order Bitcoin prints it.
	mainnetCheckpointHash   = "00000000000000000000c185f0906690a08d62d6fe842682a888d5560217e467"
	mainnetCheckpointHeight = 971712
	mainnetCheckpointBits   = 0x17020093

	// RetargetInterval is the number of blocks of a difficulty period: a
	// block whose height is a multiple of it takes new bits.
	RetargetInterval = 2016

	// TargetTimespan is the time in seconds a difficulty period should take,
	// two weeks.
	TargetTimespan = 14 * 24 * 60 * 60
)

var (
	// ErrCheckpoint is returned for a header file whose first header is not
	// the checkpoint.
	ErrCheckpoint = errors.New("first header is not the Bitcoin checkpoint")

	// ErrDifficulty is returned for a header whose bits are not the ones the
	// network's difficulty rules require of it.
	ErrDifficulty = errors.New("header bits do not follow the network's difficulty rules")
)

// chain is the Bitcoin network a header file must belong to: the checkpoint
// its first header must be and the network's proof-of-work limit, the
// easiest target a header may carry.
type chain struct {
	checkpointHash   [32]byte // internal byte order
	checkpointHeight int
	checkpointBits   uint32
	powLimit         *big.Int
}

// mainnetChain is Bitcoin mainnet, the only network the command reads.
func mainnetChain() chain {
	display, err := hex.DecodeString(mainnetCheckpointHash)
	if err != nil || len(display) != 32 {
		panic("bad mainnet checkpoint hash")
	}
	var hash [32]byte
	copy(hash[:], display)
	// Mainnet's proof-of-work limit is 2^224 - 1, compact 0x1d00ffff.
	limit := new(big.Int).Lsh(big.NewInt(1), 224)
	return chain{
		checkpointHash:   Display(hash),
		checkpointHeight: mainnetCheckpointHeight,
		checkpointBits:   mainnetCheckpointBits,
		powLimit:         limit.Sub(limit, big.NewInt(1)),
	}
}

// checkCheckpoint checks that a header file's first header is the
// checkpoint.
func (c chain) checkCheckpoint(n *headerNode) error {
	if n.hash != c.checkpointHash || n.header.Bits != c.checkpointBits {
		return fmt.Errorf("%w: block %x, want %x", ErrCheckpoint, Display(n.hash), Display(c.checkpointHash))
	}
	return nil
}

// requiredBits is the bits the network requires of the child of parent.
// Within a difficulty period they are the parent's. At a retarget they
// follow from the time the period took, from its first block to the parent;
// there is no minimum-difficulty rule.
func (c chain) requiredBits(parent *headerNode) (uint32, error) {
	height := parent.height + 1
	if height%RetargetInterval != 0 {
		return parent.header.Bits, nil
	}
	first := parent
	for first.height > height-RetargetInterval {
		if first.parent == nil {
			return 0, fmt.Errorf("%w: the period before height %d starts before the checkpoint", ErrDifficulty, height)
		}
		first = first.parent
	}
	return nextBits(c.powLimit, parent.header.Bits, first.header.Time, parent.header.Time)
}

// nextBits is the retarget of Bitcoin Core: the target of lastBits scaled
// by the time the period took, from firstTime to lastTime, over
// TargetTimespan, with that time held within a factor of four of
// TargetTimespan, capped at the proof-of-work limit and encoded as compact
// bits.
func nextBits(powLimit *big.Int, lastBits, firstTime, lastTime uint32) (uint32, error) {
	timespan := int64(lastTime) - int64(firstTime)
	timespan = max(timespan, TargetTimespan/4)
	timespan = min(timespan, TargetTimespan*4)
	target, err := compactTarget(lastBits)
	if err != nil {
		return 0, err
	}
	target.Mul(target, big.NewInt(timespan))
	target.Div(target, big.NewInt(TargetTimespan))
	if target.Cmp(powLimit) > 0 {
		target.Set(powLimit)
	}
	return compactBits(target), nil
}
