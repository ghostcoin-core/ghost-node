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

package randomx

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestGasLimitAboveConsensusMaximumRejected checks that a header whose gas
// limit is above the consensus maximum is invalid, even where the step from
// its parent is one the gas limit rule allows, and that a header at the
// maximum is valid.
func TestGasLimitAboveConsensusMaximumRejected(t *testing.T) {
	if ghost.MaxBlockGasLimit != 30_000_000 {
		t.Fatalf("consensus maximum gas limit %d, want 30,000,000", ghost.MaxBlockGasLimit)
	}
	var (
		engine = newTestEngine(t, testParams())
		config = testConfig()
		coin   = common.Hash{11}
		data   = common.Hash{12}
		parent = &types.Header{
			Number:       new(big.Int),
			GasLimit:     ghost.MaxBlockGasLimit,
			Time:         testGenesisAt,
			Difficulty:   new(big.Int).Set(testDifficulty),
			BaseFee:      big.NewInt(vars.InitialBaseFee),
			UncleHash:    types.EmptyUncleHash,
			CoinTreeRoot: &coin,
			DataTreeRoot: &data,
		}
		reader = newTestReader(config, parent)
	)
	child := func(gasLimit uint64) *types.Header {
		h := &types.Header{
			ParentHash: parent.Hash(),
			Number:     big.NewInt(1),
			GasLimit:   gasLimit,
			Time:       parent.Time + testBlockTime,
			BaseFee:    eip1559.CalcBaseFee(config, parent),
		}
		if err := engine.Prepare(reader, h); err != nil {
			t.Fatal(err)
		}
		h.UncleHash = types.EmptyUncleHash
		h.CoinTreeRoot, h.DataTreeRoot = &coin, &data
		return h
	}
	// The largest step up the gas limit rule allows from the parent.
	step := parent.GasLimit/vars.GasLimitBoundDivisor - 1

	for _, c := range []struct {
		name     string
		gasLimit uint64
		want     error
	}{
		{"at the maximum", ghost.MaxBlockGasLimit, nil},
		{"one under the maximum", ghost.MaxBlockGasLimit - 1, nil},
		{"one above the maximum", ghost.MaxBlockGasLimit + 1, errGasLimitAboveMax},
		{"the largest step above the maximum", ghost.MaxBlockGasLimit + step, errGasLimitAboveMax},
	} {
		header := child(c.gasLimit)
		err := engine.VerifyHeader(reader, header, false)
		if c.want == nil && err != nil {
			t.Errorf("%s: header rejected: %v", c.name, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: error %v, want %v", c.name, err, c.want)
		}
		// The batch path gives the same result.
		_, results := engine.VerifyHeaders(reader, []*types.Header{header}, []bool{false})
		select {
		case batchErr := <-results:
			if !sameError(batchErr, err) {
				t.Errorf("%s: batch error %v, single %v", c.name, batchErr, err)
			}
		case <-time.After(time.Minute):
			t.Fatalf("%s: no batch result", c.name)
		}
	}
}
