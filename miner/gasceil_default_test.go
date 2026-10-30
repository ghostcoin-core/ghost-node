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

package miner

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/naoina/toml"
)

// installerMinerConfig is the miner table the installers write into a
// node's config.toml: it names the Etherbase and nothing else.
const installerMinerConfig = `
[Eth.Miner]
Etherbase = "0x6bea739900000000000000000000000000000001"
`

// TestZeroGasCeilUsesDefault starts a worker from the miner settings of an
// installer's config.toml, whose gas ceiling decodes to 0, on a chain whose
// gas limit has fallen far below what a reveal transaction needs. Each block
// it builds must raise the limit toward the default ceiling, and a chain
// already at the maximum must stay there.
func TestZeroGasCeilUsesDefault(t *testing.T) {
	var file struct {
		Eth struct {
			Miner Config
		}
	}
	if err := toml.Unmarshal([]byte(installerMinerConfig), &file); err != nil {
		t.Fatal(err)
	}
	if file.Eth.Miner.GasCeil != 0 {
		t.Fatalf("installer miner table decodes to gas ceiling %d, want 0", file.Eth.Miner.GasCeil)
	}
	if file.Eth.Miner.Etherbase == (common.Address{}) {
		t.Fatal("installer miner table decodes without its Etherbase")
	}
	want := min(DefaultConfig.GasCeil, ghost.MaxBlockGasLimit)
	if want != 30_000_000 {
		t.Fatalf("default gas ceiling %d, want 30000000", want)
	}

	for _, start := range []uint64{966_010, ghost.MaxBlockGasLimit} {
		gspec := ghost.InternalNetGenesis()
		gspec.GasLimit = start
		engine := ethash.NewFaker()
		db := rawdb.NewMemoryDatabase()
		chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		backend := newTestWorkerBackend(t, ethashChainConfig, engine, rawdb.NewMemoryDatabase(), 0)
		backend.db, backend.chain, backend.genesis = db, chain, gspec

		config := *testConfig
		config.Etherbase = file.Eth.Miner.Etherbase
		config.GasCeil = file.Eth.Miner.GasCeil
		w := newWorker(&config, gspec.Config, engine, backend, new(event.TypeMux), nil, false)

		for i := 1; i <= 5; i++ {
			parent := chain.CurrentBlock()
			res := w.getSealingBlock(&generateParams{
				parentHash: parent.Hash(),
				timestamp:  parent.Time + 1,
				coinbase:   config.Etherbase,
				noUncle:    true,
				noTxs:      true,
			})
			if res.err != nil {
				t.Fatalf("start %d: building block %d: %v", start, i, res.err)
			}
			got := res.block.GasLimit()
			if expect := core.CalcGasLimit(parent.GasLimit, want); got != expect {
				t.Fatalf("start %d: block %d gas limit %d after parent %d, want %d", start, i, got, parent.GasLimit, expect)
			}
			if parent.GasLimit < want && got <= parent.GasLimit {
				t.Fatalf("start %d: block %d gas limit %d did not rise from parent %d", start, i, got, parent.GasLimit)
			}
			if parent.GasLimit == want && got != want {
				t.Fatalf("start %d: block %d gas limit %d left the maximum %d", start, i, got, want)
			}
			if _, err := chain.InsertChain(types.Blocks{res.block}); err != nil {
				t.Fatalf("start %d: block %d not imported: %v", start, i, err)
			}
		}
		w.close()
		chain.Stop()
	}
}
