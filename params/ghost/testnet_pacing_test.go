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

package ghost_test

import (
	"math"
	"math/big"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// paceHashRate is the hash rate, in hashes a second, of the CPU miner the
// test network's difficulty is sized for: light-mode RandomX on 16 threads,
// measured at about 550 hashes a second.
const paceHashRate = 550.0

// paceBlock is one simulated block: its header time, its difficulty and the
// fake-clock time it was sealed at.
type paceBlock struct {
	time       uint64
	difficulty *big.Int
	sealed     float64
}

// simulatePace mines blocks on top of a genesis at genesisTime with ASERT
// and a miner of fixed hash rate, starting when the fake clock reads start.
// Each block takes the clock time, at least one second after its parent, and
// waits while it is more than the future drift ahead of the clock, as the
// node's miner and sealer do. Sealing takes an exponential time with mean
// difficulty / hashRate, the expected number of hashes over the rate.
func simulatePace(p ghostrules.Params, genesisTime uint64, start, hashRate float64, blocks int, seed uint64) []paceBlock {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	var (
		out    = make([]paceBlock, 0, blocks)
		now    = start
		parent = genesisTime
	)
	for n := 1; n <= blocks; n++ {
		ts := max(parent+1, uint64(now))
		if float64(ts) > now+float64(p.FutureDrift) {
			now = float64(ts - p.FutureDrift)
		}
		d := p.RequiredDifficulty(genesisTime, uint64(n), ts)
		diff, _ := new(big.Float).SetInt(d).Float64()
		now += rng.ExpFloat64() * diff / hashRate
		out = append(out, paceBlock{time: ts, difficulty: d, sealed: now})
		parent = ts
	}
	return out
}

// averageSpacing is the mean seconds between the header times of
// blocks[from-1] and blocks[len-1].
func averageSpacing(blocks []paceBlock, from int) float64 {
	first, last := blocks[from-1].time, blocks[len(blocks)-1].time
	return float64(last-first) / float64(len(blocks)-from)
}

// TestTestNetPacingParams checks that the public test network has its own
// 30-second constants, not the internal network's one-second ones at
// difficulty 1.
func TestTestNetPacingParams(t *testing.T) {
	p := ghost.TestNetParams()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if reflect.DeepEqual(p, ghost.InternalNetParams()) {
		t.Fatal("test network constants are the internal network's")
	}
	if p.BlockTime != 30 {
		t.Errorf("block time %d, want 30", p.BlockTime)
	}
	if p.FutureDrift != 30 {
		t.Errorf("future drift %d, want 30", p.FutureDrift)
	}
	if p.MinDifficulty.Cmp(big.NewInt(1)) <= 0 {
		t.Errorf("minimum difficulty %v, want above 1", p.MinDifficulty)
	}
	launch := ghostrules.Launch30s()
	if p.HalfLife != launch.HalfLife {
		t.Errorf("half-life %d, want the 30-second preset's %d", p.HalfLife, launch.HalfLife)
	}
	if !p.FirstReward.Eq(launch.FirstReward) || !p.TailReward.Eq(launch.TailReward) {
		t.Errorf("rewards %v/%v, want the 30-second preset's %v/%v", p.FirstReward, p.TailReward, launch.FirstReward, launch.TailReward)
	}
	if p.StartDifficulty.Cmp(big.NewInt(1<<14)) != 0 || p.MinDifficulty.Cmp(big.NewInt(1<<12)) != 0 {
		t.Errorf("start and minimum difficulty %v/%v, want 16384/4096", p.StartDifficulty, p.MinDifficulty)
	}
	// The start is about one block time of work for the reference miner,
	// and the minimum still needs real work.
	start, _ := new(big.Float).SetInt(p.StartDifficulty).Float64()
	if secs := start / paceHashRate; secs < 20 || secs > 40 {
		t.Errorf("start difficulty takes the reference miner %.1f s, want about 30", secs)
	}
	floor, _ := new(big.Float).SetInt(p.MinDifficulty).Float64()
	if secs := floor / paceHashRate; secs < 5 {
		t.Errorf("minimum difficulty takes the reference miner %.1f s, want at least 5", secs)
	}
	if g := ghost.TestNetGenesis(); g.Difficulty.Cmp(p.StartDifficulty) != 0 {
		t.Errorf("genesis difficulty %v, want the start difficulty %v", g.Difficulty, p.StartDifficulty)
	}

	// Each call returns its own values.
	p.StartDifficulty.SetInt64(5)
	p.MinDifficulty.SetInt64(5)
	if q := ghost.TestNetParams(); q.StartDifficulty.Int64() != 1<<14 || q.MinDifficulty.Int64() != 1<<12 {
		t.Error("TestNetParams shares its values between calls")
	}
}

// TestTestNetPacingSpacing mines several hundred blocks with ASERT on a fake
// clock and checks that they come about every 30 seconds: at the reference
// hash rate from the start, and at half and double that rate once ASERT has
// had a few half-lives to adjust.
func TestTestNetPacingSpacing(t *testing.T) {
	p := ghost.TestNetParams()
	genesis := uint64(ghost.TestNetTimestamp)
	// The network starts a few minutes after its genesis time.
	start := float64(genesis + 300)

	blocks := simulatePace(p, genesis, start, paceHashRate, 720, 1)
	if got := averageSpacing(blocks, 1); math.Abs(got-30) > 6 {
		t.Errorf("reference miner: average spacing %.1f s over %d blocks, want 30 s within 20%%", got, len(blocks))
	}
	for _, rate := range []float64{paceHashRate / 2, paceHashRate * 2} {
		blocks := simulatePace(p, genesis, start, rate, 960, 2)
		if got := averageSpacing(blocks, 480); math.Abs(got-30) > 6 {
			t.Errorf("miner at %.0f H/s: average spacing %.1f s over blocks 480 to %d, want 30 s within 20%%", rate, got, len(blocks))
		}
	}
}

// TestTestNetPacingFarPastGenesis starts the network long after its genesis
// time, the case that left the old network at difficulty 1 making blocks as
// fast as it could build them. The difficulty of block 1 bottoms out at the
// minimum, which still takes real work, so the chain cannot burst ahead, and
// ASERT climbs back to 30-second blocks as the chain works off the lag.
func TestTestNetPacingFarPastGenesis(t *testing.T) {
	p := ghost.TestNetParams()
	genesis := uint64(ghost.TestNetTimestamp)

	// A year late, block 1 sits at the minimum and not at 1.
	late := genesis + 365*24*3600
	d := p.RequiredDifficulty(genesis, 1, late)
	if d.Cmp(p.MinDifficulty) != 0 {
		t.Errorf("block 1 a year late has difficulty %v, want the minimum %v", d, p.MinDifficulty)
	}
	if d.Cmp(big.NewInt(1<<12)) < 0 {
		t.Errorf("block 1 a year late has difficulty %v: a CPU seals it with almost no work", d)
	}

	// Within an hour of the genesis time block 1 is above the minimum.
	if d := p.RequiredDifficulty(genesis, 1, genesis+3600); d.Cmp(p.MinDifficulty) <= 0 {
		t.Errorf("block 1 an hour after genesis has difficulty %v, want above the minimum %v", d, p.MinDifficulty)
	}

	// A day late: the first blocks take the minimum's work, not a few
	// milliseconds, and the spacing is back near 30 seconds once the lag is
	// worked off.
	blocks := simulatePace(p, genesis, float64(genesis+24*3600), paceHashRate, 6000, 3)
	floor, _ := new(big.Float).SetInt(p.MinDifficulty).Float64()
	floorSpacing := floor / paceHashRate
	if got := averageSpacing(blocks[:200], 1); got < 0.8*floorSpacing {
		t.Errorf("first 200 blocks a day late: average spacing %.2f s, want at least %.2f s", got, 0.8*floorSpacing)
	}
	if got := averageSpacing(blocks, len(blocks)-500); math.Abs(got-30) > 6 {
		t.Errorf("a day late: average spacing %.1f s over the last 500 of %d blocks, want 30 s within 20%%", got, len(blocks))
	}
	if last := blocks[len(blocks)-1].difficulty; last.Cmp(p.MinDifficulty) <= 0 {
		t.Errorf("a day late: difficulty still at the minimum %v after %d blocks", last, len(blocks))
	}
}
