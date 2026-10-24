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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/rlp"
)

// output is the parsed output of a derive run.
type output map[string]string

// deriveCmd runs the command on a header file and returns its parsed output.
func deriveCmd(t *testing.T, tl uint64, path string) (output, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run([]string{"derive", "-tl", strconv.FormatUint(tl, 10), "-headers", path}, &stdout, &stderr)
	if err != nil {
		if stdout.Len() != 0 {
			t.Fatalf("a refused derivation printed %q", stdout.String())
		}
		return nil, err
	}
	out := make(output)
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("output line %q", line)
		}
		out[key] = value
	}
	return out, nil
}

// requireGenesis checks a derivation's output against the selected block the
// generator mined and against the golden genesis of the fixture, and returns
// the golden genesis block.
func requireGenesis(t *testing.T, name string, out output, want fixtureHeader, height int) *types.Block {
	t.Helper()
	display := Display(want.hash)
	if got := out["bitcoin-block"]; got != hex.EncodeToString(display[:]) {
		t.Errorf("selected Bitcoin block %s, want %x", got, display)
	}
	if got := out["bitcoin-height"]; got != strconv.Itoa(height) {
		t.Errorf("selected height %s, want %d", got, height)
	}
	if got := out["confirmations"]; got != strconv.Itoa(Confirmations) {
		t.Errorf("confirmations %s, want %d", got, Confirmations)
	}
	if got := out["median-time-past"]; got != strconv.Itoa(fixtureTL) {
		t.Errorf("median time past %s, want T_L %d", got, fixtureTL)
	}
	requirePinned(t, name+".genesis.hex", out["genesis-block"]+"\n")

	golden, err := os.ReadFile(filepath.Join("testdata", name+".genesis.hex"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := hex.DecodeString(strings.TrimSpace(string(golden)))
	if err != nil {
		t.Fatal(err)
	}
	block := new(types.Block)
	if err := rlp.DecodeBytes(enc, block); err != nil {
		t.Fatalf("golden genesis of %s: %v", name, err)
	}
	if got := out["genesis-hash"]; got != hex.EncodeToString(block.Hash().Bytes()) {
		t.Errorf("genesis hash %s, the golden block's is %x", got, block.Hash())
	}
	// The fields of the rule, read back from the golden block.
	h := block.Header()
	start := ghostrules.Launch30s().StartDifficulty
	switch {
	case h.Number.Sign() != 0 || h.ParentHash != (common.Hash{}):
		t.Errorf("genesis number %v, parent %x", h.Number, h.ParentHash)
	case !bytes.Equal(h.Extra, display[:]):
		t.Errorf("genesis extra data %x, want the Bitcoin block %x", h.Extra, display)
	case h.Time != fixtureTL+6000:
		t.Errorf("genesis time %d, want the median time past %d plus 6000", h.Time, fixtureTL)
	case h.Difficulty.Cmp(start) != 0:
		t.Errorf("genesis difficulty %v, want the preset's starting difficulty %v", h.Difficulty, start)
	case h.GasLimit != GenesisGasLimit:
		t.Errorf("genesis gas limit %d, want %d", h.GasLimit, GenesisGasLimit)
	case h.Root != types.EmptyRootHash:
		t.Errorf("genesis state root %x, want the empty root", h.Root)
	case h.CoinTreeRoot == nil || h.DataTreeRoot == nil:
		t.Errorf("genesis without the coin and data tree roots")
	case len(block.Transactions()) != 0 || len(block.Uncles()) != 0:
		t.Errorf("genesis with a body")
	}
	return block
}

func TestDeriveGenesisNormal(t *testing.T) {
	path, _ := loadFixture(t, "normal")
	out, err := deriveCmd(t, fixtureTL, path)
	if err != nil {
		t.Fatal(err)
	}
	main := fixtures(t)["normal"].headers
	requireGenesis(t, "normal", out, main[20], 20)

	// One second later, block 20's median time past is below T_L, and block
	// 21 would be the selected block, with one confirmation too few.
	if _, err := deriveCmd(t, fixtureTL+1, path); !errors.Is(err, ErrTooFewConfirmations) {
		t.Errorf("T_L one second later: error %v, want %v", err, ErrTooFewConfirmations)
	}
	// An earlier T_L selects an earlier block and another genesis.
	earlier, err := deriveCmd(t, uint64(mainTime(13)), path)
	if err != nil {
		t.Fatal(err)
	}
	display := Display(main[18].hash)
	if earlier["bitcoin-block"] != hex.EncodeToString(display[:]) || earlier["genesis-hash"] == out["genesis-hash"] {
		t.Errorf("an earlier T_L selected %s with genesis %s", earlier["bitcoin-block"], earlier["genesis-hash"])
	}
}

func TestDeriveGenesisTooFewConfirmations(t *testing.T) {
	path, _ := loadFixture(t, "too_few_confirmations")
	_, err := deriveCmd(t, fixtureTL, path)
	if !errors.Is(err, ErrTooFewConfirmations) {
		t.Fatalf("error %v, want %v", err, ErrTooFewConfirmations)
	}
	display := Display(fixtures(t)["normal"].headers[20].hash)
	requirePinned(t, "too_few_confirmations.refused.txt", err.Error()+"\n")
	if want := fmt.Sprintf("block %x has 5, want %d", display, Confirmations); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name %q", err, want)
	}
}

func TestDeriveGenesisReorg(t *testing.T) {
	path, raw := loadFixture(t, "reorg")
	f := fixtures(t)
	main := f["normal"].headers
	reorg := f["reorg"].headers[fixtureMainLen:]

	// The main branch alone, the first headers of the file, selects its
	// block 20 with exactly the confirmations.
	mainOnly, err := Derive(fixtureTL, raw[:fixtureMainLen*BitcoinHeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if mainOnly.BitcoinHash != main[20].hash {
		t.Fatalf("the main branch alone selected %x, want its block 20", Display(mainOnly.BitcoinHash))
	}

	// The whole file holds a heavier branch, which leaves the main branch
	// after block 10 and reaches T_L later: it selects that branch's block 25.
	out, err := deriveCmd(t, fixtureTL, path)
	if err != nil {
		t.Fatal(err)
	}
	selected := reorg[25-fixtureForkAt-1]
	block := requireGenesis(t, "reorg", out, selected, 25)
	if block.Hash() == mainOnly.Block.Hash() {
		t.Fatal("the heavier branch did not change the genesis")
	}

	// Cut back to the main branch's work, the branches tie and disagree: the
	// main branch selects its block 20, the other its block 25 with one
	// confirmation. The headers do not settle the choice.
	tied := raw[:(fixtureMainLen+25-fixtureForkAt)*BitcoinHeaderSize]
	if _, err := Derive(fixtureTL, tied); !errors.Is(err, ErrTiedBranches) {
		t.Errorf("tied branches: error %v, want %v", err, ErrTiedBranches)
	}
	// With one more block the other branch is heavier but its block 25 is
	// two confirmations deep: refused, not the main branch's choice.
	short := raw[:(fixtureMainLen+26-fixtureForkAt)*BitcoinHeaderSize]
	if _, err := Derive(fixtureTL, short); !errors.Is(err, ErrTooFewConfirmations) {
		t.Errorf("heavier branch, two confirmations: error %v, want %v", err, ErrTooFewConfirmations)
	}
}

// TestGenesisTimestampOffset checks that the genesis timestamp is the
// selected block's median time past plus the 6000 seconds of the spec, for
// every fixture and for a T_L that selects an earlier block.
func TestGenesisTimestampOffset(t *testing.T) {
	if GenesisOffset != 6000 {
		t.Fatalf("GenesisOffset %d, the spec gives 6000", GenesisOffset)
	}
	for _, c := range []struct {
		name string
		tl   uint64
	}{
		{"normal", fixtureTL},
		{"reorg", fixtureTL},
		{"normal", uint64(mainTime(13))},
	} {
		_, raw := loadFixture(t, c.name)
		d, err := Derive(c.tl, raw)
		if err != nil {
			t.Fatalf("%s at T_L %d: %v", c.name, c.tl, err)
		}
		want := uint64(d.MedianTime) + 6000
		if d.Genesis.Timestamp != want {
			t.Errorf("%s at T_L %d: genesis timestamp %d, want MTP %d + 6000", c.name, c.tl, d.Genesis.Timestamp, d.MedianTime)
		}
		if got := d.Block.Time(); got != want {
			t.Errorf("%s at T_L %d: genesis header time %d, want MTP %d + 6000", c.name, c.tl, got, d.MedianTime)
		}
		if d.Block.Time() == uint64(d.MedianTime) {
			t.Errorf("%s at T_L %d: genesis header time is the bare median time past", c.name, c.tl)
		}
	}
}

func TestDerivedGenesisEmptyAlloc(t *testing.T) {
	for _, name := range []string{"normal", "reorg"} {
		t.Run(name, func(t *testing.T) {
			_, raw := loadFixture(t, name)
			d, err := Derive(fixtureTL, raw)
			if err != nil {
				t.Fatal(err)
			}
			if d.Genesis.Alloc == nil || len(d.Genesis.Alloc) != 0 {
				t.Fatalf("genesis allocation %v, want an empty one", d.Genesis.Alloc)
			}
			if d.Block.Root() != types.EmptyRootHash {
				t.Fatalf("genesis state root %x, want the empty root", d.Block.Root())
			}
			// The state of the genesis holds no account at all.
			st, err := state.New(d.Block.Root(), state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
			if err != nil {
				t.Fatal(err)
			}
			if accounts := st.RawDump(nil).Accounts; len(accounts) != 0 {
				t.Fatalf("genesis state holds %d accounts", len(accounts))
			}
		})
	}

	// The genesis builder refuses an allocation rather than minting one.
	g, err := genesisOf(fixtureAnchorParent(), fixtureTL)
	if err != nil {
		t.Fatal(err)
	}
	g.Alloc = genesisT.GenesisAlloc{}
	g.Alloc[common.Address{1}] = genesisT.GenesisAccount{Balance: big.NewInt(1)}
	if _, err := genesisBlock(g); err == nil {
		t.Fatal("a genesis with an allocation was built")
	}
}

// TestDeriveGenesisRefusesBadHeaders covers the header-chain checks and the
// refusals of the rule on the normal fixture's headers.
func TestDeriveGenesisRefusesBadHeaders(t *testing.T) {
	main := mainBranch(t, fixtureMainLen)
	raw := rawHeaders(main)
	without := func(i int) []byte {
		out := append([]byte{}, raw[:i*BitcoinHeaderSize]...)
		return append(out, raw[(i+1)*BitcoinHeaderSize:]...)
	}
	// Header 12 with a nonce that misses its target.
	badPoW := append([]byte{}, raw...)
	h12, _ := decodeBitcoinHeader(raw[12*BitcoinHeaderSize : 13*BitcoinHeaderSize])
	for nonce := h12.Nonce + 1; ; nonce++ {
		tampered := encodeBitcoinHeader(h12.Version, h12.PrevBlock, h12.MerkleRoot, h12.Time, h12.Bits, nonce)
		h, _ := decodeBitcoinHeader(tampered[:])
		if _, err := h.checkProofOfWork(); err != nil {
			copy(badPoW[12*BitcoinHeaderSize:], tampered[:])
			break
		}
	}
	// Header 12 with bits of a zero target.
	badBits := append([]byte{}, raw...)
	zero := encodeBitcoinHeader(h12.Version, h12.PrevBlock, h12.MerkleRoot, h12.Time, 0, h12.Nonce)
	copy(badBits[12*BitcoinHeaderSize:], zero[:])
	// Header 15 with a timestamp at its parent's median time past.
	early := append([]byte{}, raw[:15*BitcoinHeaderSize]...)
	h15 := mineFixtureHeader(t, main[14].hash, "early 15", mainTime(9))
	early = append(early, h15.raw[:]...)

	for _, c := range []struct {
		name    string
		headers []byte
		want    error
	}{
		{"empty file", nil, ErrHeaderFile},
		{"partial header", raw[:len(raw)-1], ErrHeaderFile},
		{"missing link", without(5), ErrHeaderLink},
		{"duplicate header", append(append([]byte{}, raw...), raw[:BitcoinHeaderSize]...), ErrDuplicateHeader},
		{"proof of work", badPoW, ErrProofOfWork},
		{"zero target", badBits, ErrBits},
		{"median time past", early, ErrMedianTime},
		{"T_L not reached", raw[:18*BitcoinHeaderSize], ErrNotReached},
		{"starts too late", raw[10*BitcoinHeaderSize:], ErrStartsLate},
	} {
		if _, err := Derive(fixtureTL, c.headers); !errors.Is(err, c.want) {
			t.Errorf("%s: error %v, want %v", c.name, err, c.want)
		}
	}
	// The usage is checked before anything is read.
	var stdout, stderr bytes.Buffer
	if err := run([]string{"derive", "-headers", "unused"}, &stdout, &stderr); !errors.Is(err, errUsage) {
		t.Errorf("no T_L: error %v, want the usage", err)
	}
}
