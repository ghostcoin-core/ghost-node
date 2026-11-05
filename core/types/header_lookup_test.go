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

package types

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// genesisLookupVectors reads the [genesis-header] block of the decision 0004
// vectors vendored in core/ghosttree/testdata.
func genesisLookupVectors(t *testing.T) map[string]common.Hash {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "ghosttree", "testdata", "decision_0004_vectors.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]common.Hash{}
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			in = line == "[genesis-header]"
		case in:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("vector line %q", line)
			}
			out[strings.TrimSpace(k)] = common.HexToHash(strings.TrimSpace(v))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"coinLookupRoot", "dataLookupRoot", "coinMarkerRoot", "lookupDigest"} {
		if out[k] == (common.Hash{}) {
			t.Fatalf("vector genesis-header.%s missing", k)
		}
	}
	return out
}

// itemAt returns the content of item i of the RLP list b.
func itemAt(t *testing.T, b []byte, i int) []byte {
	t.Helper()
	content, _, err := rlp.SplitList(b)
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; ; j++ {
		_, val, rest, err := rlp.Split(content)
		if err != nil {
			t.Fatalf("item %d: %v", i, err)
		}
		if j == i {
			return val
		}
		content = rest
	}
}

// TestHeaderLookupGolden checks the 23-item Ghost header of decision 0004:
// the four lookup fields at items 19 to 22 with the genesis values of the
// vectors, the round trip through both decoders, the strict decoder's
// item-count rejection of the 19 items before them, and that each field is
// covered by the hash.
func TestHeaderLookupGolden(t *testing.T) {
	v := genesisLookupVectors(t)
	g := vectorGenesis()
	for name, f := range map[string]*common.Hash{
		"coinLookupRoot": g.CoinLookupRoot, "dataLookupRoot": g.DataLookupRoot,
		"coinMarkerRoot": g.CoinMarkerRoot, "lookupDigest": g.LookupDigest,
	} {
		if *f != v[name] {
			t.Errorf("genesis %s %x, want the vector's %x", name, *f, v[name])
		}
	}
	enc, err := rlp.EncodeToBytes(g)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, mustHex(t, vectorGenesisRLP)) {
		t.Errorf("genesis encodes as %x", enc)
	}
	if n := countItems(t, enc); n != 23 {
		t.Fatalf("genesis has %d items, want 23", n)
	}
	for i, name := range []string{"coinLookupRoot", "dataLookupRoot", "coinMarkerRoot", "lookupDigest"} {
		want := v[name]
		if got := itemAt(t, enc, 19+i); !bytes.Equal(got, want[:]) {
			t.Errorf("item %d is %x, want %s %x", 19+i, got, name, want)
		}
	}
	if got := itemAt(t, enc, 18); !bytes.Equal(got, g.DataMarkerRoot[:]) {
		t.Errorf("item 18 is %x, want the data marker root", got)
	}

	// Both decoders give the fields back, and the strict one the same bytes.
	strict, err := DecodeGhostHeader(enc)
	if err != nil {
		t.Fatal(err)
	}
	var dec Header
	if err := rlp.DecodeBytes(enc, &dec); err != nil {
		t.Fatal(err)
	}
	for _, h := range []*Header{strict, &dec} {
		if !h.HasLookupFields() || *h.CoinLookupRoot != v["coinLookupRoot"] || *h.DataLookupRoot != v["dataLookupRoot"] ||
			*h.CoinMarkerRoot != v["coinMarkerRoot"] || *h.LookupDigest != v["lookupDigest"] {
			t.Errorf("decoded lookup fields %v %v %v %v", h.CoinLookupRoot, h.DataLookupRoot, h.CoinMarkerRoot, h.LookupDigest)
		}
		if h.Hash() != g.Hash() {
			t.Errorf("decoded hash %x, want %x", h.Hash(), g.Hash())
		}
		if re, _ := rlp.EncodeToBytes(h); !bytes.Equal(re, enc) {
			t.Errorf("round trip gives %x", re)
		}
	}

	// The 19 items before the lookup fields are no Ghost header.
	old := spec05Genesis()
	oldEnc, err := rlp.EncodeToBytes(old)
	if err != nil {
		t.Fatal(err)
	}
	if n := countItems(t, oldEnc); n != 19 {
		t.Fatalf("the header without lookup fields has %d items", n)
	}
	var reject *GhostHeaderError
	if _, err := DecodeGhostHeader(oldEnc); !errors.As(err, &reject) || reject.Reason != GhostReasonItemCount {
		t.Errorf("a 19-item header: %v, want %s", err, GhostReasonItemCount)
	}
	if old.Hash() == g.Hash() {
		t.Error("the lookup fields leave the hash unchanged")
	}

	// Each field is covered by the hash, and copied apart.
	for name, field := range map[string]func(h *Header) *common.Hash{
		"coinLookupRoot": func(h *Header) *common.Hash { return h.CoinLookupRoot },
		"dataLookupRoot": func(h *Header) *common.Hash { return h.DataLookupRoot },
		"coinMarkerRoot": func(h *Header) *common.Hash { return h.CoinMarkerRoot },
		"lookupDigest":   func(h *Header) *common.Hash { return h.LookupDigest },
	} {
		cpy := CopyHeader(g)
		if field(cpy) == field(g) {
			t.Errorf("%s: CopyHeader shares the pointer", name)
		}
		field(cpy)[7] ^= 1
		if cpy.Hash() == g.Hash() {
			t.Errorf("%s: a changed field leaves the hash unchanged", name)
		}
		if *field(g) != v[name] {
			t.Errorf("%s: changing the copy changed the original", name)
		}
	}
	bare := CopyHeader(g)
	bare.CoinLookupRoot, bare.DataLookupRoot, bare.CoinMarkerRoot, bare.LookupDigest = nil, nil, nil, nil
	if diff := g.Size() - bare.Size(); diff != 4*common.HashLength {
		t.Errorf("the lookup fields add %v to the size, want %d", diff, 4*common.HashLength)
	}

	// Some but not all four, or the four without the roots, do not encode.
	for name, mutate := range map[string]func(h *Header){
		"no coin lookup root":  func(h *Header) { h.CoinLookupRoot = nil },
		"no data lookup root":  func(h *Header) { h.DataLookupRoot = nil },
		"no coin marker root":  func(h *Header) { h.CoinMarkerRoot = nil },
		"no lookup digest":     func(h *Header) { h.LookupDigest = nil },
		"lookup digest only":   func(h *Header) { h.CoinLookupRoot, h.DataLookupRoot, h.CoinMarkerRoot = nil, nil, nil },
		"without a tree root":  func(h *Header) { h.DataTreeRoot = nil },
		"without the roots":    func(h *Header) { h.CoinTreeRoot, h.DataTreeRoot, h.DataMarkerRoot = nil, nil, nil },
		"without the base fee": func(h *Header) { h.BaseFee = nil },
	} {
		h := vectorGenesis()
		mutate(h)
		if b, err := rlp.EncodeToBytes(h); err == nil {
			t.Errorf("%s: encoded as %x", name, b)
		}
	}
	// A 23-item list whose digest is not 32 bytes is no Ghost header for
	// the ordinary decoder either.
	short := mustHex(t, "f90304"+genesisBody+genesisLookup[:3*66]+"9f"+strings.Repeat("00", 31))
	if err := rlp.DecodeBytes(short, &dec); err == nil && dec.HasLookupFields() {
		t.Error("a short digest decodes as a Ghost header")
	}
	if _, err := DecodeGhostHeader(short); !errors.As(err, &reject) || reject.Reason != GhostReasonFieldSize {
		t.Errorf("a short digest: %v, want %s", err, GhostReasonFieldSize)
	}
}
