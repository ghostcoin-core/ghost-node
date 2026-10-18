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

package linkage

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// setup is the real design and what the check needs.
type setup struct {
	raw  []rawHop
	w    *whitelist
	tags []string
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	f := realDesign(t)
	tags, err := knownTags()
	if err != nil {
		t.Fatalf("reading the hash tags: %v", err)
	}
	return &setup{raw: f.hops, w: newWhitelist(f), tags: tags}
}

// variant returns deep copies of the three hops to link by hand.
func (s *setup) variant() (commit, partial, remainder rawHop) {
	return s.raw[0].clone(), s.raw[1].clone(), s.raw[2].clone()
}

func (s *setup) decode(t *testing.T, raws ...rawHop) []*hop {
	t.Helper()
	hops := make([]*hop, len(raws))
	for i, raw := range raws {
		h, err := decodeHop(raw)
		if err != nil {
			t.Fatalf("decoding hop: %v", err)
		}
		hops[i] = h
	}
	return hops
}

func (s *setup) check(t *testing.T, raws ...rawHop) ([]link, []allowed) {
	t.Helper()
	return checkLinkage(s.decode(t, raws...), s.w, s.tags)
}

// requireLink fails unless the check reports a link between field fieldA
// of hopA and field fieldB of hopB, in either order; the fields match by
// prefix. how, if set, must appear in the link's text.
func requireLink(t *testing.T, links []link, hopA, fieldA, hopB, fieldB, how string) {
	t.Helper()
	if len(links) == 0 {
		t.Fatalf("the check passed; want a link between %s %s and %s %s", hopA, fieldA, hopB, fieldB)
	}
	for _, l := range links {
		msg := l.String()
		if !strings.Contains(msg, how) {
			continue
		}
		if (l.hopA == hopA && strings.HasPrefix(l.fieldA, fieldA) && l.hopB == hopB && strings.HasPrefix(l.fieldB, fieldB)) ||
			(l.hopA == hopB && strings.HasPrefix(l.fieldA, fieldB) && l.hopB == hopA && strings.HasPrefix(l.fieldB, fieldA)) {
			if !strings.Contains(msg, hopA) || !strings.Contains(msg, hopB) || !strings.Contains(msg, fieldA) || !strings.Contains(msg, fieldB) {
				t.Fatalf("the link %q does not name both hops and fields", msg)
			}
			t.Logf("caught: %s", msg)
			return
		}
	}
	for _, l := range links {
		t.Logf("link: %s", l)
	}
	t.Fatalf("no link between %s %s and %s %s among %d links", hopA, fieldA, hopB, fieldB, len(links))
}

func fieldOf(t *testing.T, h *hop, name string) []byte {
	t.Helper()
	for _, f := range h.fields {
		if f.name == name {
			return common.CopyBytes(f.value)
		}
	}
	t.Fatalf("%s has no field %s", h.name, name)
	return nil
}

func spanOf(t *testing.T, h *hop, name string) span {
	t.Helper()
	for _, seg := range h.segments {
		for _, sp := range seg.spans {
			if sp.name == name {
				return sp
			}
		}
	}
	t.Fatalf("%s has no field %s", h.name, name)
	return span{}
}

// setMarker writes a reveal's marker into its payload and its receipt's
// topic, as a wallet that chose that marker would have.
func setMarker(raw *rawHop, marker []byte) {
	copy(raw.tx[revMarker:revMarker+32], marker)
	raw.logs[0].Topics[1] = common.BytesToHash(marker)
}

// setRemainder writes a reveal's remainder into its payload and its
// receipt's data.
func setRemainder(raw *rawHop, remainder []byte) {
	copy(raw.tx[revRemainder:revRemainder+32], remainder)
	copy(raw.logs[0].Data[8:40], remainder)
}

// TestLinkageThreeHopsRealDesign pulls the commit, the partial reveal and
// the reveal of the remainder from the chain and finds no value shared by
// two of them outside the whitelist.
func TestLinkageThreeHopsRealDesign(t *testing.T) {
	s := newSetup(t)
	hops := s.decode(t, s.raw...)

	// The check reads what it must: both kinds of transaction and receipt,
	// with the layouts of the coin rules.
	fieldOf(t, hops[0], "transaction.data.F")
	fieldOf(t, hops[0], "log[0].data.leaf")
	fieldOf(t, hops[0], "log[0].topic[0]")
	for _, h := range hops[1:] {
		r, err := ghostpriv.DecodeReveal(fieldOf(t, h, "transaction"))
		if err != nil {
			t.Fatalf("%s does not decode as a reveal: %v", h.name, err)
		}
		for name, want := range map[string][]byte{
			"payload.marker":    r.Marker[:],
			"payload.root":      r.Root[:],
			"payload.remainder": r.Remainder[:],
			"payload.recipient": r.Recipient[:],
			"payload.out":       common.LeftPadBytes(r.Out.Bytes(), 32),
			"payload.fee":       common.LeftPadBytes(r.Fee.Bytes(), 32),
			"payload.proof":     r.Proof,
			"payload.note":      r.Note[:],
		} {
			if got := fieldOf(t, h, name); !bytes.Equal(got, want) {
				t.Fatalf("%s: the layout here reads %s as %x, the coin rules as %x", h.name, name, got, want)
			}
		}
		if r.Version != ghostpriv.Version || r.ChainID != s.w.chainID {
			t.Fatalf("%s: version %d, chain id %d", h.name, r.Version, r.ChainID)
		}
		if !s.w.roots[r.Root] {
			t.Fatalf("%s: root %x is not in a block header", h.name, r.Root)
		}
		fieldOf(t, h, "log[0].topic[1]")
		fieldOf(t, h, "log[0].data.remainder")
	}

	// Every tag constant of the coin rules and the tree is searched.
	for _, tag := range []string{
		ghostpriv.TagCommitment, ghostpriv.TagRevealBinding, ghostpriv.TagCommitReceipt, ghostpriv.TagRevealReceipt,
		ghosttree.TagEmptyLeaf, ghosttree.TagCoinNode, ghosttree.TagDataNode, ghostprivtest.TagTestProof, tagMarker,
	} {
		if !slices.Contains(s.tags, tag) {
			t.Fatalf("the tag %q is not among the %d known tags", tag, len(s.tags))
		}
	}

	links, ok := checkLinkage(hops, s.w, s.tags)
	for _, l := range links {
		t.Errorf("link: %s", l)
	}
	if len(ok) == 0 {
		t.Fatal("no shared value was admitted; the reveals share at least the type byte, version and chain id")
	}
	zeros := 0
	for _, a := range ok {
		switch a.reason {
		case "":
			t.Fatalf("%s admitted without a reason", a.link)
		case reasonZero:
			zeros++
		default:
			t.Logf("admitted: %s, because it is %s", a.link, a.reason)
		}
	}
	t.Logf("admitted %d all-zero fields as zero padding; searched %d hash tags", zeros, len(s.tags))
}

// TestLinkageCatchesRevealNamingCommitment links the partial reveal to the
// commit by carrying the commit's leaf, as the marker and inside the proof.
func TestLinkageCatchesRevealNamingCommitment(t *testing.T) {
	s := newSetup(t)
	leaf := fieldOf(t, s.decode(t, s.raw[0])[0], "log[0].data.leaf")

	t.Run("as the marker", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		setMarker(&partial, leaf)
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopCommit, "log[0].data.leaf", hopPartial, "payload.marker", "")
	})
	t.Run("inside the proof", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		copy(partial.tx[revProof+64:], leaf)
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopCommit, "log[0].data.leaf", hopPartial, "payload.proof[32:]", "")
	})
}

// TestLinkageCatchesReusedBlinding gives the reveal of the remainder the
// marker or the remainder of the partial reveal, as a wallet reusing the
// blinding of the first reveal would.
func TestLinkageCatchesReusedBlinding(t *testing.T) {
	s := newSetup(t)
	first := s.decode(t, s.raw[1])[0]

	t.Run("marker", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		setMarker(&remainder, fieldOf(t, first, "payload.marker"))
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.marker", hopRemainder, "payload.marker", "equal values")
		requireLink(t, links, hopPartial, "log[0].topic[1]", hopRemainder, "log[0].topic[1]", "equal values")
	})
	t.Run("remainder", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		setRemainder(&remainder, fieldOf(t, first, "payload.remainder"))
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.remainder", hopRemainder, "payload.remainder", "equal values")
	})
}

// TestLinkageCatchesSingleHashDerivation sets a field of one hop to a single
// tagged hash of a field of another, in both directions.
func TestLinkageCatchesSingleHashDerivation(t *testing.T) {
	s := newSetup(t)
	hops := s.decode(t, s.raw...)
	f := fieldOf(t, hops[0], "transaction.data.F")

	t.Run("marker from the commit's F", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		setMarker(&partial, ghosttree.K(ghostpriv.TagCommitment, f).Bytes())
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopCommit, "transaction.data.F", hopPartial, "payload.marker", ghostpriv.TagCommitment)
	})
	t.Run("note word from the first reveal's marker", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		derived := ghosttree.K(ghosttree.TagCoinNode, fieldOf(t, hops[1], "payload.marker"))
		copy(remainder.tx[revNote:revNote+32], derived[:])
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.marker", hopRemainder, "payload.note[0:32]", ghosttree.TagCoinNode)
	})
	t.Run("the commit's F from the last reveal's remainder", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		derived := ghosttree.K(ghostpriv.TagRevealBinding, fieldOf(t, hops[2], "payload.remainder"))
		sp := spanOf(t, hops[0], "transaction.data.F")
		copy(commit.tx[sp.off:sp.end], derived[:])
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopCommit, "transaction.data.F", hopRemainder, "payload.remainder", ghostpriv.TagRevealBinding)
	})
}

// TestLinkageCatchesCopiedSubfield copies 16 bytes of one hop's note, off
// any field boundary, into another hop.
func TestLinkageCatchesCopiedSubfield(t *testing.T) {
	s := newSetup(t)

	t.Run("note to note", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		copy(remainder.tx[revNote+70:], partial.tx[revNote+37:revNote+37+minRun])
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.note", hopRemainder, "payload.note", "share a run")
	})
	t.Run("commit note into the proof", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		sp := spanOf(t, s.decode(t, commit)[0], "transaction.data.note")
		copy(partial.tx[revProof+1000:], commit.tx[sp.off+5:sp.off+5+minRun])
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopCommit, "transaction.data.note", hopPartial, "payload.proof", "share a run")
	})
}

// TestLinkageCatchesSharedValueNotOnWhitelist shares values that resemble
// whitelisted ones but are not on the list, and shows that a value that is
// on it passes.
func TestLinkageCatchesSharedValueNotOnWhitelist(t *testing.T) {
	s := newSetup(t)
	hops := s.decode(t, s.raw...)

	t.Run("a root no header carries", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		root := ghosttree.K(ghosttree.TagCoinNode, []byte("synthetic root of no block"))
		if s.w.roots[root] {
			t.Fatal("the synthetic root is a header's root")
		}
		copy(partial.tx[revRoot:], root[:])
		copy(remainder.tx[revRoot:], root[:])
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.root", hopRemainder, "payload.root", "equal values")
	})
	t.Run("the proof of another reveal", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		copy(remainder.tx[revProof:revProof+32], partial.tx[revProof:revProof+32])
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.proof[0:32]", hopRemainder, "payload.proof[0:32]", "equal values")
	})
	t.Run("a chain id in a field that is not one", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		word := common.LeftPadBytes(fieldOf(t, hops[1], "payload.chainId"), 32)
		copy(partial.tx[revOut:revOut+32], word)
		copy(remainder.tx[revOut:revOut+32], word)
		links, _ := s.check(t, commit, partial, remainder)
		requireLink(t, links, hopPartial, "payload.out", hopRemainder, "payload.out", "equal values")
	})
	t.Run("a header root is admitted", func(t *testing.T) {
		commit, partial, remainder := s.variant()
		copy(remainder.tx[revRoot:revRoot+32], partial.tx[revRoot:revRoot+32])
		links, ok := s.check(t, commit, partial, remainder)
		for _, l := range links {
			t.Errorf("link: %s", l)
		}
		for _, a := range ok {
			if strings.HasPrefix(a.fieldA, "payload.root") && a.reason == reasonTreeRoot {
				return
			}
		}
		t.Fatal("the shared header root was not admitted as the shared tree state")
	})
}
