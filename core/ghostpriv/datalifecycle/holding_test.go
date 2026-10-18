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

package datalifecycle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The proof of holding is not part of the node (docs/data-commitments.md).
// Here it is a test-local stand-in for spec 04, section 5.
//
// The proof system is an oracle with a key of its own: it makes a proof only
// for a statement that holds, the wallet's commitment C, built with DATA, a
// leaf under the data tree root, and its marker outside the data marker set
// under the marker-set root, and the proof is a keyed hash of the binding
// digest. So nobody but the oracle makes a proof that verifies, as nobody
// but a holder makes a real one, and a proof is good for exactly the inputs
// its binding digest covers.
//
// The verifier runs the checks of section 5 in order, one error each:
//
//  1. the type is DATA and the purpose is hold (errHoldType);
//  2. the chain id and version are this chain's (errHoldChain);
//  3. the challenge is one it issued, not answered and not expired
//     (errHoldChallenge);
//  4. the verifier identity is its own (errHoldVerifier);
//  5. the roots: the marker-set root is the one at the height it accepts as
//     current, and the data tree root is in a header of its chain at or
//     below that height (errHoldRoot);
//  6. it computes the binding digest itself and checks the proof against it
//     (errHoldProof).
//
// Known gap by design: the data marker-set root is not in the block header
// (spec 04, section 5, header-only verifiers, not settled). The verifier
// therefore reads it from chain state: the storage root of the data marker
// account in the state of the header it accepts as current. The data tree
// root it takes from the header and checks with ghosttree.Root against the
// state, and the oracle reads the marker with ghosttree.IsSpent.
const (
	tagHoldingBinding = "ghost/test-holding/binding/v1"
	tagHoldingProof   = "ghost/test-holding/proof/v1"
	tagChallenge      = "ghost/test-holding/challenge/v1"
	tagProofSystemKey = "ghost/test-holding/system-key/v1"

	// purposeHold is the hold purpose of a proof of holding. It is no purpose
	// of the node, which never sees a proof of holding.
	purposeHold byte = 0x03

	// holdingSize is the length of an encoded proof of holding.
	holdingSize = 2 + 1 + 2 + 8 + 20 + 32 + 32 + 32 + 32
)

var (
	errHoldType      = errors.New("holding check 1: not a DATA proof with the hold purpose")
	errHoldChain     = errors.New("holding check 2: chain id or version is not this chain's")
	errHoldChallenge = errors.New("holding check 3: challenge not issued, answered or expired")
	errHoldVerifier  = errors.New("holding check 4: verifier identity is not this verifier's")
	errHoldRoot      = errors.New("holding check 5: roots are not current on this verifier's chain")
	errHoldProof     = errors.New("holding check 6: proof does not verify for the binding digest")

	// errNoProof is the oracle's answer to a statement that does not hold:
	// no valid proof exists.
	errNoProof = errors.New("no proof of holding exists for the statement")
)

// holdingProof is a proof of holding as presented to a verifier: its public
// inputs and the proof. The binding digest is not sent; the verifier
// computes it.
type holdingProof struct {
	Type          [2]byte
	Purpose       byte
	Version       uint16
	ChainID       uint64
	Verifier      common.Address
	Challenge     common.Hash
	DataRoot      common.Hash
	MarkerSetRoot common.Hash
	Proof         common.Hash
}

// encode is the proof's fixed layout, what travels to the verifier.
func (p holdingProof) encode() []byte {
	b := make([]byte, 0, holdingSize)
	b = append(b, p.Type[:]...)
	b = append(b, p.Purpose)
	b = binary.BigEndian.AppendUint16(b, p.Version)
	b = binary.BigEndian.AppendUint64(b, p.ChainID)
	b = append(b, p.Verifier[:]...)
	b = append(b, p.Challenge[:]...)
	b = append(b, p.DataRoot[:]...)
	b = append(b, p.MarkerSetRoot[:]...)
	return append(b, p.Proof[:]...)
}

func decodeHolding(b []byte) (holdingProof, error) {
	var p holdingProof
	if len(b) != holdingSize {
		return p, fmt.Errorf("proof of holding of %d bytes, want %d", len(b), holdingSize)
	}
	copy(p.Type[:], b[0:2])
	p.Purpose = b[2]
	p.Version = binary.BigEndian.Uint16(b[3:5])
	p.ChainID = binary.BigEndian.Uint64(b[5:13])
	p.Verifier = common.BytesToAddress(b[13:33])
	p.Challenge = common.BytesToHash(b[33:65])
	p.DataRoot = common.BytesToHash(b[65:97])
	p.MarkerSetRoot = common.BytesToHash(b[97:129])
	p.Proof = common.BytesToHash(b[129:161])
	return p, nil
}

// holdingBinding is the binding digest over every public input, with the
// genesis hash as the domain. The proof field is not covered.
func holdingBinding(p holdingProof, genesis common.Hash) common.Hash {
	enc := p.encode()
	return ghosttree.K(tagHoldingBinding, genesis[:], enc[:holdingSize-32])
}

// markerSetRoot is the data marker-set root of the state after header: the
// storage root of the data marker account (see the known gap above).
func markerSetRoot(n *node, header *types.Header) common.Hash {
	return n.stateAt(header).GetStorageRoot(ghost.DataMarkerAccount)
}

// proofSystem is the oracle standing in for the proof system.
type proofSystem struct {
	key common.Hash
}

func newProofSystem(label string) *proofSystem {
	return &proofSystem{key: ghosttree.K(tagProofSystemKey, []byte(label))}
}

func (ps *proofSystem) proofOf(binding common.Hash) common.Hash {
	return ghosttree.K(tagHoldingProof, ps.key[:], binding[:])
}

// holdingWitness is the prover's private input: the wallet's secrets, the
// content fingerprint, and the leaf's position and membership path.
type holdingWitness struct {
	w        *wallet
	cf       common.Hash
	position uint32
	path     [32]common.Hash

	// opens, if set, is a fingerprint the proof opens in place of the
	// wallet's own, under the data outer hash: an adversarial witness.
	opens *common.Hash
}

// prove makes the proof for the public inputs pub, whose marker-set root is
// claimed to be the one after header at on node n, if the statement holds:
// C = K(data commitment tag, DATA, F_d) is the leaf at the witness position
// under pub.DataRoot, and the marker derived from the same secrets is not in
// the marker set whose root is pub.MarkerSetRoot.
func (ps *proofSystem) prove(n *node, at *types.Header, wit holdingWitness, pub holdingProof) (holdingProof, error) {
	leaf := wit.w.commitment(wit.cf)
	if wit.opens != nil {
		leaf = ghostpriv.DataCommitment(*wit.opens)
	}
	root := pub.DataRoot
	if !ghosttree.VerifyMembership(&types.Header{DataTreeRoot: &root}, ghosttree.Data, wit.position, leaf, wit.path) {
		return holdingProof{}, fmt.Errorf("%w: C is not a leaf under the data tree root %x", errNoProof, pub.DataRoot)
	}
	st := n.stateAt(at)
	if st.GetStorageRoot(ghost.DataMarkerAccount) != pub.MarkerSetRoot {
		return holdingProof{}, fmt.Errorf("%w: the marker set at block %d is not the one named", errNoProof, at.Number)
	}
	if ghosttree.IsSpent(st, ghosttree.Data, wit.w.marker()) {
		return holdingProof{}, fmt.Errorf("%w: the marker is in the data marker set at block %d", errNoProof, at.Number)
	}
	pub.Proof = ps.proofOf(holdingBinding(pub, n.chain.Genesis().Hash()))
	return pub, nil
}

// holdingVerifier is a verifier of proofs of holding, with its own identity,
// the chain it trusts and its own challenge book.
type holdingVerifier struct {
	id       common.Address
	n        *node
	sys      *proofSystem
	chainID  uint64
	issued   map[common.Hash]uint64 // challenge to the tick it was issued at
	answered map[common.Hash]bool
	count    uint64
	now      uint64 // the verifier's clock, in ticks
	limit    uint64 // a challenge expires after this many ticks

	// current, if set, is the header the verifier accepts as current; else
	// it takes the latest header of its chain.
	current *types.Header
}

func newHoldingVerifier(label string, n *node, sys *proofSystem) *holdingVerifier {
	return &holdingVerifier{
		id:       address("verifier " + label),
		n:        n,
		sys:      sys,
		chainID:  n.chain.Config().GetChainID().Uint64(),
		issued:   make(map[common.Hash]uint64),
		answered: make(map[common.Hash]bool),
		limit:    10,
	}
}

// issue chooses a fresh challenge.
func (v *holdingVerifier) issue() common.Hash {
	v.count++
	c := ghosttree.K(tagChallenge, v.id[:], binary.BigEndian.AppendUint64(nil, v.count))
	v.issued[c] = v.now
	return c
}

// issueValue issues a challenge value the verifier chose elsewhere, so two
// verifiers can hold the same one.
func (v *holdingVerifier) issueValue(c common.Hash) { v.issued[c] = v.now }

func (v *holdingVerifier) currentHeader() *types.Header {
	if v.current != nil {
		return v.current
	}
	return v.n.head()
}

// verify runs checks 1 to 6 and, on success, records the challenge as
// answered.
func (v *holdingVerifier) verify(p holdingProof) error {
	// Check 1: type and purpose.
	if p.Type != ghostpriv.Data || p.Purpose != purposeHold {
		return fmt.Errorf("%w: type %x, purpose %#x", errHoldType, p.Type, p.Purpose)
	}
	// Check 2: chain id and version.
	if p.ChainID != v.chainID || p.Version != ghostpriv.Version {
		return fmt.Errorf("%w: chain %d, version %d", errHoldChain, p.ChainID, p.Version)
	}
	// Check 3: the challenge.
	at, ok := v.issued[p.Challenge]
	if !ok || v.answered[p.Challenge] || v.now-at > v.limit {
		return fmt.Errorf("%w: %x", errHoldChallenge, p.Challenge)
	}
	// Check 4: the verifier identity.
	if p.Verifier != v.id {
		return fmt.Errorf("%w: %v", errHoldVerifier, p.Verifier)
	}
	// Check 5: the roots, from the chain this verifier trusts.
	if err := v.checkRoots(p); err != nil {
		return err
	}
	// Check 6: the binding digest, computed here with this verifier's own
	// identity, and the proof.
	own := p
	own.Verifier = v.id
	if p.Proof != v.sys.proofOf(holdingBinding(own, v.n.chain.Genesis().Hash())) {
		return errHoldProof
	}
	v.answered[p.Challenge] = true
	return nil
}

// checkRoots is check 5: the marker-set root must be the current one, and the
// data tree root that of a canonical header at or below the current height,
// matching the data tree of that header's state.
func (v *holdingVerifier) checkRoots(p holdingProof) error {
	cur := v.currentHeader()
	if want := markerSetRoot(v.n, cur); p.MarkerSetRoot != want {
		return fmt.Errorf("%w: marker-set root %x, current %x at block %d", errHoldRoot, p.MarkerSetRoot, want, cur.Number)
	}
	for num := cur.Number.Uint64(); ; num-- {
		h := v.n.chain.GetHeaderByNumber(num)
		if h == nil {
			return fmt.Errorf("%w: no canonical block %d", errHoldRoot, num)
		}
		if h.DataTreeRoot != nil && *h.DataTreeRoot == p.DataRoot {
			root, err := ghosttree.Root(v.n.stateAt(h), ghosttree.Data)
			if err != nil || root != p.DataRoot {
				return fmt.Errorf("%w: header %d data tree root %x, state %x (%v)", errHoldRoot, num, p.DataRoot, root, err)
			}
			return nil
		}
		if num == 0 {
			return fmt.Errorf("%w: data tree root %x in no canonical header up to block %d", errHoldRoot, p.DataRoot, cur.Number)
		}
	}
}

// holdingRequest is the public inputs of a proof of holding for verifier v
// and challenge c, with the roots of header at on node n.
func holdingRequest(n *node, at *types.Header, v common.Address, c common.Hash) holdingProof {
	return holdingProof{
		Type:          ghostpriv.Data,
		Purpose:       purposeHold,
		Version:       ghostpriv.Version,
		ChainID:       n.chain.Config().GetChainID().Uint64(),
		Verifier:      v,
		Challenge:     c,
		DataRoot:      *at.DataTreeRoot,
		MarkerSetRoot: markerSetRoot(n, at),
	}
}

// proveHolding is the wallet's whole proof of holding on node n: restore
// from the digits through the endpoint, the witness from the bulk notes, and
// a proof against the roots of header at for verifier v and challenge c.
func proveHolding(t *testing.T, sys *proofSystem, n *node, at *types.Header, w *wallet, v common.Address, c common.Hash) (holdingProof, error) {
	t.Helper()
	ep := newEndpoint(t, n)
	ep.at = at
	r, err := w.restore(ep)
	if err != nil {
		return holdingProof{}, err
	}
	wit := holdingWitness{w: w, cf: r.content.cf, position: r.position, path: witness(t, r.notes, r.position)}
	return sys.prove(n, at, wit, holdingRequest(n, at, v, c))
}
