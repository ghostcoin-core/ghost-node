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

package ghostpriv_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
)

// The statement checker's known-answer fixture (KNOW_PREIMAGE_v1): the
// chain parameters (42 bytes), the statement in the layout of
// ghostverifier's ghost_preimage.h (116 bytes) and the proof the pinned
// prover made for them, uncompressed. The linked verifier's tests read it
// (verifier_cgo_test.go, realproof_timing_test.go), and the ghostverifier
// crate's tests/know_preimage.rs checks it is the prover's own proof.
const (
	preimageFixture        = "know_preimage.bin"
	preimageParamsBytes    = 42
	preimageStatementBytes = 116
)

const realPreimageRegenerate = `regenerate the fixture: cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example preimagefixture -- core/ghostpriv/testdata/know_preimage.bin, or, after changing the statement here, GHOST_REAL_PROOF_REQUEST=/tmp/know_preimage.req go test -run '^TestPreimageFixtureStatement$' ./core/ghostpriv/ and the same cargo run with /tmp/know_preimage.req before the output file (see ghostverifier/examples/preimagefixture.rs)`

// The fixture's statement: the example chain (id 1234, a genesis hash of
// 0x47 bytes), a calling policy, a test-only preimage x and a context whose
// byte i is i ^ 0xc5.
var (
	realPreimageChainID = uint64(1234)
	realPreimageGenesis = common.BytesToHash(bytes.Repeat([]byte{0x47}, 32))
	realPreimagePolicy  = common.HexToAddress("0x00000000000000000000000000000000c0ffee61")
	realPreimageX       = common.BytesToHash(bytes.Repeat([]byte{0x71}, 32))
)

// realPreimage returns the fixture's statement, its Proof the recorded
// proof, and that proof, after checking that the fixture was made for
// exactly the request the node's inputs give. With GHOST_REAL_PROOF_REQUEST
// set it writes the request and x to that file and skips the test.
func realPreimage(t *testing.T) (p *ghostpriv.Preimage, proof []byte) {
	t.Helper()
	p = &ghostpriv.Preimage{Y: ghostpriv.PreimageY(realPreimageX)}
	for i := range p.Context {
		p.Context[i] = byte(i) ^ 0xc5
	}
	in := p.VerifyInputs(realPreimageChainID, realPreimageGenesis, realPreimagePolicy)
	request := preimageRequest(in)
	if len(request) != preimageParamsBytes+preimageStatementBytes {
		t.Fatalf("request of %d bytes", len(request))
	}
	inputs := append(common.CopyBytes(request), realPreimageX[:]...)
	if out := os.Getenv("GHOST_REAL_PROOF_REQUEST"); out != "" {
		if err := os.WriteFile(out, inputs, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote the preimage proof request to %s", out)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", preimageFixture))
	if err != nil {
		t.Fatalf("%v; %s", err, realPreimageRegenerate)
	}
	if len(raw) <= len(request) || !bytes.Equal(raw[:len(request)], request) {
		t.Fatalf("the fixture is not for this statement; %s", realPreimageRegenerate)
	}
	proof = raw[len(request):]
	if len(proof) > ghostpriv.ActionProofSize {
		t.Fatalf("proof of %d bytes, the field holds %d", len(proof), ghostpriv.ActionProofSize)
	}
	p.Proof = proof
	return p, proof
}

// preimageRequest is the chain parameters and the KNOW_PREIMAGE_v1
// statement of in, in the layout of ghost_preimage.h: the chain id (8, big
// endian), version 1 (2) and the domain, then the policy, y and the context.
func preimageRequest(in *ghostpriv.VerifyInputs) []byte {
	b := binary.BigEndian.AppendUint64(nil, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, ghostpriv.PreimageVersion)
	b = append(b, in.Domain[:]...)
	b = append(b, in.Policy[:]...)
	b = append(b, in.Y[:]...)
	return append(b, in.Context[:]...)
}

// TestPreimageFixtureStatement checks, without the linked library, that the
// statement checker's fixture was made for the statement the node builds:
// its chain parameters, policy, y = K("ghost/policy-preimage/v1", x) and
// context are byte for byte the node's, at the offsets of ghost_preimage.h,
// and its proof fits the checker's proof field.
func TestPreimageFixtureStatement(t *testing.T) {
	p, proof := realPreimage(t)
	raw, err := os.ReadFile(filepath.Join("testdata", preimageFixture))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint64(raw[0:8]); got != realPreimageChainID {
		t.Fatalf("fixture chain id %d", got)
	}
	if got := binary.BigEndian.Uint16(raw[8:10]); got != ghostpriv.PreimageVersion {
		t.Fatalf("fixture version %d", got)
	}
	s := raw[preimageParamsBytes : preimageParamsBytes+preimageStatementBytes]
	if common.BytesToAddress(s[0:20]) != realPreimagePolicy {
		t.Fatalf("fixture policy %x", s[0:20])
	}
	if common.BytesToHash(s[20:52]) != ghostpriv.PreimageY(realPreimageX) {
		t.Fatalf("fixture y %x is not the node's K of x", s[20:52])
	}
	if !bytes.Equal(s[52:], p.Context[:]) {
		t.Fatalf("fixture context %x", s[52:])
	}
	if len(proof) == 0 || len(proof) > ghostpriv.ActionProofSize {
		t.Fatalf("proof of %d bytes", len(proof))
	}
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ghostpriv.DecodePreimageInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Y != p.Y || dec.Context != p.Context || !bytes.Equal(dec.Proof[:len(proof)], proof) {
		t.Fatal("the checker input does not carry the fixture's statement and proof")
	}
}
