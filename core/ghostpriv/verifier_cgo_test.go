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

//go:build cgo && (ghostrelease || ghostproofs) && (linux || darwin)

package ghostpriv_test

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/holiman/uint256"
)

// errDefaultDataVerifier is the default verifier's answer to a data reveal
// whose proof is not its own: the linked proof verifier rejects it.
var errDefaultDataVerifier = ghostpriv.ErrProofRejected

// Lengths of the chain parameters and of the coin reveal statement in the
// layout of ghost_proofs.h.
const (
	chainParamsBytes = 42
	coinRevealBytes  = 368
)

// knownAnswer is one honest coin reveal made by the pinned ghost-proofs
// prover (ghostverifier/examples/knownanswer.rs): the chain parameters and
// statement in the layout of ghost_proofs.h, and the full proof.
type knownAnswer struct {
	params, statement, proof []byte
}

// knownAnswerFiles are the known-answer fixtures by commitment format: a
// salted (version 2) coin only, since the node takes no version 1 coin.
var knownAnswerFiles = []struct{ name, file string }{
	{"salted version 2", "salted_coin_reveal.bin.gz"},
}

// loadKnownAnswer loads the salted fixture.
func loadKnownAnswer(t *testing.T) knownAnswer {
	t.Helper()
	return loadKnownAnswerFile(t, "salted_coin_reveal.bin.gz")
}

func loadKnownAnswerFile(t *testing.T, name string) knownAnswer {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= chainParamsBytes+coinRevealBytes {
		t.Fatalf("fixture of %d bytes", len(raw))
	}
	return knownAnswer{
		params:    raw[:chainParamsBytes],
		statement: raw[chainParamsBytes : chainParamsBytes+coinRevealBytes],
		proof:     raw[chainParamsBytes+coinRevealBytes:],
	}
}

// inputs reads the fixture into the inputs the node computes for the reveal,
// field by field at the offsets of ghost_proofs.h.
func (ka knownAnswer) inputs(t *testing.T) *ghostpriv.VerifyInputs {
	t.Helper()
	p, s := ka.params, ka.statement
	if v := binary.BigEndian.Uint16(p[8:10]); v != ghostpriv.Version {
		t.Fatalf("fixture version %d", v)
	}
	in := &ghostpriv.VerifyInputs{
		Kind:      ghosttree.Coin,
		Purpose:   ghostpriv.PurposeReveal,
		Version:   ghostpriv.RevealVersionV1,
		ChainID:   binary.BigEndian.Uint64(p[0:8]),
		Domain:    common.BytesToHash(p[10:42]),
		Root:      common.BytesToHash(s[0:32]),
		Marker:    common.BytesToHash(s[32:64]),
		Remainder: common.BytesToHash(s[64:96]),
		Recipient: common.BytesToAddress(s[252:272]),
		Out:       new(uint256.Int).SetBytes(s[272:304]),
		Fee:       new(uint256.Int).SetBytes(s[304:336]),
		Rule:      common.BytesToHash(s[336:368]),
	}
	copy(in.Note[:], s[96:252])
	return in
}

// TestGhostDataVerifierPlainRejection checks that data reveals and revokes
// reach the linked proof verifier through ghost_data.h and that a proof that
// is not theirs is ErrProofRejected and never an acceptance, whatever the fee
// or rule: a zero fee, a fee at the data reserve, a fee above it and a
// non-empty rule. A fee above the reserve and a non-empty rule are plain
// rejections, the status "rejected", whatever the proof. The accept
// path for real data proofs is in the ghostverifier crate's tests
// (ghostverifier/tests/data_reveal.rs). The well-formed proof here is the coin
// fixture's; a malformed one is still ErrProofRejected.
func TestGhostDataVerifierPlainRejection(t *testing.T) {
	ka := loadKnownAnswer(t)
	coin := ka.inputs(t)
	v := ghostpriv.DefaultVerifier()
	data := func(purpose byte) *ghostpriv.VerifyInputs {
		return &ghostpriv.VerifyInputs{
			Kind:      ghosttree.Data,
			Purpose:   purpose,
			ChainID:   coin.ChainID,
			Domain:    coin.Domain,
			Root:      coin.Root,
			Marker:    coin.Marker,
			Recipient: coin.Recipient,
			Out:       new(uint256.Int),
			Fee:       new(uint256.Int),
			Cf:        common.Hash{0: 0xcf, 31: 0x01},
		}
	}
	proof := func() []byte { return common.CopyBytes(ka.proof) }
	atReserve := new(uint256.Int).Set(ghostpriv.DataReserve)
	aboveReserve := new(uint256.Int).AddUint64(ghostpriv.DataReserve, 1)
	// Each statement and, for those the verifier rejects before it reads the
	// proof, the status it names: the coin proof does not decode as a data
	// proof, so for the others it may be "malformed input".
	statements := map[string]struct {
		change func(in *ghostpriv.VerifyInputs)
		status string
	}{
		"zero fee":              {func(*ghostpriv.VerifyInputs) {}, ""},
		"fee at the reserve":    {func(in *ghostpriv.VerifyInputs) { in.Fee = atReserve }, ""},
		"fee above the reserve": {func(in *ghostpriv.VerifyInputs) { in.Fee = aboveReserve }, "rejected"},
		"non-empty rule":        {func(in *ghostpriv.VerifyInputs) { in.Rule = common.Hash{31: 1} }, "rejected"},
	}

	for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
		for sname, st := range statements {
			for pname, p := range map[string][]byte{
				"proof":           proof(),
				"proof and zeros": append(proof(), make([]byte, 4096)...),
				"proof field":     append(proof(), make([]byte, ghostpriv.ProofSize-len(ka.proof))...),
			} {
				for vname, verifier := range map[string]ghostpriv.Verifier{"default": v, "active": ghostpriv.ActiveVerifier()} {
					in := data(purpose)
					st.change(in)
					err := verifier.VerifyReveal(in, p)
					if err == nil {
						t.Fatalf("purpose %#x, %s, %s, %s verifier: accepted", purpose, sname, pname, vname)
					}
					if !errors.Is(err, ghostpriv.ErrProofRejected) {
						t.Errorf("purpose %#x, %s, %s, %s verifier: %v, want %v", purpose, sname, pname, vname, err, ghostpriv.ErrProofRejected)
					}
					if st.status != "" && err.Error() != ghostpriv.ErrProofRejected.Error()+": "+st.status {
						t.Errorf("purpose %#x, %s, %s, %s verifier: %v, want status %q", purpose, sname, pname, vname, err, st.status)
					}
				}
			}
		}

		n := len(ka.proof)
		padded := append(proof(), make([]byte, 64)...)
		padded[n+10] = 1
		for name, p := range map[string][]byte{
			"non-zero padding": padded,
			"truncated":        proof()[:n-1],
			"empty":            nil,
			"oversized":        make([]byte, 2<<20+1),
		} {
			if err := v.VerifyReveal(data(purpose), p); !errors.Is(err, ghostpriv.ErrProofRejected) {
				t.Errorf("purpose %#x, %s: %v, want %v", purpose, name, err, ghostpriv.ErrProofRejected)
			}
		}
	}

	// What the verifier does not verify is not passed to it.
	for _, purpose := range []byte{0x00, 0x03, 0x04, 0xff} {
		if err := v.VerifyReveal(data(purpose), proof()); !errors.Is(err, ghostpriv.ErrProofStatement) {
			t.Errorf("data purpose %#x: %v, want %v", purpose, err, ghostpriv.ErrProofStatement)
		}
	}
	in := data(ghostpriv.PurposeReveal)
	in.Kind = ghosttree.Kind(7)
	if err := v.VerifyReveal(in, proof()); !errors.Is(err, ghostpriv.ErrProofStatement) {
		t.Errorf("unknown kind: %v, want %v", err, ghostpriv.ErrProofStatement)
	}
}

// TestGhostVerifierKnownAnswerPreimage checks the statement checker's
// verifier, linked from ghostverifier's ghost_preimage.h, against the pinned
// prover's real proof: the default verifier, which is the active one, says
// it verifies the statement and accepts the proof through VerifyPreimage, the
// statement checker's path, and through VerifyReveal with the proof field
// padded or not. It rejects the proof with any public input changed, with a
// flipped proof byte, of a bad length or as another statement, and refuses
// another version of the statement without calling the library.
func TestGhostVerifierKnownAnswerPreimage(t *testing.T) {
	defer ghostpriv.SetVerifier(nil)()
	p, proof := realPreimage(t)
	if p.Y != ghostpriv.PreimageY(realPreimageX) {
		t.Fatalf("y %x is not K of the fixture's x", p.Y)
	}
	v := ghostpriv.DefaultVerifier()
	pv, ok := v.(ghostpriv.PreimageVerifier)
	if !ok || !pv.VerifiesPreimage() {
		t.Fatal("the default verifier does not verify the statement checker's statement")
	}
	input, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(input) != ghostpriv.PreimageInputSize {
		t.Fatalf("checker input of %d bytes", len(input))
	}
	clone := func() *ghostpriv.VerifyInputs {
		return p.VerifyInputs(realPreimageChainID, realPreimageGenesis, realPreimagePolicy)
	}
	field := func() []byte {
		return append(common.CopyBytes(proof), make([]byte, ghostpriv.ActionProofSize-len(proof))...)
	}
	rejected := func(t *testing.T, name string, err error, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}

	t.Run("valid proof accepted", func(t *testing.T) {
		// The statement checker's path: the active verifier, then the
		// default one given outright.
		if err := ghostpriv.VerifyPreimage(nil, realPreimageChainID, realPreimageGenesis, realPreimagePolicy, input); err != nil {
			t.Fatalf("statement check with the active verifier: %v", err)
		}
		if err := ghostpriv.VerifyPreimage(v, realPreimageChainID, realPreimageGenesis, realPreimagePolicy, input); err != nil {
			t.Fatalf("statement check with the default verifier: %v", err)
		}
		if err := v.VerifyReveal(clone(), common.CopyBytes(proof)); err != nil {
			t.Fatalf("the proof: %v", err)
		}
		if err := v.VerifyReveal(clone(), field()); err != nil {
			t.Fatalf("the proof field: %v", err)
		}
		if err := ghostpriv.ActiveVerifier().VerifyReveal(clone(), field()); err != nil {
			t.Fatalf("the active verifier: %v", err)
		}
	})

	t.Run("changed public input rejected", func(t *testing.T) {
		for name, change := range map[string]func(in *ghostpriv.VerifyInputs){
			"chain id":      func(in *ghostpriv.VerifyInputs) { in.ChainID++ },
			"domain":        func(in *ghostpriv.VerifyInputs) { in.Domain[31] ^= 1 },
			"policy":        func(in *ghostpriv.VerifyInputs) { in.Policy[19] ^= 1 },
			"y":             func(in *ghostpriv.VerifyInputs) { in.Y[0] ^= 1 },
			"context start": func(in *ghostpriv.VerifyInputs) { in.Context[0] ^= 1 },
			"context end":   func(in *ghostpriv.VerifyInputs) { in.Context[ghostpriv.PreimageContextSize-1] ^= 1 },
		} {
			in := clone()
			change(in)
			rejected(t, name, v.VerifyReveal(in, field()), ghostpriv.ErrProofRejected)
		}
		// Through the statement checker's path: another caller, chain or
		// genesis, or a changed y or context in the input.
		check := func(name string, chainID uint64, genesis common.Hash, policy common.Address, in []byte) {
			err := ghostpriv.VerifyPreimage(nil, chainID, genesis, policy, in)
			rejected(t, name, err, ghostpriv.ErrPreimageProof)
			rejected(t, name, err, ghostpriv.ErrProofRejected)
		}
		other := realPreimagePolicy
		other[0] ^= 1
		check("other policy", realPreimageChainID, realPreimageGenesis, other, input)
		check("other chain", realPreimageChainID+1, realPreimageGenesis, realPreimagePolicy, input)
		check("other genesis", realPreimageChainID, common.Hash{0x01}, realPreimagePolicy, input)
		for _, at := range []int{1, 32, 33, 33 + ghostpriv.PreimageContextSize - 1} {
			bad := common.CopyBytes(input)
			bad[at] ^= 1
			check("input byte "+strconv.Itoa(at), realPreimageChainID, realPreimageGenesis, realPreimagePolicy, bad)
		}
	})

	t.Run("bad proof rejected", func(t *testing.T) {
		n := len(proof)
		for _, at := range []int{0, 1, n / 3, n / 2, 2 * n / 3, n - 1} {
			q := field()
			q[at] ^= 1
			rejected(t, "flipped byte "+strconv.Itoa(at), v.VerifyReveal(clone(), q), ghostpriv.ErrProofRejected)
		}
		padded := field()
		padded[n+10] = 1
		rejected(t, "non-zero padding", v.VerifyReveal(clone(), padded), ghostpriv.ErrProofRejected)
		rejected(t, "truncated", v.VerifyReveal(clone(), common.CopyBytes(proof[:n-1])), ghostpriv.ErrProofRejected)
		rejected(t, "empty", v.VerifyReveal(clone(), nil), ghostpriv.ErrProofRejected)
		rejected(t, "longer than the field", v.VerifyReveal(clone(), append(field(), 0)), ghostpriv.ErrProofRejected)
		rejected(t, "zero proof field", v.VerifyReveal(clone(), make([]byte, ghostpriv.ActionProofSize)), ghostpriv.ErrProofRejected)
		ka := loadKnownAnswer(t)
		rejected(t, "a coin reveal's proof", v.VerifyReveal(clone(), common.CopyBytes(ka.proof)), ghostpriv.ErrProofRejected)
		bad := common.CopyBytes(input)
		bad[1+32+ghostpriv.PreimageContextSize+n/2] ^= 1
		err := ghostpriv.VerifyPreimage(nil, realPreimageChainID, realPreimageGenesis, realPreimagePolicy, bad)
		rejected(t, "statement check with a flipped proof byte", err, ghostpriv.ErrPreimageProof)
	})

	t.Run("other statements and versions", func(t *testing.T) {
		in := clone()
		in.Purpose = ghostpriv.PurposeAction
		in.Version = ghostpriv.PolicyActionVersion
		if err := v.VerifyReveal(in, field()); err == nil {
			t.Error("the statement checker's proof was accepted as a policy action")
		}
		for _, version := range []uint16{0, 2, 0xffff} {
			in := clone()
			in.Version = version
			err := v.VerifyReveal(in, field())
			rejected(t, "version "+strconv.Itoa(int(version)), err, ghostpriv.ErrStatementUnsupported)
			rejected(t, "version "+strconv.Itoa(int(version)), err, ghostpriv.ErrProofStatement)
			if errors.Is(err, ghostpriv.ErrProofRejected) {
				t.Errorf("version %d reached the library: %v", version, err)
			}
		}
	})
}

// TestGhostVerifierKnownAnswer checks the linked proof verifier against a
// real proof of each commitment format: it accepts the proof for its own
// statement, followed by zeros or not, and rejects a changed proof, every
// changed statement field and chain parameter, and every data reveal.
func TestGhostVerifierKnownAnswer(t *testing.T) {
	for _, f := range knownAnswerFiles {
		t.Run(f.name, func(t *testing.T) { testGhostVerifierKnownAnswer(t, loadKnownAnswerFile(t, f.file)) })
	}
}

func testGhostVerifierKnownAnswer(t *testing.T, ka knownAnswer) {
	base := ka.inputs(t)
	// The example's chain: id 1234 and a genesis hash of 0x47 bytes.
	if base.ChainID != 1234 || base.Domain != common.BytesToHash(bytes.Repeat([]byte{0x47}, 32)) {
		t.Fatalf("fixture chain parameters %d, %x", base.ChainID, base.Domain)
	}
	if base.Rule != (common.Hash{}) || base.Out.IsZero() || base.Fee.IsZero() {
		t.Fatalf("fixture rule %x, out %v, fee %v", base.Rule, base.Out, base.Fee)
	}
	v := ghostpriv.DefaultVerifier()
	clone := func() *ghostpriv.VerifyInputs {
		in := *base
		in.Out = new(uint256.Int).Set(base.Out)
		in.Fee = new(uint256.Int).Set(base.Fee)
		return &in
	}
	proof := func() []byte { return common.CopyBytes(ka.proof) }
	rejected := func(t *testing.T, name string, err error, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}

	t.Run("valid proof accepted", func(t *testing.T) {
		if err := v.VerifyReveal(clone(), proof()); err != nil {
			t.Fatalf("the proof: %v", err)
		}
		if err := v.VerifyReveal(clone(), append(proof(), make([]byte, 4096)...)); err != nil {
			t.Fatalf("the proof followed by zeros: %v", err)
		}
		if err := ghostpriv.ActiveVerifier().VerifyReveal(clone(), proof()); err != nil {
			t.Fatalf("the active verifier: %v", err)
		}
	})

	t.Run("flipped proof byte rejected", func(t *testing.T) {
		n := len(ka.proof)
		for _, at := range []int{0, 1, n / 3, n / 2, 2 * n / 3, n - 40, n - 1} {
			p := proof()
			p[at] ^= 1
			rejected(t, "flipped byte", v.VerifyReveal(clone(), p), ghostpriv.ErrProofRejected)
		}
		padded := append(proof(), make([]byte, 64)...)
		padded[n+10] = 1
		rejected(t, "non-zero padding", v.VerifyReveal(clone(), padded), ghostpriv.ErrProofRejected)
		rejected(t, "truncated", v.VerifyReveal(clone(), proof()[:n-1]), ghostpriv.ErrProofRejected)
		rejected(t, "empty", v.VerifyReveal(clone(), nil), ghostpriv.ErrProofRejected)
	})

	t.Run("changed statement field rejected", func(t *testing.T) {
		for name, change := range map[string]func(in *ghostpriv.VerifyInputs){
			"chain id":  func(in *ghostpriv.VerifyInputs) { in.ChainID++ },
			"domain":    func(in *ghostpriv.VerifyInputs) { in.Domain[31] ^= 1 },
			"root":      func(in *ghostpriv.VerifyInputs) { in.Root[0] ^= 1 },
			"marker":    func(in *ghostpriv.VerifyInputs) { in.Marker[31] ^= 1 },
			"remainder": func(in *ghostpriv.VerifyInputs) { in.Remainder[7] ^= 1 },
			"note":      func(in *ghostpriv.VerifyInputs) { in.Note[ghostpriv.RevealNoteSize-1] ^= 1 },
			"recipient": func(in *ghostpriv.VerifyInputs) { in.Recipient[19] ^= 1 },
			"out":       func(in *ghostpriv.VerifyInputs) { in.Out.AddUint64(in.Out, 1) },
			"fee":       func(in *ghostpriv.VerifyInputs) { in.Fee.SubUint64(in.Fee, 1) },
			"rule":      func(in *ghostpriv.VerifyInputs) { in.Rule[31] = 1 },
			"out range": func(in *ghostpriv.VerifyInputs) { in.Out.Lsh(uint256.NewInt(1), 96) },
		} {
			in := clone()
			change(in)
			rejected(t, name, v.VerifyReveal(in, proof()), ghostpriv.ErrProofRejected)
		}
		in := clone()
		in.Purpose = ghostpriv.PurposeRevoke
		rejected(t, "revoke purpose", v.VerifyReveal(in, proof()), ghostpriv.ErrProofStatement)
		rejected(t, "no inputs", v.VerifyReveal(nil, proof()), ghostpriv.ErrProofStatement)
	})

	t.Run("data reveal rejected", func(t *testing.T) {
		for _, purpose := range []byte{ghostpriv.PurposeReveal, ghostpriv.PurposeRevoke} {
			in := clone()
			in.Kind = ghosttree.Data
			in.Purpose = purpose
			rejected(t, "data reveal", v.VerifyReveal(in, proof()), errDefaultDataVerifier)
		}
	})

	// The linked library verifies the ordinary reveal of version 1 and 2
	// and the policy reveal of version 1. Any other version is refused
	// before it is called, as is a version 1 note longer than its 156 bytes.
	// The version 1 proof, given as a version 2 ordinary reveal or as a
	// policy reveal, reaches the library and is rejected.
	t.Run("other versions refused, other statements rejected", func(t *testing.T) {
		for _, verifier := range []ghostpriv.Verifier{v, ghostpriv.ActiveVerifier()} {
			for _, version := range []uint16{0, 3, 0xffff} {
				in := clone()
				in.Version = version
				err := verifier.VerifyReveal(in, proof())
				rejected(t, "ordinary reveal of another version", err, ghostpriv.ErrStatementUnsupported)
				rejected(t, "ordinary reveal of another version", err, ghostpriv.ErrProofStatement)
			}
			in := clone()
			in.Version = ghostpriv.RevealVersion
			rejected(t, "version 1 proof as version 2", verifier.VerifyReveal(in, proof()), ghostpriv.ErrProofRejected)
			in = clone()
			in.Purpose = ghostpriv.PurposePolicySpend
			rejected(t, "version 1 proof as a policy reveal", verifier.VerifyReveal(in, proof()), ghostpriv.ErrProofRejected)
			in = clone()
			in.Purpose = ghostpriv.PurposePolicySpend
			in.Version = 2
			err := verifier.VerifyReveal(in, proof())
			rejected(t, "policy reveal version 2", err, ghostpriv.ErrStatementUnsupported)
			rejected(t, "policy reveal version 2", err, ghostpriv.ErrProofStatement)

			in = clone()
			in.Note[ghostpriv.RevealNoteSize] = 1
			err = verifier.VerifyReveal(in, proof())
			rejected(t, "version 1 note past 156 bytes", err, ghostpriv.ErrProofStatement)
			if errors.Is(err, ghostpriv.ErrProofRejected) {
				t.Errorf("version 1 note past 156 bytes reached the verifier: %v", err)
			}
		}
	})
}
