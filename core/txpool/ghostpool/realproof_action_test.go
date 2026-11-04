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

//go:build cgo && ghostproofs && (linux || darwin)

package ghostpool

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/types"
)

var realActionFixture = filepath.Join("testdata", "pool_action.bin.gz")

const realActionRegenerate = `regenerate the fixture: GHOST_REAL_PROOF_REQUEST=/tmp/pool_action.req CGO_ENABLED=1 go test -tags ghostproofs -run '^TestRealProofPolicyActionAdmission$' ./core/txpool/ghostpool/, then cargo run --release --locked --manifest-path ghostverifier/Cargo.toml --example actionfixture -- /tmp/pool_action.req pool_action.bin and gzip -n -9 pool_action.bin into core/txpool/ghostpool/testdata/ (see ghostverifier/examples/actionfixture.rs)`

// actionRequest is the chain parameters and the KNOW_ACTION_v1 statement of
// in, in the layout of ghost_action.h.
func actionRequest(in *ghostpriv.VerifyInputs) []byte {
	b := binary.BigEndian.AppendUint64(nil, in.ChainID)
	b = binary.BigEndian.AppendUint16(b, ghostpriv.PolicyActionVersion)
	b = append(b, in.Domain[:]...)
	b = append(b, in.Policy[:]...)
	b = append(b, in.Marker[:]...)
	b = binary.BigEndian.AppendUint64(b, in.ActionNonce)
	b = append(b, in.ActionTag[:]...)
	b = append(b, in.ActionSalt[:]...)
	e, d := in.ExpectedRemaining.Bytes32(), in.Debit.Bytes32()
	b = append(b, e[:]...)
	b = append(b, d[:]...)
	b = binary.BigEndian.AppendUint64(b, in.Expiry)
	return append(b, in.CalldataHash[:]...)
}

// TestRealProofPolicyActionAdmission checks that the pool, with the default
// linked verifier active, admits a 0x54 action on an open slot whose proof
// is the pinned prover's KNOW_ACTION_v1 proof, and refuses and does not hold
// the same action with a flipped proof byte.
func TestRealProofPolicyActionAdmission(t *testing.T) {
	pf := newPolicyFixture(t, 1, 0, nil)
	r := pf.slots[0]
	a := pf.action(r, 1000, 0x5a)
	request := actionRequest(a.VerifyInputs(pf.chainID, pf.genesis.Hash(), pf.slotNow(r)))
	if out := os.Getenv("GHOST_REAL_PROOF_REQUEST"); out != "" {
		root := testActionRoot(r.Marker)
		if err := os.WriteFile(out, append(request, root[:]...), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote the action proof request to %s", out)
	}
	f, err := os.Open(realActionFixture)
	if err != nil {
		t.Fatalf("%v; %s", err, realActionRegenerate)
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
	if len(raw) <= len(request) || !bytes.Equal(raw[:len(request)], request) {
		t.Fatalf("the fixture is not for this action; %s", realActionRegenerate)
	}
	a.Proof = raw[len(request):]

	t.Cleanup(ghostpriv.SetVerifier(nil))
	if v := ghostpriv.ActiveVerifier(); v != ghostpriv.DefaultVerifier() {
		t.Fatalf("active verifier %T, want the default", v)
	}
	bad := *a
	bad.Proof = common.CopyBytes(a.Proof)
	bad.Proof[len(bad.Proof)/2] ^= 1
	badTx, tx := pf.actionTx(&bad), pf.actionTx(a)

	p := pf.newPool()
	if err := p.Add([]*types.Transaction{badTx}, true, true)[0]; !errors.Is(err, ghostpriv.ErrActionProof) {
		t.Fatalf("action with a flipped proof byte: %v, want %v", err, ghostpriv.ErrActionProof)
	}
	if p.Has(badTx.Hash()) {
		t.Fatal("the pool holds the refused action")
	}
	if err := p.Add([]*types.Transaction{tx}, true, true)[0]; err != nil {
		t.Fatalf("real-proof action refused: %v", err)
	}
	if !p.Has(tx.Hash()) {
		t.Fatal("the pool does not hold the admitted action")
	}
}
