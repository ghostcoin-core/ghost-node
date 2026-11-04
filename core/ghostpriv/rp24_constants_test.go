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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The verification charges of spec 10, section 10.3, as the node's gas
// constants hold them: each class's gas less its bytes, its base cost and
// its other fixed charges. ACTION_STATE_GAS is the slot debit with its
// result log, inside the fixed action charge.
const (
	byteGas        = 16
	baseTxGas      = 21_000
	actionStateGas = 15_000

	verifyGasOrd    = ghostpriv.GasPriv - byteGas*types.GhostRevealEnvelopeSize - baseTxGas
	verifyGasPolicy = ghostpriv.GasPolicy - byteGas*types.GhostPolicyRevealEnvelopeSize - baseTxGas - ghostpriv.SlotOpenGas
	verifyGasAction = ghostpriv.GasAction - byteGas*types.GhostPolicyActionEnvelopeSize - baseTxGas - ghostpriv.ActionCallGas - actionStateGas
)

// TestRP24Constants pins the node's gas constants (RP-24 of spec 10) to the
// values the ghost repository's checker of spec 10 computes. The file is the
// checker's output; regenerate it with
//
//	python3 scripts/check_private_reveal_policies.py --constants > core/ghostpriv/testdata/rp24_constants.json
//
// run in the ghost repository at the spec revision the node implements.
func TestRP24Constants(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "rp24_constants.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]uint64
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	have := map[string]uint64{
		"G_PRIV":                ghostpriv.GasPriv,
		"G_POLICY":              ghostpriv.GasPolicy,
		"G_ACTION":              ghostpriv.GasAction,
		"G_DATA":                types.GhostDataRevealGas,
		"VERIFY_GAS_ORD":        verifyGasOrd,
		"VERIFY_GAS_POLICY":     verifyGasPolicy,
		"VERIFY_GAS_ACTION":     verifyGasAction,
		"VERIFY_GAS_DATA":       types.GhostDataRevealGas - byteGas*types.GhostDataRevealEnvelopeSize - baseTxGas,
		"PREIMAGE_VERIFY_GAS":   ghost.PreimageVerifyGas,
		"SLOT_OPEN_GAS":         ghostpriv.SlotOpenGas,
		"ACTION_CALL_GAS":       ghostpriv.ActionCallGas,
		"ACTION_STATE_GAS":      actionStateGas,
		"REGISTRY_GAS":          ghost.PolicyRegistryGas,
		"ORD_ENVELOPE_BYTES":    types.GhostRevealEnvelopeSize,
		"POLICY_ENVELOPE_BYTES": types.GhostPolicyRevealEnvelopeSize,
		"ACTION_ENVELOPE_BYTES": types.GhostPolicyActionEnvelopeSize,
		"ACTION_PROOF_BYTES":    ghostpriv.ActionProofSize,
		"NOTE_BYTES":            ghostpriv.NoteSize,
		"GAS_PER_MS":            gasPerMs,
	}
	// The proofs crate's trace width bounds the prover, not the node.
	delete(want, "MAX_TRACE_WIDTH")
	for name, w := range want {
		h, ok := have[name]
		if !ok {
			t.Errorf("%s = %d: the node has no constant for it", name, w)
			continue
		}
		if h != w {
			t.Errorf("%s = %d, the checker computes %d", name, h, w)
		}
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: not in the checker's output", name)
		}
	}
}

// gasPerMs is GAS_PER_MS of spec 07, section 4.
const gasPerMs = 10_000
