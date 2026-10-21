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

package tests

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
)

// removedPrecompileFixtures are the execution fixture families that call a
// precompile Ghost removes (0x01 ECRECOVER, 0x06 to 0x08 BN254 and 0x0a point
// evaluation; docs/ghost-evm-profile.md). On Ghost every call to those
// addresses fails and uses all its gas, so the fixtures' expected results
// cannot hold. They are skipped, not rewritten; each line gives the reason.
var removedPrecompileFixtures = []string{
	`(^|/)stPreCompiledContracts/`,  // calls ECRECOVER and the BN254 precompiles
	`(^|/)stPreCompiledContracts2/`, // calls ECRECOVER and the BN254 precompiles
	`(^|/)stZeroKnowledge/`,         // calls the BN254 precompiles
	`(^|/)stZeroKnowledge2/`,        // calls the BN254 precompiles
	`(?i)ecrecover`,                 // calls ECRECOVER (0x01)
	`(?i)ecadd`,                     // calls BN254 ADD (0x06)
	`(?i)ecmul`,                     // calls BN254 MUL (0x07)
	`(?i)ecpairing`,                 // calls BN254 PAIRING (0x08)
	`(?i)point_?evaluation`,         // calls POINT EVALUATION (0x0a)
}

// skipRemovedPrecompiles skips, by name, every fixture family that calls a
// removed precompile.
func skipRemovedPrecompiles(tm *testMatcher) {
	for _, pattern := range removedPrecompileFixtures {
		tm.skipLoad(pattern)
	}
}

// removedPrecompileSkipReason is the reason given for a fixture skipped
// because one of its calls reached a removed precompile.
const removedPrecompileSkipReason = "calls a precompile Ghost removes (docs/ghost-evm-profile.md)"

// removedPrecompileTracer records whether a call frame ended with the error of
// a removed precompile, that is whether the execution reached one.
type removedPrecompileTracer struct {
	reached bool
}

func (r *removedPrecompileTracer) note(err error) {
	if errors.Is(err, vm.ErrPrecompileRemoved) {
		r.reached = true
	}
}

func (r *removedPrecompileTracer) CaptureTxStart(gasLimit uint64) {
}

func (r *removedPrecompileTracer) CaptureTxEnd(restGas uint64) {
}

func (r *removedPrecompileTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
}

func (r *removedPrecompileTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	r.note(err)
}

func (r *removedPrecompileTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}

func (r *removedPrecompileTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	r.note(err)
}

func (r *removedPrecompileTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
}

func (r *removedPrecompileTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
}

// skipIfReachesRemovedPrecompile runs a fixture that failed once more with a
// tracer, and skips it when the execution reached a removed precompile. Such a
// fixture expects the precompile to work, so its results cannot hold on
// Ghost, whatever its name; a fixture that fails without reaching one is not
// skipped.
func skipIfReachesRemovedPrecompile(t *testing.T, run func(tracer vm.EVMLogger)) {
	t.Helper()
	tracer := new(removedPrecompileTracer)
	run(tracer)
	if tracer.reached {
		t.Skip(removedPrecompileSkipReason)
	}
}
