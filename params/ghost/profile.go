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

// Package ghost holds the checks that keep a chain configuration within what
// the Ghost node runs.
package ghost

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/params/types/ctypes"
)

// ErrNotGhostProfile is returned for a chain configuration that switches on a
// feature the Ghost node turns off.
var ErrNotGhostProfile = errors.New("chain configuration switches on features this node turns off")

// CheckProfile returns an error naming every feature of the configuration that
// the Ghost node turns off:
//
//   - the proof-of-stake transition (a terminal total difficulty);
//   - Ethereum Classic's rules: ECBP-1100 artificial finality (MESS), the
//     ECIP-1017 reward schedule, the ECIP-1010 bomb delay and ECIP-1099
//     (Etchash);
//   - withdrawals (EIP-4895), blob transactions (EIP-4844), the BLOBBASEFEE
//     opcode (EIP-7516) and the beacon block root contract (EIP-4788);
//   - PREVRANDAO (EIP-4399): on Ghost, DIFFICULTY returns the block's
//     difficulty, as before the Merge.
//
// The code for these features stays, as in upstream, but no chain the node
// runs may switch them on.
func CheckProfile(c ctypes.ChainConfigurator) error {
	var off []string
	set := func(transitions ...*uint64) bool {
		for _, t := range transitions {
			if t != nil {
				return true
			}
		}
		return false
	}
	if c.GetEthashTerminalTotalDifficulty() != nil || c.GetEthashTerminalTotalDifficultyPassed() {
		off = append(off, "the proof-of-stake transition (terminalTotalDifficulty)")
	}
	if set(c.GetECBP1100Transition()) {
		off = append(off, "ECBP-1100 artificial finality")
	}
	if set(c.GetEthashECIP1017Transition()) {
		off = append(off, "the ECIP-1017 reward schedule")
	}
	if set(c.GetEthashECIP1010PauseTransition()) {
		off = append(off, "the ECIP-1010 difficulty bomb delay")
	}
	if set(c.GetEthashECIP1099Transition()) {
		off = append(off, "ECIP-1099 (Etchash)")
	}
	if set(c.GetEIP4895Transition(), c.GetEIP4895TransitionTime()) {
		off = append(off, "withdrawals (EIP-4895)")
	}
	if set(c.GetEIP4844Transition(), c.GetEIP4844TransitionTime()) {
		off = append(off, "blob transactions (EIP-4844)")
	}
	if set(c.GetEIP7516Transition(), c.GetEIP7516TransitionTime()) {
		off = append(off, "the BLOBBASEFEE opcode (EIP-7516)")
	}
	if set(c.GetEIP4788Transition(), c.GetEIP4788TransitionTime()) {
		off = append(off, "the beacon block root contract (EIP-4788)")
	}
	if set(c.GetEIP4399Transition()) {
		off = append(off, "PREVRANDAO (EIP-4399)")
	}
	if len(off) > 0 {
		return fmt.Errorf("%w: %s", ErrNotGhostProfile, strings.Join(off, ", "))
	}
	return nil
}
