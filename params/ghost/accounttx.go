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

package ghost

// The gas constants of the account transaction, type 0x52 (spec 09,
// section 8; docs/account-transactions.md). They are consensus constants.
const (
	// AccountTxSigByteGas is the gas of each byte of the scheme ID, the
	// public key and the signature.
	AccountTxSigByteGas uint64 = 16

	// AccountTxGasPerMs is the gas charged per millisecond of the slowest
	// measured signature verification.
	AccountTxGasPerMs = 10_000

	// AccountTxVerifyGasMLDSA44 is VERIFY_GAS of scheme 0x0001, ML-DSA-44:
	// ceil(t_ms * AccountTxGasPerMs) for the slowest of the measured
	// verifications, rounded up to a multiple of 1,000. The measurement is
	// recorded in docs/account-transactions.md.
	AccountTxVerifyGasMLDSA44 uint64 = 3_000

	// AccountTxVerifyGasSLHDSA is VERIFY_GAS of scheme 0x0002,
	// SLH-DSA-SHAKE-128s, measured by the same rule.
	AccountTxVerifyGasSLHDSA uint64 = 12_000
)

// The bounds on the signature checks of account transactions in the pool and
// on the wire (spec 09, sections 8.3 and 8.4). They are node settings, not
// consensus constants. Each is set from the measurement recorded in
// docs/account-transactions.md, taking the slowest verification of the
// slower scheme, SLH-DSA-SHAKE-128s, as the cost of every one, and none is
// zero.
const (
	// SigVerifyWorkers is the number of workers that verify the signatures of
	// pool transactions. No more signatures are verified at once.
	SigVerifyWorkers = 4

	// SigVerifyQueue is the number of signature checks the workers take at
	// once, waiting or running. Three slots in four are for transactions from
	// peers, one in four for transactions from local RPC.
	SigVerifyQueue = 256

	// SigFailureCacheSize is the number of recent signature failures kept, so
	// that the same failing transaction is not verified twice.
	SigFailureCacheSize = 4096

	// SigPeerBudget is the number of account transactions a peer may have
	// verified per second, and announce for fetching.
	SigPeerBudget = 50

	// SigRPCConnBudget is the number of account transactions one RPC
	// connection may submit per second.
	SigRPCConnBudget = 80

	// SigRPCBudget is the number of account transactions all RPC connections
	// together may submit per second.
	SigRPCBudget = 800
)

// AccountTxVerifyGas returns VERIFY_GAS of a scheme, zero for a scheme whose
// verification gas is not set. A transaction of a scheme with zero
// verification gas is refused.
func AccountTxVerifyGas(scheme uint16) uint64 {
	switch scheme {
	case 0x0001:
		return AccountTxVerifyGasMLDSA44
	case 0x0002:
		return AccountTxVerifyGasSLHDSA
	}
	return 0
}
