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

// Proof-carrying account transactions (docs/account-transactions.md). An
// account transaction (type 0x52) to a frozen policy created before the next
// block whose calldata ends with the statement checker's input, a
// KNOW_PREIMAGE_v1 statement and its proof, is too large for the account
// transaction cap of AccountTxMaxBytes. The pool takes it in a size class of
// its own, verifies its proof once, within the budgets below, and holds no
// more than ProofTxMaxHeld of them.
const (
	// AccountTxMaxBytes is TX_MAX_BYTES, the cap of every other account
	// transaction (spec 09, section 8.3): the transaction pool's 128 KiB.
	AccountTxMaxBytes = 131_072

	// ProofTxMaxBytes is the largest envelope of a proof-carrying
	// transaction. Above it a transaction is dropped unread and, from a
	// peer, counts as one failed check.
	ProofTxMaxBytes = 1_048_576

	// ProofTxMaxHeld is the most proof-carrying transactions the pool
	// holds, at most one of them per sender account.
	ProofTxMaxHeld = 4

	// ProofPeerBudget is the number of proof-carrying transactions a peer
	// may deliver per chain head. The budget is refilled when the head moves.
	ProofPeerBudget = 4

	// ProofFailLimit is the number of failed proof checks, oversized
	// deliveries included, of one peer at one head at which the peer is
	// disconnected.
	ProofFailLimit = 3

	// ProofCheckSlots is the number of proof verifications that run at
	// once: one is open to peers and one is kept for local RPC submissions.
	ProofCheckSlots = 2

	// ProofChecksPerHead is the number of proof verifications the node runs
	// per chain head. Past it, proof-carrying transactions are dropped
	// unverified with a busy error, which is no fault of the peer.
	ProofChecksPerHead = 16

	// ProofRejectedMemory is the number of hashes of transactions whose
	// proof failed that the pool remembers and refuses again without a
	// check; the oldest is forgotten first.
	ProofRejectedMemory = 4096

	// PreimageVerifyGas is PREIMAGE_VERIFY_GAS, the gas of a call to the
	// statement checker on top of StatementCheckerWordGas per 32-byte word
	// of its input (spec 10, section 9.3).
	PreimageVerifyGas uint64 = 110_000

	// StatementCheckerWordGas is the gas of the statement checker per
	// 32-byte word of its input.
	StatementCheckerWordGas uint64 = 3
)
