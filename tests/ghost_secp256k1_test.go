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

// secp256k1TxFixtures are the execution fixture directories whose
// transactions are of a type Ghost refuses: legacy (0x00), EIP-2930 (0x01),
// EIP-1559 (0x02) or EIP-4844 (0x03), signed with secp256k1 (spec 09,
// section 12, QS-1). No signer recovers their sender, so their expected
// results cannot hold. Each pattern matches the name of a fixture root, which
// the walk then skips whole; the fixtures are skipped, not rewritten, and each
// line gives the reason.
var secp256k1TxFixtures = []string{
	`(^|/)GeneralStateTests/`,         // every family signs its transaction as type 0x00 to 0x03 with secp256k1
	`(^|/)EIPTests/StateTests/`,       // the EIP state tests sign their transactions the same way
	`(^|/)evm-benchmarks/benchmarks/`, // the benchmark state tests sign their transactions the same way
	`(^|/)BlockchainTests/`,           // every family's blocks hold type 0x00 to 0x03 transactions
	`(^|/)TransactionTests/`,          // checks the secp256k1 sender of type 0x00 to 0x03 envelopes
	`(^|/)fixtures/state_tests/`,      // execution-spec-tests: type 0x00 to 0x03 transactions
	`(^|/)fixtures/blockchain_tests/`, // execution-spec-tests: blocks of type 0x00 to 0x03 transactions
}

// skipSecp256k1TxFixtures skips, by directory name, every fixture root whose
// transactions are of a refused type.
func skipSecp256k1TxFixtures(tm *testMatcher) {
	for _, pattern := range secp256k1TxFixtures {
		tm.skipLoad(pattern)
	}
}
