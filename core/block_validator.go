// Copyright 2015 The go-ethereum Authors
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

package core

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/trie"
)

// ErrPolicyCoinbase is returned for a block whose coinbase is a registered
// frozen policy in the state after the block.
var ErrPolicyCoinbase = errors.New("coinbase is a frozen policy")

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config ctypes.ChainConfigurator // Chain configuration options
	bc     *BlockChain              // Canonical block chain
	engine consensus.Engine         // Consensus engine used for validating
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(config ctypes.ChainConfigurator, blockchain *BlockChain, engine consensus.Engine) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// Check whether the block is already imported.
	if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}

	// Header validity is known at this point. Here we verify that uncles, transactions
	// and withdrawals given in the block body match the header.
	header := block.Header()
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch (header value %x, calculated %x)", header.UncleHash, hash)
	}
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch (header value %x, calculated %x)", header.TxHash, hash)
	}

	// Withdrawals are present after the Shanghai fork.
	if header.WithdrawalsHash != nil {
		// Withdrawals list must be present in body after Shanghai.
		if block.Withdrawals() == nil {
			return errors.New("missing withdrawals in block body")
		}
		if hash := types.DeriveSha(block.Withdrawals(), trie.NewStackTrie(nil)); hash != *header.WithdrawalsHash {
			return fmt.Errorf("withdrawals root hash mismatch (header value %x, calculated %x)", *header.WithdrawalsHash, hash)
		}
	} else if block.Withdrawals() != nil {
		// Withdrawals are not allowed prior to Shanghai fork
		return errors.New("withdrawals present in block body")
	}

	// Blob transactions may be present after the Cancun fork.
	var blobs int
	for i, tx := range block.Transactions() {
		// Count the number of blobs to validate against the header's blobGasUsed
		blobs += len(tx.BlobHashes())

		// If the tx is a blob tx, it must NOT have a sidecar attached to be valid in a block.
		if tx.BlobTxSidecar() != nil {
			return fmt.Errorf("unexpected blob sidecar in transaction at index %d", i)
		}

		// The individual checks for blob validity (version-check + not empty)
		// happens in StateTransition.
	}

	// Check blob gas usage.
	if header.BlobGasUsed != nil {
		if want := *header.BlobGasUsed / vars.BlobTxBlobGasPerBlob; uint64(blobs) != want { // div because the header is surely good vs the body might be bloated
			return fmt.Errorf("blob gas used mismatch (header %v, calculated %v)", *header.BlobGasUsed, blobs*vars.BlobTxBlobGasPerBlob)
		}
	} else {
		if blobs > 0 {
			return errors.New("data blobs present in block body")
		}
	}

	// Ancestor block must be known.
	if !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	return nil
}

// ValidateState validates the various changes that happen after a state transition,
// such as amount of used gas, the receipt roots and the state root itself.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	header := block.Header()
	if block.GasUsed() != usedGas {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, Rn]]))
	receiptSha := types.DeriveSha(receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// A frozen policy never holds a balance, so it cannot be paid as the
	// coinbase. The check reads the state after execution, so it also
	// catches a policy created in this block.
	if ghost.IsRegisteredPolicy(statedb, header.Coinbase) {
		return fmt.Errorf("%w: %v", ErrPolicyCoinbase, header.Coinbase.Hex())
	}
	// Validate the tree roots of a header that carries them against the trees
	// in the state after execution.
	if err := validateTreeRoots(header, statedb); err != nil {
		return err
	}
	// Validate the state root against the received state root and throw
	if root := statedb.IntermediateRoot(v.config.IsEnabled(v.config.GetEIP161dTransition, header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x) dberr: %w", header.Root, root, statedb.Error())
	}
	return nil
}

// validateTreeRoots checks the Ghost fields of a header that carries any of
// them against those of the executed state: the coin and data tree roots
// and the data marker root, and, when the header carries any lookup field,
// the coin and data lookup roots, the coin marker root and the block lookup
// digest of decision 0004. A header without roots is left to the consensus
// engine, which rejects it on Ghost chains, as is one with the roots but
// without the lookup fields.
func validateTreeRoots(header *types.Header, statedb *state.StateDB) error {
	type field struct {
		name   string
		remote *common.Hash
		local  func(f *ghosttree.HeaderFields) common.Hash
		lookup bool // checked only when the header carries a lookup field
	}
	fields := []field{
		{"coinTreeRoot", header.CoinTreeRoot, func(f *ghosttree.HeaderFields) common.Hash { return f.CoinTreeRoot }, false},
		{"dataTreeRoot", header.DataTreeRoot, func(f *ghosttree.HeaderFields) common.Hash { return f.DataTreeRoot }, false},
		{"dataMarkerRoot", header.DataMarkerRoot, func(f *ghosttree.HeaderFields) common.Hash { return f.DataMarkerRoot }, false},
		{"coinLookupRoot", header.CoinLookupRoot, func(f *ghosttree.HeaderFields) common.Hash { return f.CoinLookupRoot }, true},
		{"dataLookupRoot", header.DataLookupRoot, func(f *ghosttree.HeaderFields) common.Hash { return f.DataLookupRoot }, true},
		{"coinMarkerRoot", header.CoinMarkerRoot, func(f *ghosttree.HeaderFields) common.Hash { return f.CoinMarkerRoot }, true},
		{"lookupDigest", header.LookupDigest, func(f *ghosttree.HeaderFields) common.Hash { return f.LookupDigest }, true},
	}
	var carries, lookups bool
	for _, f := range fields {
		if f.remote != nil {
			carries = true
			lookups = lookups || f.lookup
		}
	}
	if !carries {
		return nil
	}
	local, err := ghosttree.ReadHeaderFields(statedb, header.Number.Uint64())
	if err != nil {
		return fmt.Errorf("invalid tree roots: %w", err)
	}
	for _, f := range fields {
		if f.lookup && !lookups {
			continue
		}
		want := f.local(local)
		if f.remote == nil {
			return fmt.Errorf("invalid %s (remote: missing local: %x)", f.name, want)
		}
		if *f.remote != want {
			return fmt.Errorf("invalid %s (remote: %x local: %x)", f.name, *f.remote, want)
		}
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/vars.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < vars.MinGasLimit {
		desiredLimit = vars.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}
