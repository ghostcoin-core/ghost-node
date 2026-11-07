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

package randomx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ghostrules"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/ghostmmr"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

var (
	errInvalidTimestamp  = errors.New("invalid timestamp")
	errInvalidDifficulty = errors.New("invalid difficulty")
	errUnknownGenesis    = errors.New("genesis header unavailable")
	errUnsupportedField  = errors.New("header field not used by this chain")
	errUnclesNotAllowed  = errors.New("uncles not allowed")
	errInvalidUncleHash  = errors.New("uncle hash not empty")
	errInvalidMixDigest  = errors.New("mix digest not zero")
	errInvalidPoW        = errors.New("invalid proof-of-work")
	errNoWithdrawals     = errors.New("withdrawals not supported")
	errMissingTreeRoot   = errors.New("header has no tree root")
	errMissingBaseFee    = errors.New("header has no base fee")
	errGasLimitAboveMax  = errors.New("gas limit above the consensus maximum")

	// ErrHeaderMmrRoot is a header whose HeaderMmrRoot is missing or is not
	// the root of the header MMR over the earlier blocks of its chain.
	ErrHeaderMmrRoot = errors.New("header MMR root missing or wrong")

	// ErrWorkOverflow is a block whose chain's total difficulty, its own
	// included, would reach 2^128, the reason work-overflow of decision 0005.
	ErrWorkOverflow = fmt.Errorf("invalid block: %w", ghostmmr.ErrWorkOverflow)
)

// HeaderMMRReader is a chain that keeps the header MMR: core.BlockChain and
// core.HeaderChain. HeaderMMR returns the state the header with the given
// hash and number commits to, the MMR over blocks 0 to number-1 of its own
// chain, which the caller must not change. For any other chain the engine
// computes the state from the headers.
type HeaderMMRReader interface {
	HeaderMMR(hash common.Hash, number uint64) (ghostmmr.State, error)
}

// headerMMRLeaf returns the leaf of a block: its header hash and difficulty.
func headerMMRLeaf(header *types.Header) (ghostmmr.Entry, error) {
	work, err := ghostmmr.WorkFromBig(header.Difficulty)
	if err != nil {
		return ghostmmr.Entry{}, ErrWorkOverflow
	}
	return ghostmmr.Leaf(header.Hash(), work), nil
}

// childMMR returns the header MMR state a child of parent commits to: the
// parent's state with the parent's leaf appended.
func childMMR(parentState ghostmmr.State, parent *types.Header) (ghostmmr.State, error) {
	leaf, err := headerMMRLeaf(parent)
	if err != nil {
		return ghostmmr.State{}, err
	}
	state, _, err := parentState.Append(leaf)
	if errors.Is(err, ghostmmr.ErrWorkOverflow) {
		return ghostmmr.State{}, ErrWorkOverflow
	}
	return state, err
}

// headerMMROf returns the header MMR state the given header commits to. It
// asks the chain when it keeps the MMR, and the engine's memo of states; a
// header neither knows is walked down through lookup, parent by parent, to
// one they know or to the genesis, which commits to the empty MMR.
func (r *RandomX) headerMMROf(chain consensus.ChainHeaderReader, lookup headerLookup, header *types.Header) (ghostmmr.State, error) {
	reader, _ := chain.(HeaderMMRReader)
	known := func(h *types.Header) (ghostmmr.State, bool, error) {
		n := h.Number.Uint64()
		if n == 0 {
			return ghostmmr.State{}, true, nil
		}
		hash := h.Hash()
		if s, ok := r.mmrs.Get(hash); ok {
			return s, true, nil
		}
		if reader != nil && chain.GetHeader(hash, n) != nil {
			// A chain reader can answer for headers its store has not
			// imported, such as a miner's headers built on it but not yet
			// inserted. Its store does not know their state, so such a
			// header is walked down from its parent like any other.
			if s, err := reader.HeaderMMR(hash, n); err == nil {
				return s, true, nil
			}
		}
		return ghostmmr.State{}, false, nil
	}
	var pending []*types.Header // headers without a known state, newest first
	state, ok, err := known(header)
	for h := header; !ok; {
		if err != nil {
			return ghostmmr.State{}, err
		}
		pending = append(pending, h)
		n := h.Number.Uint64()
		parent := lookup(h.ParentHash, n-1)
		if parent == nil {
			return ghostmmr.State{}, consensus.ErrUnknownAncestor
		}
		state, ok, err = known(parent)
		h = parent
	}
	if err != nil {
		return ghostmmr.State{}, err
	}
	for k := len(pending) - 1; k >= 0; k-- {
		parent := lookup(pending[k].ParentHash, pending[k].Number.Uint64()-1)
		if state, err = childMMR(state, parent); err != nil {
			return ghostmmr.State{}, err
		}
		r.mmrs.Add(pending[k].Hash(), state)
	}
	return state, nil
}

// expectedHeaderMMR returns the header MMR state a child of parent commits
// to.
func (r *RandomX) expectedHeaderMMR(chain consensus.ChainHeaderReader, lookup headerLookup, parent *types.Header) (ghostmmr.State, error) {
	parentState, err := r.headerMMROf(chain, lookup, parent)
	if err != nil {
		return ghostmmr.State{}, err
	}
	return childMMR(parentState, parent)
}

// checkHeaderMMR checks the header MMR root of a header against the state its
// chain gives, and that the chain's total difficulty with the header's own
// stays below 2^128. A header without the Ghost layout carries no root.
func checkHeaderMMR(header *types.Header, expected ghostmmr.State) error {
	total, err := expected.TotalWork()
	if err != nil {
		return ErrWorkOverflow
	}
	own, err := ghostmmr.WorkFromBig(header.Difficulty)
	if err != nil {
		return ErrWorkOverflow
	}
	if _, ok := total.Add(own); !ok {
		return ErrWorkOverflow
	}
	if header.CoinTreeRoot == nil {
		if header.HeaderMmrRoot != nil {
			return fmt.Errorf("%w: header MMR root without tree roots", errUnsupportedField)
		}
		return nil
	}
	if header.HeaderMmrRoot == nil {
		return fmt.Errorf("%w: header has none", ErrHeaderMmrRoot)
	}
	root, err := expected.Root()
	if err != nil {
		return err
	}
	if *header.HeaderMmrRoot != root {
		return fmt.Errorf("%w: have %x, want %x over %d blocks", ErrHeaderMmrRoot, *header.HeaderMmrRoot, root, expected.N)
	}
	return nil
}

// Author implements consensus.Engine, returning the header's coinbase.
func (r *RandomX) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader implements consensus.Engine.
func (r *RandomX) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	if number == 0 {
		return consensus.ErrUnknownAncestor
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	var key common.Hash
	if seal {
		var err error
		if key, err = r.keyOf(chainLookup(chain), header); err != nil {
			return err
		}
	}
	mmr, err := r.expectedHeaderMMR(chain, chainLookup(chain), parent)
	if err != nil {
		return err
	}
	r.mmrs.Add(header.Hash(), mmr)
	return r.verifyHeader(chain, header, parent, seal, key, mmr, uint64(r.now().Unix()))
}

// VerifyHeaders implements consensus.Engine. One sequential pass finds every
// header's parent and RandomX key, following parent hashes through the batch
// and the chain; the checks, the RandomX hash last, then run in parallel.
// Results come out in the order of the input.
func (r *RandomX) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))
	if len(headers) == 0 {
		return abort, results
	}
	var (
		now     = uint64(r.now().Unix())
		lookup  = batchLookup(chain, headers)
		parents = make([]*types.Header, len(headers))
		keys    = make([]common.Hash, len(headers))
		mmrs    = make([]ghostmmr.State, len(headers))
		errs    = make([]error, len(headers))
	)
	for i, header := range headers {
		number := header.Number.Uint64()
		if number == 0 {
			errs[i] = consensus.ErrUnknownAncestor
			continue
		}
		if parents[i] = lookup(header.ParentHash, number-1); parents[i] == nil {
			errs[i] = consensus.ErrUnknownAncestor
			continue
		}
		if seals[i] {
			if keys[i], errs[i] = r.keyOf(lookup, header); errs[i] != nil {
				continue
			}
		}
		// The header MMR state each header commits to, in order, so that a
		// header's parent in the batch is remembered when it is reached.
		if mmrs[i], errs[i] = r.expectedHeaderMMR(chain, lookup, parents[i]); errs[i] == nil {
			r.mmrs.Add(header.Hash(), mmrs[i])
		}
	}

	workers := min(runtime.GOMAXPROCS(0), len(headers))
	var (
		inputs = make(chan int)
		done   = make(chan int, workers)
	)
	for w := 0; w < workers; w++ {
		go func() {
			for i := range inputs {
				if errs[i] == nil {
					errs[i] = r.verifyHeader(chain, headers[i], parents[i], seals[i], keys[i], mmrs[i], now)
				}
				done <- i
			}
		}()
	}
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			feed    = inputs
		)
		for {
			select {
			case feed <- in:
				if in++; in == len(headers) {
					feed = nil
				}
			case i := <-done:
				for checked[i] = true; out < len(headers) && checked[out]; out++ {
					results <- errs[out]
				}
				if out == len(headers) {
					return
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, results
}

// VerifyUncles implements consensus.Engine: a block may not carry uncles.
func (r *RandomX) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errUnclesNotAllowed
	}
	return nil
}

// verifyHeader checks a header against its parent, cheapest checks first and
// the RandomX hash last. mmr is the header MMR state the header must commit
// to, its parent's with the parent's leaf appended. now is the local clock in
// seconds.
func (r *RandomX) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, seal bool, key common.Hash, mmr ghostmmr.State, now uint64) error {
	// Parent link.
	if header.Number == nil || header.Number.Cmp(new(big.Int).Add(parent.Number, common.Big1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	if header.ParentHash != parent.Hash() {
		return consensus.ErrUnknownAncestor
	}
	if uint64(len(header.Extra)) > vars.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), vars.MaximumExtraDataSize)
	}
	// Timestamp. Only the future-drift failure can clear with time.
	if err := r.params.CheckTimestamp(parent.Time, header.Time, now); err != nil {
		if errors.Is(err, ghostrules.ErrTimestampTooFarAhead) {
			return consensus.ErrFutureBlock
		}
		return fmt.Errorf("%w: %w", errInvalidTimestamp, err)
	}
	// Difficulty.
	expected, err := r.requiredDifficulty(chain, header.Time, parent)
	if err != nil {
		return err
	}
	if header.Difficulty == nil || header.Difficulty.Cmp(expected) != 0 {
		return fmt.Errorf("%w: have %v, want %v", errInvalidDifficulty, header.Difficulty, expected)
	}
	// Gas limit and base fee.
	if header.GasLimit > ghost.MaxBlockGasLimit {
		return fmt.Errorf("%w: have %v, max %v", errGasLimitAboveMax, header.GasLimit, ghost.MaxBlockGasLimit)
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	config := chain.Config()
	if !config.IsEnabled(config.GetEIP1559Transition, header.Number) {
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := eip1559.VerifyEIP1559Header(config, parent, header); err != nil {
		return err
	}
	// Fields of features the chain turns off.
	switch {
	case header.WithdrawalsHash != nil:
		return fmt.Errorf("%w: withdrawalsHash", errUnsupportedField)
	case header.BlobGasUsed != nil:
		return fmt.Errorf("%w: blobGasUsed", errUnsupportedField)
	case header.ExcessBlobGas != nil:
		return fmt.Errorf("%w: excessBlobGas", errUnsupportedField)
	case header.ParentBeaconRoot != nil:
		return fmt.Errorf("%w: parentBeaconRoot", errUnsupportedField)
	}
	// Both tree roots, in every header with a base fee; block validation
	// checks their values against the executed state, with the state root.
	if err := checkTreeRootFields(config.IsEnabled(config.GetEIP1559Transition, header.Number), header); err != nil {
		return err
	}
	// The header MMR root, which depends on the earlier headers only, so it
	// is checked here before any body is executed; and the total difficulty
	// below 2^128.
	if err := checkHeaderMMR(header, mmr); err != nil {
		return err
	}
	// Uncle hash and mix digest.
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// The RandomX hash.
	if seal {
		return r.verifySeal(header, key)
	}
	return nil
}

// checkTreeRootFields checks that a header carries both tree roots and the
// data marker root when its chain has EIP-1559 in force, and none of them
// otherwise. checkHeaderMMR checks the header MMR root that goes with them. The roots take the Ghost layout, which requires the base fee, so
// a chain without EIP-1559 (so far only developer mode) cannot carry them
// after its genesis.
func checkTreeRootFields(london bool, header *types.Header) error {
	switch {
	case !london && (header.CoinTreeRoot != nil || header.DataTreeRoot != nil || header.DataMarkerRoot != nil):
		return fmt.Errorf("%w: tree roots without a base fee", errUnsupportedField)
	case !london:
		return nil
	case header.CoinTreeRoot == nil:
		return fmt.Errorf("%w: coinTreeRoot", errMissingTreeRoot)
	case header.DataTreeRoot == nil:
		return fmt.Errorf("%w: dataTreeRoot", errMissingTreeRoot)
	case header.DataMarkerRoot == nil:
		return fmt.Errorf("%w: dataMarkerRoot", errMissingTreeRoot)
	}
	return nil
}

// verifySeal checks the header's RandomX hash under key against its
// difficulty.
func (r *RandomX) verifySeal(header *types.Header, key common.Hash) error {
	if header.Difficulty == nil || header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}
	hash, err := r.powHash(header, key)
	if err != nil {
		return err
	}
	if !ghostrules.SealValid(hash, header.Difficulty) {
		return errInvalidPoW
	}
	return nil
}

// powHash returns the header's RandomX hash under key.
func (r *RandomX) powHash(header *types.Header, key common.Hash) ([32]byte, error) {
	entry, err := r.caches.acquire(key)
	if err != nil {
		return [32]byte{}, err
	}
	defer r.caches.release(entry)
	return r.caches.hash(entry, sealInput(r.SealHash(header), header.Nonce.Uint64()))
}

// sealInput is the RandomX input of a header: its seal hash followed by the
// nonce as 8 big-endian bytes.
func sealInput(sealHash common.Hash, nonce uint64) []byte {
	input := make([]byte, common.HashLength+8)
	copy(input, sealHash[:])
	binary.BigEndian.PutUint64(input[common.HashLength:], nonce)
	return input
}

// Prepare implements consensus.Engine, setting the difficulty and clearing
// the seal fields.
func (r *RandomX) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	difficulty, err := r.requiredDifficulty(chain, header.Time, parent)
	if err != nil {
		return err
	}
	header.Difficulty = difficulty
	header.MixDigest = common.Hash{}
	header.Nonce = types.BlockNonce{}
	return nil
}

// Finalize implements consensus.Engine, paying the whole block reward to the
// coinbase. Nothing else is credited; uncles are never rewarded.
func (r *RandomX) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) {
	state.AddBalance(header.Coinbase, r.params.BlockReward(header.Number.Uint64()))
}

// FinalizeAndAssemble implements consensus.Engine, paying the block reward,
// setting the tree roots, the header MMR root and the state root and
// assembling the block.
func (r *RandomX) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	if len(withdrawals) > 0 {
		return nil, errNoWithdrawals
	}
	if len(uncles) > 0 {
		return nil, errUnclesNotAllowed
	}
	config := chain.Config()
	london := config.IsEnabled(config.GetEIP1559Transition, header.Number)
	if london && header.BaseFee == nil {
		return nil, errMissingBaseFee
	}
	r.Finalize(chain, header, state, txs, nil, nil)
	header.CoinTreeRoot, header.DataTreeRoot, header.DataMarkerRoot, header.HeaderMmrRoot = nil, nil, nil, nil
	if london {
		// The header MMR root over the earlier blocks: the parent's state
		// with the parent's leaf appended. It is set here with the tree
		// roots, not in Prepare, because the root needs the tree roots
		// beside it to be encoded.
		number := header.Number.Uint64()
		parent := chain.GetHeader(header.ParentHash, number-1)
		if parent == nil {
			return nil, consensus.ErrUnknownAncestor
		}
		mmr, err := r.expectedHeaderMMR(chain, chainLookup(chain), parent)
		if err != nil {
			return nil, err
		}
		if err := checkHeaderMMR(&types.Header{Difficulty: header.Difficulty}, mmr); err != nil {
			return nil, err
		}
		root, err := mmr.Root()
		if err != nil {
			return nil, err
		}
		mmrRoot := common.Hash(root)
		coinRoot, err := ghosttree.Root(state, ghosttree.Coin)
		if err != nil {
			return nil, err
		}
		dataRoot, err := ghosttree.Root(state, ghosttree.Data)
		if err != nil {
			return nil, err
		}
		markerRoot, err := ghosttree.DataMarkerRoot(state)
		if err != nil {
			return nil, err
		}
		header.CoinTreeRoot, header.DataTreeRoot, header.DataMarkerRoot = &coinRoot, &dataRoot, &markerRoot
		header.HeaderMmrRoot = &mmrRoot
	}
	header.Root = state.IntermediateRoot(config.IsEnabled(config.GetEIP161dTransition, header.Number))
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

// SealHash returns the hash the seal commits to: the Keccak-256 of the RLP
// header with MixDigest and Nonce zeroed, so it covers every other field,
// including any field added to the header later.
func (r *RandomX) SealHash(header *types.Header) (hash common.Hash) {
	h := types.CopyHeader(header)
	h.MixDigest = common.Hash{}
	h.Nonce = types.BlockNonce{}
	hasher := sha3.NewLegacyKeccak256()
	rlp.Encode(hasher, h)
	hasher.Sum(hash[:0])
	return hash
}

// CalcDifficulty implements consensus.Engine, returning the ASERT difficulty
// of a block on parent at the given time, anchored at the genesis header's
// time. It returns nil when the chain cannot supply its genesis header.
func (r *RandomX) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	difficulty, err := r.requiredDifficulty(chain, time, parent)
	if err != nil {
		return nil
	}
	return difficulty
}

func (r *RandomX) requiredDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) (*big.Int, error) {
	genesis := parent
	if parent.Number.Sign() != 0 {
		if genesis = chain.GetHeaderByNumber(0); genesis == nil {
			return nil, errUnknownGenesis
		}
	}
	return r.params.RequiredDifficulty(genesis.Time, parent.Number.Uint64()+1, time), nil
}

// APIs implements consensus.Engine, serving API under the "ethash"
// namespace, the proof-of-work name the chain configuration uses, and under
// the "eth" namespace, where remote miners call getWork and submitWork.
func (r *RandomX) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	apis := []rpc.API{{Namespace: "ethash", Service: &API{r}}}
	return append(apis, rpc.API{Namespace: "eth", Service: &API{r}})
}

// API is the engine's RPC service: the hash rate, and work for remote
// miners (remote.go).
type API struct {
	r *RandomX
}

// GetHashrate returns the hashes per second of the local sealer and of the
// remote miners that submitted a rate.
func (api *API) GetHashrate() uint64 {
	return uint64(api.r.Hashrate())
}
