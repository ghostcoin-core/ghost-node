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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/mutations"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config ctypes.ChainConfigurator // Chain configuration options
	bc     *BlockChain              // Canonical block chain
	engine consensus.Engine         // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config ctypes.ChainConfigurator, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the block and state according to any hard-fork specs
	isDAOSupport := p.config.IsEnabled(p.config.GetEthashEIP779Transition, block.Number())
	if isDAOSupport {
		if daoNumber := p.config.GetEthashEIP779Transition(); daoNumber != nil && *daoNumber == block.NumberU64() {
			mutations.ApplyDAOHardFork(statedb)
		}
	}
	var (
		context = NewEVMBlockContext(header, p.bc, nil)
		vmenv   = vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
		signer  = types.NewGhostAccountSigner(types.MakeSigner(p.config, header.Number, header.Time), p.genesisHash())
	)
	if beaconRoot := block.BeaconRoot(); beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, vmenv, statedb)
	}
	// The block's public root, if any, and the binding transactions it has
	// proved so far.
	var roots ghostPublicRoots
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		// Only the reveals and the account transaction are taken: a block
		// holding a secp256k1 type, or any other type, is invalid.
		if err := types.CheckTxType(tx); err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		// A public root is checked against the bindings the node builds from
		// the binding transactions of this block, which follow it, on the
		// state at the root.
		if tx.Type() == types.GhostPublicRootTxType {
			if p.bc == nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: no chain for a public root", i, tx.Hash().Hex())
			}
			genesis := p.bc.Genesis().Hash()
			statedb.SetTxContext(tx.Hash(), i)
			bindings, err := ghostBlockBindings(statedb, genesis, block.Transactions()[i+1:])
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipt, err := applyGhostPublicRoot(p.config, statedb, header, p.bc, genesis, blockHash, tx, usedGas, &roots, bindings)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipts = append(receipts, receipt)
			continue
		}
		// A binding transaction runs as an account transaction once the
		// block's root has proved its binding.
		if tx.Type() == types.GhostBindingTxType {
			if p.bc == nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: no chain for a binding transaction", i, tx.Hash().Hex())
			}
			statedb.SetTxContext(tx.Hash(), i)
			receipt, err := applyGhostBindingTx(p.config, gp, statedb, header, p.bc.Genesis().Hash(), blockHash, tx, usedGas, vmenv, &roots)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipts = append(receipts, receipt)
			allLogs = append(allLogs, receipt.Logs...)
			continue
		}
		// A bundle is no reveal (IsGhostReveal), but is applied beside them.
		if tx.Type() == types.GhostBundleTxType {
			if p.bc == nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: no chain for a bundle", i, tx.Hash().Hex())
			}
			statedb.SetTxContext(tx.Hash(), i)
			receipt, err := applyGhostBundle(p.config, gp, statedb, header, p.bc, p.bc.Genesis().Hash(), blockHash, tx, usedGas)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipts = append(receipts, receipt)
			allLogs = append(allLogs, receipt.Logs...)
			continue
		}
		if tx.IsGhostReveal() {
			if p.bc == nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: no chain for a reveal", i, tx.Hash().Hex())
			}
			statedb.SetTxContext(tx.Hash(), i)
			var (
				receipt *types.Receipt
				err     error
			)
			// A policy action runs its policy call in the EVM; every other
			// native type is a reveal.
			if tx.Type() == types.GhostPolicyActionTxType {
				receipt, err = ApplyPolicyAction(p.config, p.bc, gp, statedb, header, p.bc.Genesis().Hash(), blockHash, tx, usedGas, cfg)
			} else {
				receipt, err = applyGhostReveal(p.config, gp, statedb, header, p.bc, p.bc.Genesis().Hash(), blockHash, tx, usedGas)
			}
			if err != nil {
				return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			receipts = append(receipts, receipt)
			allLogs = append(allLogs, receipt.Logs...)
			continue
		}
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)
		receipt, err := applyTransaction(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	if err := roots.finish(); err != nil {
		return nil, nil, 0, fmt.Errorf("could not apply the block's public root: %w", err)
	}
	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	blockTime := block.Time()
	if len(withdrawals) > 0 && !(p.config.IsEnabledByTime(p.config.GetEIP4895TransitionTime, &blockTime) || p.config.IsEnabled(p.config.GetEIP4895Transition, blockNumber)) {
		return nil, nil, 0, fmt.Errorf("withdrawals before shanghai")
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), withdrawals)

	return receipts, allLogs, *usedGas, nil
}

// genesisHash returns the hash of the chain's genesis block, zero without a
// chain, which makes the signer refuse every account transaction.
func (p *StateProcessor) genesisHash() common.Hash {
	if p.bc == nil {
		return common.Hash{}
	}
	return p.bc.Genesis().Hash()
}

func applyTransaction(msg *Message, config ctypes.ChainConfigurator, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	eip161d := config.IsEnabled(config.GetEIP161dTransition, blockNumber)
	if config.IsEnabled(config.GetEIP658Transition, blockNumber) {
		statedb.Finalise(eip161d)
	} else {
		root = statedb.IntermediateRoot(eip161d).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * vars.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// applyGhostReveal applies a coin reveal (type 0x50), a data reveal (type
// 0x51) or a policy reveal (type 0x53), the native transactions without an
// account, in the block of header: it takes exactly the gas of the
// transaction's class from the block gas pool, which must hold it (G_PRIV,
// G_DATA or G_POLICY), runs the checks of the transaction's own type with the
// active proof verifier and makes its change (core/ghostpriv). chain gives
// the headers of the block's ancestry and genesis is the chain's genesis
// hash. Any failure makes the block invalid. A policy action (type 0x54) is
// not a reveal here: it goes to ApplyPolicyAction, and this refuses it.
func applyGhostReveal(config ctypes.ChainConfigurator, gp *GasPool, statedb *state.StateDB, header *types.Header, chain ghostpriv.ChainReader, genesis common.Hash, blockHash common.Hash, tx *types.Transaction, usedGas *uint64) (*types.Receipt, error) {
	gas := tx.Gas()
	if err := gp.SubGas(gas); err != nil {
		return nil, err
	}
	env := &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   chain,
		ChainID: config.GetChainID(),
		Genesis: genesis,
	}
	var err error
	switch tx.Type() {
	case types.GhostRevealTxType:
		err = ghostpriv.ApplyReveal(statedb, env, ghostpriv.ActiveVerifier(), tx.GhostRevealEnvelope())
	case types.GhostDataRevealTxType:
		err = ghostpriv.ApplyDataReveal(statedb, env, ghostpriv.ActiveVerifier(), tx.GhostDataRevealEnvelope())
	case types.GhostPolicyRevealTxType:
		err = ghostpriv.ApplyPolicyReveal(statedb, env, ghostpriv.ActiveVerifier(), tx.GhostPolicyRevealEnvelope())
	default:
		err = fmt.Errorf("%w: type %#x is not a reveal", types.ErrTxTypeNotSupported, tx.Type())
	}
	if err != nil {
		return nil, err
	}
	return ghostNativeReceipt(config, statedb, header, blockHash, tx, gas, usedGas), nil
}

// applyGhostBundle applies a bundle (type 0x55) in the block of header: it
// takes exactly count times G_PRIV from the block gas pool, which must hold
// it, checks the bundle's structure and root proof with the active proof
// verifier and applies its reveals in order, skipping those whose
// state-dependent checks fail (ghostpriv.ApplyBundle). A structural failure
// makes the block invalid. The receipt is one receipt of type 0x55, status
// successful, with the bundle's whole gas and the logs of the applied
// reveals in order.
func applyGhostBundle(config ctypes.ChainConfigurator, gp *GasPool, statedb *state.StateDB, header *types.Header, chain ghostpriv.ChainReader, genesis common.Hash, blockHash common.Hash, tx *types.Transaction, usedGas *uint64) (*types.Receipt, error) {
	if tx.Type() != types.GhostBundleTxType {
		return nil, fmt.Errorf("%w: type %#x is not a bundle", types.ErrTxTypeNotSupported, tx.Type())
	}
	gas := tx.Gas()
	if err := gp.SubGas(gas); err != nil {
		return nil, err
	}
	env := &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   chain,
		ChainID: config.GetChainID(),
		Genesis: genesis,
	}
	if _, err := ghostpriv.ApplyBundle(statedb, env, ghostpriv.ActiveVerifier(), tx.GhostBundleEnvelope()); err != nil {
		return nil, err
	}
	return ghostNativeReceipt(config, statedb, header, blockHash, tx, gas, usedGas), nil
}

// ghostPublicRoots is the public root of a block being applied, at most one,
// and the count of the binding transactions after it applied so far.
type ghostPublicRoots struct {
	root *ghostpriv.PublicRoot
	next int
}

// finish checks, at the end of the block, that every binding the root lists
// was applied: a root with bindings the block does not hold is invalid.
func (r *ghostPublicRoots) finish() error {
	if r.root != nil && r.next != len(r.root.Bindings) {
		return fmt.Errorf("%w: root of %d, block of %d", ghostpriv.ErrPublicRootCount, len(r.root.Bindings), r.next)
	}
	return nil
}

// ghostBlockBindings returns the bindings the node builds for the binding
// transactions among txs, the rest of the block after its public root, in
// order: the account each carries, the key identity read from statedb and
// the transaction hash the node computes on the chain of genesis. Every
// other transaction is passed over; a second public root is
// ErrPublicRootRepeated.
func ghostBlockBindings(statedb *state.StateDB, genesis common.Hash, txs []*types.Transaction) ([]types.GhostBinding, error) {
	var bindings []types.GhostBinding
	for _, tx := range txs {
		if tx.Type() == types.GhostPublicRootTxType {
			return nil, ghostpriv.ErrPublicRootRepeated
		}
		_, carried, ok := tx.GhostBinding()
		if !ok {
			continue
		}
		hash, _ := tx.GhostBindingTxHash(genesis)
		bindings = append(bindings, ghostpriv.NodeBinding(statedb, carried.Account(), hash))
	}
	return bindings, nil
}

// applyGhostPublicRoot applies a public root (type 0x56) in the block of
// header: the block's first and only one, before every binding transaction
// of the block. It checks the root against the bindings the node built from
// the block's binding transactions (ghostpriv.CheckPublicRoot) with the
// active proof verifier; any failure makes the block invalid. The root takes
// no gas and changes no state; its receipt is of type 0x56, status
// successful, with no gas and no logs.
func applyGhostPublicRoot(config ctypes.ChainConfigurator, statedb *state.StateDB, header *types.Header, chain ghostpriv.ChainReader, genesis common.Hash, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, roots *ghostPublicRoots, bindings []types.GhostBinding) (*types.Receipt, error) {
	if tx.Type() != types.GhostPublicRootTxType {
		return nil, fmt.Errorf("%w: type %#x is not a public root", types.ErrTxTypeNotSupported, tx.Type())
	}
	if roots.root != nil {
		return nil, ghostpriv.ErrPublicRootRepeated
	}
	env := &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   chain,
		ChainID: config.GetChainID(),
		Genesis: genesis,
	}
	root, err := ghostpriv.CheckPublicRoot(env, ghostpriv.ActiveVerifier(), tx.GhostPublicRootEnvelope(), bindings)
	if err != nil {
		return nil, err
	}
	roots.root = root
	return ghostNativeReceipt(config, statedb, header, blockHash, tx, 0, usedGas), nil
}

// applyGhostBindingTx applies a binding transaction (type 0x57) in the block
// of header, after the block's public root. Its binding must be the one the
// node builds on the state at this point of the block (the account's key
// identity recorded and carried, the node's transaction hash) and the next
// one the root proved; then it runs as an account transaction of its
// binding's account, with every state-dependent check (nonce, balance,
// code, gas) and the gas of an account transaction of its scheme. Any
// failure makes the block invalid.
func applyGhostBindingTx(config ctypes.ChainConfigurator, gp *GasPool, statedb *state.StateDB, header *types.Header, genesis common.Hash, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM, roots *ghostPublicRoots) (*types.Receipt, error) {
	scheme, carried, ok := tx.GhostBinding()
	if !ok {
		return nil, fmt.Errorf("%w: type %#x is not a binding transaction", types.ErrTxTypeNotSupported, tx.Type())
	}
	if roots.root == nil {
		return nil, ghostpriv.ErrPublicRootMissing
	}
	if roots.next >= len(roots.root.Bindings) {
		return nil, fmt.Errorf("%w: root of %d, block of more", ghostpriv.ErrPublicRootCount, len(roots.root.Bindings))
	}
	if err := tx.CheckGhostBindingShape(); err != nil {
		return nil, err
	}
	if chainID := config.GetChainID(); chainID == nil || tx.ChainId().Cmp(chainID) != 0 {
		return nil, fmt.Errorf("%w: have %d want %d", types.ErrInvalidChainId, tx.ChainId(), chainID)
	}
	hash, _ := tx.GhostBindingTxHash(genesis)
	node, err := ghostpriv.CheckBinding(statedb, carried, hash)
	if err != nil {
		return nil, err
	}
	if node != roots.root.Bindings[roots.next] {
		return nil, fmt.Errorf("%w: binding %d of the root is not the block's", ghostpriv.ErrPublicRootBinding, roots.next)
	}
	roots.next++
	msg, err := ghostBindingMessage(tx, scheme, carried, header.BaseFee)
	if err != nil {
		return nil, err
	}
	return applyTransaction(msg, config, gp, statedb, header.Number, blockHash, tx, usedGas, evm)
}

// ghostBindingMessage converts a binding transaction into a Message from the
// account of its binding, which the block's root proved, carrying its scheme
// and key identity as an account transaction's message does.
func ghostBindingMessage(tx *types.Transaction, scheme uint16, binding types.GhostBinding, baseFee *big.Int) (*Message, error) {
	msg := &Message{
		From:               binding.Account(),
		Nonce:              tx.Nonce(),
		GasLimit:           tx.Gas(),
		GasPrice:           new(big.Int).Set(tx.GasPrice()),
		GasFeeCap:          new(big.Int).Set(tx.GasFeeCap()),
		GasTipCap:          new(big.Int).Set(tx.GasTipCap()),
		To:                 tx.To(),
		Value:              tx.Value(),
		Data:               tx.Data(),
		AccessList:         tx.AccessList(),
		GhostAccountScheme: scheme,
		GhostKeyIdentity:   binding.KeyIdentity(),
	}
	if baseFee != nil {
		msg.GasPrice = cmath.BigMin(msg.GasPrice.Add(msg.GasTipCap, baseFee), msg.GasFeeCap)
	}
	var err error
	msg.ExtraIntrinsicGas, err = ghostBindingExtraIntrinsicGas(scheme)
	return msg, err
}

// ghostBindingExtraIntrinsicGas is the intrinsic gas a binding transaction
// takes on top of the type 0x02 intrinsic gas: that of an account
// transaction of its scheme (GhostAccountExtraIntrinsicGas), as if it carried
// the scheme's public key and signature.
func ghostBindingExtraIntrinsicGas(scheme uint16) (uint64, error) {
	pubKey, sig, ok := types.GhostSchemeSizes(scheme)
	if !ok {
		return 0, fmt.Errorf("%w: scheme %#04x", types.ErrGhostAccountScheme, scheme)
	}
	verify := ghost.AccountTxVerifyGas(scheme)
	if verify == 0 {
		return 0, fmt.Errorf("%w: scheme %#04x", ErrGhostAccountVerifyGas, scheme)
	}
	return ghost.AccountTxSigByteGas*uint64(2+pubKey+sig) + verify, nil
}

// ghostNativeReceipt finalises the state after a native transaction without
// an account, adds its gas to usedGas and returns its receipt: status
// successful, the gas and the logs the transaction wrote.
func ghostNativeReceipt(config ctypes.ChainConfigurator, statedb *state.StateDB, header *types.Header, blockHash common.Hash, tx *types.Transaction, gas uint64, usedGas *uint64) *types.Receipt {
	var root []byte
	eip161d := config.IsEnabled(config.GetEIP161dTransition, header.Number)
	if config.IsEnabled(config.GetEIP658Transition, header.Number) {
		statedb.Finalise(eip161d)
	} else {
		root = statedb.IntermediateRoot(eip161d).Bytes()
	}
	*usedGas += gas

	receipt := &types.Receipt{
		Type:              tx.Type(),
		PostState:         root,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: *usedGas,
		TxHash:            tx.Hash(),
		GasUsed:           gas,
		EffectiveGasPrice: new(big.Int),
	}
	receipt.Logs = statedb.GetLogs(tx.Hash(), header.Number.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = new(big.Int).Set(header.Number)
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
//
// Account transactions (type 0x52) are taken when bc is the chain, whose
// genesis hash their signatures are bound to, and refused otherwise.
func ApplyTransaction(config ctypes.ChainConfigurator, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	var genesis common.Hash
	if chain, ok := bc.(*BlockChain); ok && chain != nil {
		genesis = chain.Genesis().Hash()
	}
	return applyTransactionWithGenesis(config, bc, genesis, author, gp, statedb, header, tx, usedGas, cfg)
}

// applyTransactionWithGenesis is ApplyTransaction with the genesis hash of
// the chain given; a zero hash refuses every account transaction.
func applyTransactionWithGenesis(config ctypes.ChainConfigurator, bc ChainContext, genesis common.Hash, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	signer := types.NewGhostAccountSigner(types.MakeSigner(config, header.Number, header.Time), genesis)
	msg, err := TransactionToMessage(tx, signer, header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	txContext := NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	return applyTransaction(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
func ProcessBeaconBlockRoot(beaconRoot common.Hash, vmenv *vm.EVM, statedb *state.StateDB) {
	// If EIP-4788 is enabled, we need to invoke the beaconroot storage contract with
	// the new root
	msg := &Message{
		From:      vars.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &vars.BeaconRootsStorageAddress,
		Data:      beaconRoot[:],
	}
	vmenv.Reset(NewEVMTxContext(msg), statedb)
	statedb.AddAddressToAccessList(vars.BeaconRootsStorageAddress)
	_, _, _ = vmenv.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.U2560)
	statedb.Finalise(true)
}
