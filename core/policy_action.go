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

package core

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/holiman/uint256"
)

// ApplyPolicyAction applies a policy action, the native transaction 0x54
// without an account (spec 10, section 8), in the block of header, and
// returns its receipt. It is the one execution of an action for block
// processing, the chain maker and the miner.
//
// It takes exactly G_ACTION from the block gas pool, which must hold it, and
// runs checks 1 to 10 of the action with the active proof verifier
// (ghostpriv.CheckAction); a failure makes the block invalid and changes
// nothing. Then, in order:
//
//  1. the exact debit leaves the slot, whose action nonce is spent, and the
//     slot closes if its remaining reaches zero; G_ACTION times the base fee
//     of the debit is burned and the rest is the coinbase's tip
//     (ghostpriv.SettleAction);
//  2. under a snapshot of its own, the slot's policy is called with the
//     action's calldata from ACTION_CALLER, which is also ORIGIN, at
//     GASPRICE zero, with ACTION_CALL_GAS and no value, with actionMarker
//     and actionSettle at 0x60 answering for this action; a call that fails
//     or reverts undoes its own effects only, never the debit or the nonce;
//  3. the action-result log is written, for a call that succeeded or failed.
//
// The receipt is a typed 0x54 receipt with status successful and gas used
// G_ACTION whatever the call used: no gas is refunded.
//
// chain gives the headers of the block's ancestry and the consensus engine,
// and genesis is the chain's genesis hash.
func ApplyPolicyAction(config ctypes.ChainConfigurator, chain ChainContext, gp *GasPool, statedb *state.StateDB, header *types.Header, genesis common.Hash, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	if tx.Type() != types.GhostPolicyActionTxType {
		return nil, fmt.Errorf("%w: type %#x is not a policy action", types.ErrTxTypeNotSupported, tx.Type())
	}
	gas := tx.Gas()
	if gas != ghostpriv.GasAction {
		return nil, fmt.Errorf("%w: policy action gas %d", types.ErrTxTypeNotSupported, gas)
	}
	if err := gp.SubGas(gas); err != nil {
		return nil, err
	}
	env := &ghostpriv.BlockEnv{
		Header:  header,
		Chain:   chain,
		ChainID: config.GetChainID(),
		Genesis: genesis,
	}
	a, fee, err := ghostpriv.CheckAction(statedb, env, ghostpriv.ActiveVerifier(), tx.GhostPolicyActionEnvelope())
	if err != nil {
		gp.AddGas(gas)
		return nil, err
	}
	snap := statedb.Snapshot()
	slot, err := ghostpriv.SettleAction(statedb, env, a, fee)
	if err != nil {
		statedb.RevertToSnapshot(snap)
		gp.AddGas(gas)
		return nil, err
	}
	remaining := new(uint256.Int)
	if after, ok := ghostpriv.ReadEscrowSlot(statedb, a.Marker); ok {
		remaining = after.Remaining
	}

	// The policy call, from ACTION_CALLER with ACTION_CALL_GAS.
	var (
		caller   = ghost.ActionCallerAddress
		blockCtx = NewEVMBlockContext(header, chain, &header.Coinbase)
		txCtx    = vm.TxContext{Origin: caller, GasPrice: new(big.Int)}
		evm      = vm.NewEVM(blockCtx, txCtx, statedb, config, cfg)
		policy   = slot.Policy
	)
	evm.SetActionContext(&vm.ActionContext{
		Marker:    a.Marker,
		Policy:    policy,
		Debit:     new(uint256.Int).Set(a.Debit),
		Remaining: remaining,
	})
	eip2930 := config.IsEnabled(config.GetEIP2930Transition, header.Number)
	eip3651 := config.IsEnabledByTime(config.GetEIP3651TransitionTime, &header.Time) || config.IsEnabled(config.GetEIP3651Transition, header.Number)
	statedb.Prepare(eip2930, eip3651, caller, header.Coinbase, &policy, evm.ActivePrecompiles(), nil)
	ret, left, callErr := evm.Call(vm.AccountRef(caller), policy, a.Calldata, ghostpriv.ActionCallGas, new(uint256.Int))
	if left > ghostpriv.ActionCallGas {
		left = ghostpriv.ActionCallGas
	}
	evm.SetActionContext(nil)
	if callErr != nil && callErr != vm.ErrExecutionReverted {
		ret = nil
	}
	ghostpriv.WriteActionResult(statedb, header.Number.Uint64(), a, callErr == nil, ghostpriv.ActionCallGas-left, ret)

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
	return receipt, nil
}
