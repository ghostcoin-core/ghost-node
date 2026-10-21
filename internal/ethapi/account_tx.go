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

package ethapi

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The node's accounts are ML-DSA-44 accounts of its keystore, and the methods
// that sign with them (personal_signTransaction, personal_sendTransaction,
// eth_signTransaction, eth_sendTransaction and eth_resend) sign an account
// transaction, type 0x52 (docs/account-transactions.md).

// accountTxExtraGas is the intrinsic gas an ML-DSA-44 account transaction
// takes on top of the type 0x02 intrinsic gas: its scheme, public key and
// signature bytes and the verification gas of the scheme. The gas estimate
// of a call does not include it, so it is added to the estimate.
var accountTxExtraGas = ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) +
	ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44)

// accountTxSigner returns the signer of the node's account transactions: the
// latest signer of the chain, bound to its genesis hash.
func accountTxSigner(ctx context.Context, b Backend) (types.Signer, error) {
	genesis, err := b.HeaderByNumber(ctx, 0)
	if err != nil {
		return nil, err
	}
	if genesis == nil {
		return nil, errors.New("genesis block not found")
	}
	return types.NewGhostAccountSigner(types.LatestSigner(b.ChainConfig()), genesis.Hash()), nil
}

// setAccountTxDefaults fills in the defaults of the arguments of an account
// transaction. A gas limit it estimates includes the gas of the signature.
func (args *TransactionArgs) setAccountTxDefaults(ctx context.Context, b Backend) error {
	estimated := args.Gas == nil
	if err := args.setDefaults(ctx, b, false); err != nil {
		return err
	}
	if estimated {
		gas := *args.Gas + hexutil.Uint64(accountTxExtraGas)
		args.Gas = &gas
	}
	return nil
}

// toAccountTx converts the arguments to an unsigned account transaction. It
// assumes that setDefaults has been called. A gas price stands for both fee
// caps.
func (args *TransactionArgs) toAccountTx() *types.GhostAccountTx {
	tipCap, feeCap := (*big.Int)(args.MaxPriorityFeePerGas), (*big.Int)(args.MaxFeePerGas)
	if args.GasPrice != nil {
		tipCap, feeCap = (*big.Int)(args.GasPrice), (*big.Int)(args.GasPrice)
	}
	al := types.AccessList{}
	if args.AccessList != nil {
		al = *args.AccessList
	}
	return &types.GhostAccountTx{
		ChainID:    new(big.Int).Set((*big.Int)(args.ChainID)),
		Nonce:      uint64(*args.Nonce),
		GasTipCap:  new(big.Int).Set(tipCap),
		GasFeeCap:  new(big.Int).Set(feeCap),
		Gas:        uint64(*args.Gas),
		To:         args.To,
		Value:      new(big.Int).Set((*big.Int)(args.Value)),
		Data:       args.data(),
		AccessList: al,
	}
}

// signAccountTx signs the account transaction of the arguments, whose
// defaults are set, with the key of its sender: with passwd when given, and
// with the unlocked key otherwise.
func signAccountTx(ctx context.Context, b Backend, args *TransactionArgs, passwd *string) (*types.Transaction, error) {
	account := accounts.Account{Address: args.from()}
	wallet, err := b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	signer, err := accountTxSigner(ctx, b)
	if err != nil {
		return nil, err
	}
	if passwd != nil {
		return wallet.SignAccountTxWithPassphrase(account, *passwd, signer, args.toAccountTx())
	}
	return wallet.SignAccountTx(account, signer, args.toAccountTx())
}

// txSender returns the sender of a transaction for display: for an account
// transaction the address derived from its scheme and public key, which the
// node verified when it took the transaction, and the sender of signer for
// any other.
func txSender(signer types.Signer, tx *types.Transaction) (common.Address, error) {
	if scheme, publicKey, _, ok := tx.GhostAccountAuth(); ok {
		return types.GhostAccountAddressOf(scheme, publicKey), nil
	}
	return types.Sender(signer, tx)
}
