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
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// The node's signing methods (personal_signTransaction,
// personal_sendTransaction, eth_signTransaction, eth_sendTransaction and
// eth_resend) build an account transaction, type 0x52, and sign it with the
// ML-DSA-44 key of the keystore account (docs/account-transactions.md).

// accountTxSigGas is the gas an account transaction signed with an ML-DSA-44
// key takes on top of the type 0x02 intrinsic gas: 16 * (2 + public key +
// signature) + VERIFY_GAS (core.GhostAccountExtraIntrinsicGas). The keystore
// signs with ML-DSA-44 keys only.
var accountTxSigGas = ghost.AccountTxSigByteGas*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) +
	ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44)

// accountTxSigner returns the signer of account transactions of b's chain,
// bound to the hash of its genesis header.
func accountTxSigner(ctx context.Context, b Backend) (types.Signer, error) {
	return accountSigner(ctx, b, types.LatestSigner(b.ChainConfig()))
}

// setAccountTxDefaults fills in the defaults of an account transaction. A gas
// limit that is estimated has the signature gas added, which a call does not
// take; a gas limit given is kept as it is.
func (args *TransactionArgs) setAccountTxDefaults(ctx context.Context, b Backend) error {
	if args.IsEIP4844() || args.Blobs != nil {
		return errBlobTxNotSupported
	}
	estimate := args.Gas == nil
	if err := args.setDefaults(ctx, b, false); err != nil {
		return err
	}
	if estimate {
		gas := uint64(*args.Gas)
		if gas > math.MaxUint64-accountTxSigGas {
			return core.ErrGasUintOverflow
		}
		gas += accountTxSigGas
		args.Gas = (*hexutil.Uint64)(&gas)
	}
	return nil
}

// toAccountTx returns the unsigned account transaction of args, whose
// defaults are set. A gas price is both the fee cap and the tip cap.
func (args *TransactionArgs) toAccountTx() *types.GhostAccountTx {
	feeCap, tipCap := args.MaxFeePerGas.ToInt(), args.MaxPriorityFeePerGas.ToInt()
	if args.GasPrice != nil {
		feeCap, tipCap = args.GasPrice.ToInt(), args.GasPrice.ToInt()
	}
	al := types.AccessList{}
	if args.AccessList != nil {
		al = *args.AccessList
	}
	return &types.GhostAccountTx{
		ChainID:    new(big.Int).Set(args.ChainID.ToInt()),
		Nonce:      uint64(*args.Nonce),
		GasTipCap:  bigOrZero(tipCap),
		GasFeeCap:  bigOrZero(feeCap),
		Gas:        uint64(*args.Gas),
		To:         args.To,
		Value:      bigOrZero(args.Value.ToInt()),
		Data:       args.data(),
		AccessList: al,
	}
}

// bigOrZero returns a copy of v, and zero for nil.
func bigOrZero(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}

// walletSignAccountTx signs the account transaction tx with the key of account
// in wallet: with the unlocked key, or, with a passphrase, with the key it
// decrypts. The sender derived from the signed transaction must be account.
func walletSignAccountTx(ctx context.Context, b Backend, wallet accounts.Wallet, account accounts.Account, passwd *string, tx *types.GhostAccountTx) (*types.Transaction, error) {
	signer, err := accountTxSigner(ctx, b)
	if err != nil {
		return nil, err
	}
	var signed *types.Transaction
	if passwd == nil {
		signed, err = wallet.SignAccountTx(account, signer, tx)
	} else {
		signed, err = wallet.SignAccountTxWithPassphrase(account, *passwd, signer, tx)
	}
	if err != nil {
		return nil, err
	}
	from, err := types.GhostAccountAddress(signer, signed)
	if err != nil {
		return nil, err
	}
	if from != account.Address {
		return nil, fmt.Errorf("signed account transaction is from %v, not the account %v", from, account.Address)
	}
	return signed, nil
}

// accountTxFeeCheck checks that the fee of the account transaction tx is
// within the node's cap.
func accountTxFeeCheck(b Backend, tx *types.GhostAccountTx) error {
	return checkTxFee(tx.GasFeeCap, tx.Gas, b.RPCTxFeeCap())
}

// sameAccountTx reports whether the account transaction p in the pool is the
// transaction of want and from, apart from the signature: p is from the
// account, and want, with p's scheme and public key, has p's signature hash.
func sameAccountTx(signer types.Signer, p *types.Transaction, want *types.GhostAccountTx, from accounts.Account) bool {
	scheme, publicKey, _, ok := p.GhostAccountAuth()
	if !ok || types.GhostAccountAddressOf(scheme, publicKey) != from.Address {
		return false
	}
	cpy := *want
	cpy.Scheme = types.GhostScheme(scheme)
	cpy.PublicKey = publicKey
	return signer.Hash(types.NewTx(&cpy)) == signer.Hash(p)
}
