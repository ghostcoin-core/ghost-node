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

package ghostpriv_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
)

// bindingExtraGas is the intrinsic gas an ML-DSA-44 binding transaction
// takes on top of that of a type 0x02 transaction: its scheme ID and public
// key as calldata, without the signature bytes and the signature
// verification an account transaction pays.
var bindingExtraGas uint64 = 16 * (2 + types.GhostMLDSA44PublicKeySize)

// gasSchemes are the account transaction schemes with their documented extra
// intrinsic gas of a raw-signature account transaction (spec 09, section
// 8.1; docs/account-transactions.md).
var gasSchemes = []struct {
	name    string
	scheme  uint16
	rawGas  uint64 // 16 * (2 + public key + signature) + VERIFY_GAS
	sigSize int
}{
	{"ML-DSA-44", types.GhostSchemeMLDSA44, 62_744, types.GhostMLDSA44SignatureSize},
	{"SLH-DSA-SHAKE-128s", types.GhostSchemeSLHDSA, 138_240, types.GhostSLHDSASignatureSize},
	{"ML-DSA-44 rescue", types.GhostSchemeMLDSA44Rescue, 63_256, types.GhostMLDSA44SignatureSize},
	{"SLH-DSA-SHAKE-128s rescue", types.GhostSchemeSLHDSARescue, 159_232, types.GhostSLHDSASignatureSize},
}

// rawAuthTx is an account transaction of scheme carrying a public key and a
// signature of the scheme's sizes, zero bytes: only its sizes are priced.
func rawAuthTx(t *testing.T, scheme uint16) *types.Transaction {
	t.Helper()
	pub, sig, ok := types.GhostSchemeSizes(scheme)
	if !ok {
		t.Fatalf("scheme %#04x has no sizes", scheme)
	}
	return types.NewTx(&types.GhostAccountTx{
		ChainID:   big.NewInt(1),
		GasTipCap: new(big.Int),
		GasFeeCap: new(big.Int),
		Value:     new(big.Int),
		Scheme:    types.GhostScheme(scheme),
		PublicKey: make([]byte, pub),
		Signature: make([]byte, sig),
	})
}

// TestPublicRootBindingGasDropsSignatureGas checks that a binding
// transaction (0x57), which carries no signature bytes, is priced at the
// raw-signature account transaction's gas of its scheme less SIG_BYTE_GAS *
// the signature bytes and less VERIFY_GAS, for every scheme; that a scheme
// without sizes is refused; and that a block holding a binding transaction
// whose gas limit is that price, below a raw-signature one's, imports with
// that gas used and charged to the binding's account.
func TestPublicRootBindingGasDropsSignatureGas(t *testing.T) {
	for _, c := range gasSchemes {
		raw, err := core.GhostAccountExtraIntrinsicGas(rawAuthTx(t, c.scheme))
		if err != nil || raw != c.rawGas {
			t.Fatalf("%s: raw-signature gas %d (%v), want %d", c.name, raw, err, c.rawGas)
		}
		got, err := core.GhostBindingExtraIntrinsicGas(c.scheme)
		if err != nil {
			t.Fatalf("%s: binding gas: %v", c.name, err)
		}
		want := raw - ghost.AccountTxSigByteGas*uint64(c.sigSize) - ghost.AccountTxVerifyGas(c.scheme)
		if got != want {
			t.Fatalf("%s: binding gas %d, want %d: the raw-signature %d less the signature bytes and VERIFY_GAS", c.name, got, want, raw)
		}
		if ghost.AccountTxVerifyGas(c.scheme) == 0 || got >= raw {
			t.Fatalf("%s: binding gas %d is not below the raw-signature %d", c.name, got, raw)
		}
	}
	if got, err := core.GhostBindingExtraIntrinsicGas(types.GhostSchemeMLDSA44); err != nil || got != bindingExtraGas {
		t.Fatalf("ML-DSA-44 binding gas %d (%v), want %d", got, err, bindingExtraGas)
	}
	if _, err := core.GhostBindingExtraIntrinsicGas(0x0005); !errors.Is(err, types.ErrGhostAccountScheme) {
		t.Fatalf("unknown scheme: %v, want %v", err, types.ErrGhostAccountScheme)
	}

	// In a block: a binding transaction whose gas limit covers its own
	// intrinsic gas but not a raw-signature one's imports, at that gas.
	useStub(t)
	s := newPublicChain(t)
	value := big.NewInt(1_000_000)
	inner := s.unbound(1, pubTo(1), value)
	inner.Gas = 21_000 + bindingExtraGas
	if inner.Gas >= 21_000+accountExtraGas {
		t.Fatal("the binding transaction's gas limit covers a raw-signature one's")
	}
	inner.Binding = types.NewGhostBinding(addrA, pubIdentity(seedA), s.txHash(inner))
	bind := types.NewTx(inner)
	before, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	balance := before.GetBalance(addrA).ToBig()

	blocks, _ := s.build(t, func(b *core.BlockGen) {
		b.AddTx(rootTx(t, s.rootOf(bind)))
		b.AddTx(bind)
	})
	s.f.insert(s.chain, blocks[1:])
	rs := s.chain.GetReceiptsByHash(blocks[1].Hash())
	if len(rs) != 2 || rs[1].Type != types.GhostBindingTxType || rs[1].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("receipts %d, binding receipt not successful", len(rs))
	}
	if rs[1].GasUsed != 21_000+bindingExtraGas {
		t.Fatalf("binding gas used %d, want %d", rs[1].GasUsed, 21_000+bindingExtraGas)
	}
	if blocks[1].GasUsed() != rs[1].GasUsed {
		t.Fatalf("block gas used %d, want the binding transaction's %d", blocks[1].GasUsed(), rs[1].GasUsed)
	}
	after, err := s.chain.State()
	if err != nil {
		t.Fatal(err)
	}
	paid := new(big.Int).Mul(new(big.Int).SetUint64(rs[1].GasUsed), rs[1].EffectiveGasPrice)
	wantBalance := new(big.Int).Sub(balance, new(big.Int).Add(value, paid))
	if got := after.GetBalance(addrA).ToBig(); got.Cmp(wantBalance) != 0 {
		t.Fatalf("balance of the binding's account %v, want %v", got, wantBalance)
	}
}

// TestPublicRootRawSignatureGasUnchanged checks that an account transaction
// with its raw signature (0x52) keeps the gas of spec 09, section 8.1, its
// signature bytes and VERIFY_GAS included: the extra intrinsic gas of every
// scheme is the documented one, and in a block with a public root a
// raw-signature transaction uses that gas, while one whose gas limit covers
// only a binding transaction's price is refused.
func TestPublicRootRawSignatureGasUnchanged(t *testing.T) {
	for _, c := range gasSchemes {
		pub, sig, _ := types.GhostSchemeSizes(c.scheme)
		want := ghost.AccountTxSigByteGas*uint64(2+pub+sig) + ghost.AccountTxVerifyGas(c.scheme)
		got, err := core.GhostAccountExtraIntrinsicGas(rawAuthTx(t, c.scheme))
		if err != nil || got != want || got != c.rawGas {
			t.Fatalf("%s: raw-signature gas %d (%v), want %d", c.name, got, err, c.rawGas)
		}
	}
	if accountExtraGas != gasSchemes[0].rawGas {
		t.Fatalf("ML-DSA-44 extra gas %d, want %d", accountExtraGas, gasSchemes[0].rawGas)
	}

	useStub(t)
	s := newPublicChain(t)
	value := big.NewInt(1_000_000)
	bindA := s.bindingTx(addrA, pubIdentity(seedA), 1, pubTo(1), value)
	raw := s.f.callTx(keyC, 0, pubTo(3), value, nil, 21_000)
	blocks, _ := s.build(t, func(b *core.BlockGen) {
		b.AddTx(rootTx(t, s.rootOf(bindA)))
		b.AddTx(raw)
		b.AddTx(bindA)
	})
	s.f.insert(s.chain, blocks[1:])
	rs := s.chain.GetReceiptsByHash(blocks[1].Hash())
	if len(rs) != 3 || rs[1].Type != types.GhostAccountTxType || rs[1].Status != types.ReceiptStatusSuccessful {
		t.Fatal("the raw-signature transaction did not import beside the root")
	}
	if rs[1].GasUsed != 21_000+accountExtraGas {
		t.Fatalf("raw-signature gas used %d, want %d", rs[1].GasUsed, 21_000+accountExtraGas)
	}
	if rs[2].GasUsed != 21_000+bindingExtraGas {
		t.Fatalf("binding gas used %d, want %d", rs[2].GasUsed, 21_000+bindingExtraGas)
	}

	// A raw-signature transaction is not priced as a binding transaction,
	// whatever else its block holds.
	to := pubTo(3)
	short := s.f.signAccountTx(keyC, &types.GhostAccountTx{
		ChainID:   new(big.Int).SetUint64(s.f.chainID),
		Nonce:     0,
		GasTipCap: new(big.Int).Set(gwei),
		GasFeeCap: new(big.Int).Mul(gwei, big.NewInt(100)),
		Gas:       21_000 + accountExtraGas - 1,
		To:        &to,
		Value:     value,
	})
	if err := s.insertBad(t, "raw-signature gas below its signature's", s.unchecked(t, rootTx(t, s.rootOf(bindA)), short, bindA)); !errors.Is(err, core.ErrIntrinsicGas) {
		t.Fatalf("raw-signature transaction below its gas: block imported with %v, want %v", err, core.ErrIntrinsicGas)
	}
}
