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

package legacypool

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// setupGhostAccountPool returns a pool on a test chain with a genesis block,
// which lets it take account transactions, and the genesis hash.
func setupGhostAccountPool(t *testing.T) (*LegacyPool, common.Hash) {
	t.Helper()
	pool, _, _ := setupPool()
	return pool, testGenesis.Hash()
}

type ghostPoolTx struct {
	nonce   uint64
	gas     uint64
	chainID *big.Int
	badSig  bool
	scheme  uint16 // replaces the scheme when not zero
}

func makeGhostPoolTx(t *testing.T, genesis common.Hash, key *mldsa44.PrivateKey, p ghostPoolTx) *types.Transaction {
	t.Helper()
	chainID := params.TestChainConfig.GetChainID()
	if p.chainID != nil {
		chainID = p.chainID
	}
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	signer := types.NewGhostAccountSigner(types.LatestSignerForChainID(chainID), genesis)
	tx, err := types.SignGhostAccountTx(signer, key, &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     p.nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       p.gas,
		To:        &to,
		Value:     big.NewInt(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.badSig && p.scheme == 0 {
		return tx
	}
	_, pk, sig, _ := tx.GhostAccountAuth()
	scheme := types.GhostSchemeMLDSA44
	if p.scheme != 0 {
		scheme = p.scheme
	}
	if p.badSig {
		sig[7] ^= 0x01
	}
	return types.NewTx(&types.GhostAccountTx{
		ChainID:   tx.ChainId(),
		Nonce:     tx.Nonce(),
		GasTipCap: tx.GasTipCap(),
		GasFeeCap: tx.GasFeeCap(),
		Gas:       tx.Gas(),
		To:        tx.To(),
		Value:     tx.Value(),
		Scheme:    types.GhostScheme(scheme),
		PublicKey: pk,
		Signature: sig,
	})
}

func TestGhostAccountTxPool(t *testing.T) {
	pool, genesis := setupGhostAccountPool(t)
	defer pool.Close()

	if ghost.AccountTxVerifyGasMLDSA44 == 0 {
		t.Fatal("the verification gas of ML-DSA-44 is not set")
	}
	key, _, from := testAccount(1)
	testAddBalance(pool, from, big.NewInt(1_000_000_000_000_000_000))

	// A valid account transaction is admitted, under its derived sender.
	valid := makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 0, gas: txGas})
	if !pool.Filter(valid) {
		t.Fatal("the pool does not take account transactions")
	}
	if err := pool.addRemoteSync(valid); err != nil {
		t.Fatalf("valid account transaction refused: %v", err)
	}
	if pool.Get(valid.Hash()) == nil {
		t.Fatal("valid account transaction not in the pool")
	}
	if pending, _ := pool.Stats(); pending != 1 {
		t.Fatalf("pending %d, want 1", pending)
	}
	if list := pool.pending[from]; list == nil || list.Len() != 1 {
		t.Fatal("the transaction is not pending under the derived sender")
	}

	// Refused: a bad signature, a wrong chain ID, an intrinsic gas too low.
	for _, tc := range []struct {
		name string
		tx   ghostPoolTx
		want error
	}{
		{"bad signature", ghostPoolTx{nonce: 1, gas: txGas, badSig: true}, types.ErrInvalidSig},
		{"wrong chain ID", ghostPoolTx{nonce: 1, gas: txGas, chainID: big.NewInt(999)}, types.ErrInvalidChainId},
		{"gas one below the intrinsic gas", ghostPoolTx{nonce: 1, gas: txGas - 1}, core.ErrIntrinsicGas},
		{"gas of a type 0x02 transfer", ghostPoolTx{nonce: 1, gas: vars.TxGas}, core.ErrIntrinsicGas},
	} {
		tx := makeGhostPoolTx(t, genesis, key, tc.tx)
		if err := pool.addRemoteSync(tx); !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
		}
		if pool.Get(tx.Hash()) != nil {
			t.Errorf("%s: transaction in the pool", tc.name)
		}
	}

	// The signature is not checked when a cheap check fails: each of these
	// carries a bad signature too, and is refused for the cheap check.
	poor, _, _ := testAccount(2) // no balance
	contract, _, contractAddr := testAccount(3)
	pool.mu.Lock()
	pool.currentState.AddBalance(contractAddr, uint256.NewInt(1_000_000_000_000_000_000))
	pool.currentState.SetCode(contractAddr, []byte{0x00})
	pool.mu.Unlock()
	stale, _, staleAddr := testAccount(4)
	testAddBalance(pool, staleAddr, big.NewInt(1_000_000_000_000_000_000))
	testSetNonce(pool, staleAddr, 5)

	for _, tc := range []struct {
		name string
		key  *mldsa44.PrivateKey
		tx   ghostPoolTx
		want error
	}{
		{"unknown scheme", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, scheme: 0x0003}, types.ErrGhostAccountScheme},
		{"lengths of another scheme", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, scheme: types.GhostSchemeSLHDSA}, types.ErrGhostAccountLength},
		{"wrong chain ID", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, chainID: big.NewInt(999)}, types.ErrInvalidChainId},
		{"intrinsic gas too low", key, ghostPoolTx{nonce: 1, gas: txGas - 1, badSig: true}, core.ErrIntrinsicGas},
		{"code at the sender", contract, ghostPoolTx{nonce: 0, gas: txGas, badSig: true}, core.ErrSenderNoEOA},
		{"nonce too low", stale, ghostPoolTx{nonce: 4, gas: txGas, badSig: true}, core.ErrNonceTooLow},
		{"balance too low", poor, ghostPoolTx{nonce: 0, gas: txGas, badSig: true}, core.ErrInsufficientFunds},
	} {
		tx := makeGhostPoolTx(t, genesis, tc.key, tc.tx)
		err := pool.addRemoteSync(tx)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
		}
		if errors.Is(err, types.ErrInvalidSig) {
			t.Errorf("%s: the signature was checked before the cheap check", tc.name)
		}
	}
	// The same transactions with a good signature where the cheap check
	// passes are admitted: the cases above failed for the cheap check alone.
	if err := pool.addRemoteSync(makeGhostPoolTx(t, genesis, stale, ghostPoolTx{nonce: 5, gas: txGas})); err != nil {
		t.Errorf("stale account at its nonce: %v", err)
	}
	if err := pool.addRemoteSync(makeGhostPoolTx(t, genesis, key, ghostPoolTx{nonce: 1, gas: txGas})); err != nil {
		t.Errorf("next nonce: %v", err)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
}

// withGhostAuth returns tx with its gas limit, scheme, public key and
// signature replaced, without signing it again.
func withGhostAuth(tx *types.Transaction, gas uint64, scheme uint16, pk, sig []byte) *types.Transaction {
	return types.NewTx(&types.GhostAccountTx{
		ChainID:   tx.ChainId(),
		Nonce:     tx.Nonce(),
		GasTipCap: tx.GasTipCap(),
		GasFeeCap: tx.GasFeeCap(),
		Gas:       gas,
		To:        tx.To(),
		Value:     tx.Value(),
		Scheme:    types.GhostScheme(scheme),
		PublicKey: common.CopyBytes(pk),
		Signature: common.CopyBytes(sig),
	})
}

// TestGhostPoolSLHDSA checks that the pool admits an SLH-DSA-SHAKE-128s
// account transaction at its intrinsic gas, the type 0x02 intrinsic gas plus
// 126,240 byte gas plus VERIFY_GAS[0x0002], well under the pool's size cap,
// that it refuses a bad signature and a lower gas limit, and that a key or
// signature of the other scheme is refused for its length and never reaches
// the signature verifier (QS-4).
func TestGhostPoolSLHDSA(t *testing.T) {
	pool, genesis := setupGhostAccountPool(t)
	defer pool.Close()
	counter := newCountingVerify(true)
	useVerifier(pool, counter, ghost.SigFailureCacheSize)

	if ghost.AccountTxVerifyGasSLHDSA == 0 {
		t.Fatal("the verification gas of SLH-DSA-SHAKE-128s is not set")
	}
	slhGas := vars.TxGas + 126_240 + ghost.AccountTxVerifyGasSLHDSA
	if byteGas := ghost.AccountTxSigByteGas * (2 + types.GhostSLHDSAPublicKeySize + types.GhostSLHDSASignatureSize); byteGas != 126_240 {
		t.Fatalf("byte gas %d, want 126,240", byteGas)
	}

	_, key, err := slhdsa.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x52}, 48)), slhdsa.SHAKE_128s)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	from := types.GhostAccountAddressOf(types.GhostSchemeSLHDSA, pub)
	testAddBalance(pool, from, big.NewInt(1_000_000_000_000_000_000))

	chainID := params.TestChainConfig.GetChainID()
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	signer := types.NewGhostAccountSigner(types.LatestSignerForChainID(chainID), genesis)
	valid, err := types.SignGhostAccountTxSLHDSA(signer, &key, &types.GhostAccountTx{
		ChainID:   chainID,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       slhGas,
		To:        &to,
		Value:     big.NewInt(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := valid.GhostAccountAuth()
	if n := 2 + len(pub) + len(sig); n != 7890 {
		t.Fatalf("scheme, key and signature of %d bytes, want 7,890", n)
	}
	if valid.Size() >= txMaxSize {
		t.Fatalf("SLH-DSA transaction of %d bytes, the pool's cap is %d", valid.Size(), txMaxSize)
	}

	// Refused before the signature: a gas limit one below the intrinsic gas
	// and the gas of an ML-DSA-44 transfer, each with a bad signature too.
	badSig := common.CopyBytes(sig)
	badSig[len(badSig)/2] ^= 0x01
	for _, tc := range []struct {
		name string
		gas  uint64
	}{
		{"gas one below the intrinsic gas", slhGas - 1},
		{"gas of an ML-DSA-44 transfer", txGas},
	} {
		tx := withGhostAuth(valid, tc.gas, types.GhostSchemeSLHDSA, pub, badSig)
		if err := pool.addRemoteSync(tx); !errors.Is(err, core.ErrIntrinsicGas) || errors.Is(err, types.ErrInvalidSig) {
			t.Errorf("%s: error %v, want %v", tc.name, err, core.ErrIntrinsicGas)
		}
	}
	// QS-4: the keys and signatures of one scheme under the other.
	mlKey, _, mlFrom := testAccount(1)
	testAddBalance(pool, mlFrom, big.NewInt(1_000_000_000_000_000_000))
	mlTx := makeGhostPoolTx(t, genesis, mlKey, ghostPoolTx{nonce: 0, gas: txGas})
	_, mlPub, mlSig, _ := mlTx.GhostAccountAuth()
	for _, tc := range []struct {
		name   string
		scheme uint16
		pk     []byte
		sig    []byte
		gas    uint64
	}{
		{"ML-DSA-44 key and signature under 0x0002", types.GhostSchemeSLHDSA, mlPub, mlSig, slhGas},
		{"ML-DSA-44 signature under 0x0002", types.GhostSchemeSLHDSA, pub, mlSig, slhGas},
		{"SLH-DSA key and signature under 0x0001", types.GhostSchemeMLDSA44, pub, sig, slhGas},
		{"SLH-DSA signature under 0x0001", types.GhostSchemeMLDSA44, mlPub, sig, slhGas},
	} {
		tx := withGhostAuth(valid, tc.gas, tc.scheme, tc.pk, tc.sig)
		if err := pool.addRemoteSync(tx); !errors.Is(err, types.ErrGhostAccountLength) {
			t.Errorf("%s: error %v, want %v", tc.name, err, types.ErrGhostAccountLength)
		}
	}
	if calls, _, _ := counter.stats(); calls != 0 {
		t.Fatalf("%d signatures verified for transactions refused by a cheap check, want none", calls)
	}

	// A bad signature is verified and refused; the valid transaction is
	// admitted under the derived sender.
	if err := pool.addRemoteSync(withGhostAuth(valid, slhGas, types.GhostSchemeSLHDSA, pub, badSig)); !errors.Is(err, types.ErrInvalidSig) {
		t.Fatalf("bad signature: error %v, want %v", err, types.ErrInvalidSig)
	}
	if !pool.Filter(valid) {
		t.Fatal("the pool does not take SLH-DSA account transactions")
	}
	if err := pool.addRemoteSync(valid); err != nil {
		t.Fatalf("valid SLH-DSA transaction refused: %v", err)
	}
	if list := pool.pending[from]; list == nil || list.Len() != 1 || pool.Get(valid.Hash()) == nil {
		t.Fatal("the SLH-DSA transaction is not pending under the derived sender")
	}
	if calls, _, _ := counter.stats(); calls != 2 {
		t.Fatalf("%d signatures verified, want 2", calls)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
}

// TestGhostAccountTxPoolWithoutGenesis checks that a pool whose chain gives
// no genesis block refuses account transactions.
func TestGhostAccountTxPoolWithoutGenesis(t *testing.T) {
	// The test chain without its genesis block.
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	chain := newTestBlockChain(params.TestChainConfig, 10_000_000, statedb, new(event.Feed))
	chain.genesis = nil
	pool := New(testTxPoolConfig, chain)
	if err := pool.Init(testTxPoolConfig.PriceLimit, chain.CurrentBlock(), makeAddressReserver()); err != nil {
		t.Fatal(err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	key, _, from := testAccount(1)
	testAddBalance(pool, from, big.NewInt(1_000_000_000_000_000_000))
	tx := makeGhostPoolTx(t, testGenesis.Hash(), key, ghostPoolTx{nonce: 0, gas: txGas})
	if pool.Filter(tx) {
		t.Error("the pool takes account transactions without a genesis hash")
	}
	if err := pool.addRemoteSync(tx); !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Errorf("error %v, want %v", err, core.ErrTxTypeNotSupported)
	}
	if err := pool.addRemoteSync(tx); errors.Is(err, txpool.ErrAlreadyKnown) {
		t.Error("the refused transaction was kept")
	}
}
