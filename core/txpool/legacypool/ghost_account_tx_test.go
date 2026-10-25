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
	"github.com/ethereum/go-ethereum/trie"
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
		{"unknown scheme", key, ghostPoolTx{nonce: 1, gas: txGas, badSig: true, scheme: 0x0005}, types.ErrGhostAccountScheme},
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

// ghostRescueAccount is a rescue-key account of the pool tests.
type ghostRescueAccount struct {
	mlKey  *mldsa44.PrivateKey
	slhKey *slhdsa.PrivateKey
	pk     []byte
	from   common.Address
}

// newGhostRescueAccount returns the rescue-key account made from seed,
// funded in the pool's state.
func newGhostRescueAccount(t *testing.T, pool *LegacyPool, seed byte) *ghostRescueAccount {
	t.Helper()
	mlKey, mlPub, _ := testAccount(seed)
	_, slhKey, err := slhdsa.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 48)), slhdsa.SHAKE_128s)
	if err != nil {
		t.Fatal(err)
	}
	slhPub, err := slhKey.PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pk := types.GhostRescuePublicKey(mlPub, slhPub)
	acc := &ghostRescueAccount{mlKey: mlKey, slhKey: &slhKey, pk: pk, from: types.GhostAccountAddressOf(types.GhostSchemeMLDSA44Rescue, pk)}
	testAddBalance(pool, acc.from, big.NewInt(1_000_000_000_000_000_000))
	return acc
}

// tx signs a transfer of the account under scheme 0x0003 or 0x0004, at the
// scheme's intrinsic gas, with a fee cap and tip of price.
func (a *ghostRescueAccount) tx(t *testing.T, genesis common.Hash, scheme uint16, nonce uint64, price int64) *types.Transaction {
	t.Helper()
	chainID := params.TestChainConfig.GetChainID()
	signer := types.NewGhostAccountSigner(types.LatestSignerForChainID(chainID), genesis)
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	sigSize := types.GhostMLDSA44SignatureSize
	if scheme == types.GhostSchemeSLHDSARescue {
		sigSize = types.GhostSLHDSASignatureSize
	}
	txdata := &types.GhostAccountTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(price),
		GasFeeCap: big.NewInt(price),
		Gas:       vars.TxGas + ghost.AccountTxSigByteGas*uint64(2+types.GhostRescuePublicKeySize+sigSize) + ghost.AccountTxVerifyGas(scheme),
		To:        &to,
		Value:     big.NewInt(100),
	}
	var (
		tx  *types.Transaction
		err error
	)
	switch scheme {
	case types.GhostSchemeMLDSA44Rescue:
		tx, err = types.SignGhostAccountTxRescue(signer, a.mlKey, a.pk[types.GhostMLDSA44PublicKeySize:], txdata)
	case types.GhostSchemeSLHDSARescue:
		tx, err = types.SignGhostAccountTxRescueSLHDSA(signer, a.pk[:types.GhostMLDSA44PublicKeySize], a.slhKey, txdata)
	default:
		t.Fatalf("scheme %#04x is no rescue scheme", scheme)
	}
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// ghostPoolHead is a head of the given number for a pool reset.
func ghostPoolHead(number uint64, parent common.Hash, extra string) *types.Header {
	return &types.Header{
		ParentHash: parent,
		Number:     new(big.Int).SetUint64(number),
		GasLimit:   10_000_000,
		BaseFee:    big.NewInt(1),
		Extra:      []byte(extra),
	}
}

// ghostReorgChain is the test chain with the blocks of a reorganisation.
type ghostReorgChain struct {
	*testBlockChain
	blocks map[common.Hash]*types.Block
}

func (c *ghostReorgChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	if b := c.blocks[hash]; b != nil && b.NumberU64() == number {
		return b
	}
	return nil
}

// TestGhostPoolRescueSunset checks ML_RESCUE_HEIGHT H in the pool: a 0x0003
// transaction is accepted while the next block is below H and refused, with
// no signature check, once it is at H or after; the pending and queued 0x0003
// transactions are dropped when the head reaches H-1, those a
// reorganisation puts back included; 0x0004 transactions stay, and a 0x0004
// transaction replaces a 0x0003 one at its nonce before H.
func TestGhostPoolRescueSunset(t *testing.T) {
	t.Run("reorganisation", testGhostPoolRescueSunsetReorg)

	const height = 10
	h := uint64(height)
	defer ghost.SetMLRescueHeight(&h)()

	pool, genesis := setupGhostAccountPool(t)
	defer pool.Close()
	counter := newCountingVerify(true)
	useVerifier(pool, counter, ghost.SigFailureCacheSize)
	a := newGhostRescueAccount(t, pool, 0x31)
	b := newGhostRescueAccount(t, pool, 0x32)
	const (
		mlRescue  = types.GhostSchemeMLDSA44Rescue
		slhRescue = types.GhostSchemeSLHDSARescue
	)

	// Head 0: a 0x0003 and a 0x0004 transaction of one account are pending.
	a0 := a.tx(t, genesis, mlRescue, 0, 1)
	a1 := a.tx(t, genesis, slhRescue, 1, 1)
	for _, tx := range []*types.Transaction{a0, a1} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("nonce %d refused: %v", tx.Nonce(), err)
		}
	}
	// A 0x0004 transaction replaces a 0x0003 one at its nonce.
	b0 := b.tx(t, genesis, mlRescue, 0, 1)
	if err := pool.addRemoteSync(b0); err != nil {
		t.Fatalf("0x0003 refused: %v", err)
	}
	b0r := b.tx(t, genesis, slhRescue, 0, 2)
	if err := pool.addRemoteSync(b0r); err != nil {
		t.Fatalf("0x0004 replacement refused: %v", err)
	}
	if pool.Get(b0.Hash()) != nil || pool.Get(b0r.Hash()) == nil {
		t.Fatal("the 0x0004 transaction did not replace the 0x0003 one")
	}

	// Head H-2, next block H-1: 0x0003 is still accepted, and nothing is
	// dropped. Nonce 3 is queued behind the gap at nonce 2.
	<-pool.requestReset(nil, ghostPoolHead(height-2, common.Hash{}, ""))
	a3 := a.tx(t, genesis, mlRescue, 3, 1)
	if err := pool.addRemoteSync(a3); err != nil {
		t.Fatalf("0x0003 with the next block at H-1 refused: %v", err)
	}
	for _, tx := range []*types.Transaction{a0, a1, a3, b0r} {
		if pool.Get(tx.Hash()) == nil {
			t.Fatalf("nonce %d dropped before the sunset", tx.Nonce())
		}
	}
	if pending, queued := pool.Stats(); pending != 3 || queued != 1 {
		t.Fatalf("pending %d queued %d, want 3 and 1", pending, queued)
	}

	// Head H-1, next block H: the pending and the queued 0x0003
	// transactions are dropped, the 0x0004 ones stay.
	<-pool.requestReset(nil, ghostPoolHead(height-1, common.Hash{}, ""))
	for _, tx := range []*types.Transaction{a0, a3} {
		if pool.Get(tx.Hash()) != nil {
			t.Errorf("0x0003 nonce %d still in the pool with the next block at H", tx.Nonce())
		}
	}
	for _, tx := range []*types.Transaction{a1, b0r} {
		if pool.Get(tx.Hash()) == nil {
			t.Errorf("0x0004 nonce %d dropped at the sunset", tx.Nonce())
		}
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}

	// Next block H, then H+1: 0x0003 is refused before any signature check,
	// a bad signature included; 0x0004 is accepted.
	for _, head := range []uint64{height - 1, height} {
		<-pool.requestReset(nil, ghostPoolHead(head, common.Hash{}, ""))
		calls, _, _ := counter.stats()
		good := a.tx(t, genesis, mlRescue, 0, 1)
		_, pk, sig, _ := good.GhostAccountAuth()
		sig[0] ^= 1
		for name, tx := range map[string]*types.Transaction{"valid": good, "bad signature": withGhostAuth(good, good.Gas(), mlRescue, pk, sig)} {
			err := pool.addRemoteSync(tx)
			if !errors.Is(err, core.ErrGhostAccountSunset) || errors.Is(err, types.ErrInvalidSig) {
				t.Errorf("next block %d, %s 0x0003: error %v, want %v", head+1, name, err, core.ErrGhostAccountSunset)
			}
			if pool.Get(tx.Hash()) != nil {
				t.Errorf("next block %d, %s 0x0003: in the pool", head+1, name)
			}
		}
		if after, _, _ := counter.stats(); after != calls {
			t.Errorf("next block %d: %d signatures verified for refused 0x0003 transactions, want none", head+1, after-calls)
		}
	}
	a0slh := a.tx(t, genesis, slhRescue, 0, 1)
	if err := pool.addRemoteSync(a0slh); err != nil {
		t.Fatalf("0x0004 after H refused: %v", err)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
}

// testGhostPoolRescueSunsetReorg is the reorganisation part of
// TestGhostPoolRescueSunset: a 0x0003 transaction of a block a
// reorganisation drops goes back into the pool, unless the new head is at
// H-1 or above, and a pending 0x0003 transaction is dropped by the same
// reorganisation.
func testGhostPoolRescueSunsetReorg(t *testing.T) {
	const height = 10
	for _, sunset := range []bool{false, true} {
		var restore func()
		if sunset {
			h := uint64(height)
			restore = ghost.SetMLRescueHeight(&h)
		} else {
			restore = ghost.SetMLRescueHeight(nil)
		}
		statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		chain := &ghostReorgChain{newTestBlockChain(params.TestChainConfig, 10_000_000, statedb, new(event.Feed)), map[common.Hash]*types.Block{}}
		pool := New(testTxPoolConfig, chain)
		if err := pool.Init(testTxPoolConfig.PriceLimit, chain.CurrentBlock(), makeAddressReserver()); err != nil {
			t.Fatal(err)
		}
		<-pool.initDoneCh
		genesis := testGenesis.Hash()
		a := newGhostRescueAccount(t, pool, 0x33)
		b := newGhostRescueAccount(t, pool, 0x34)

		// The old chain holds a's 0x0003 nonce 0 at H-2; the new chain, from
		// the same block at H-3, reaches H-1 without it.
		reorged := a.tx(t, genesis, types.GhostSchemeMLDSA44Rescue, 0, 1)
		ancestor := types.NewBlock(ghostPoolHead(height-3, common.Hash{}, "ancestor"), nil, nil, nil, trie.NewStackTrie(nil))
		old := types.NewBlock(ghostPoolHead(height-2, ancestor.Hash(), "old"), []*types.Transaction{reorged}, nil, nil, trie.NewStackTrie(nil))
		new1 := types.NewBlock(ghostPoolHead(height-2, ancestor.Hash(), "new"), nil, nil, nil, trie.NewStackTrie(nil))
		new2 := types.NewBlock(ghostPoolHead(height-1, new1.Hash(), "new"), nil, nil, nil, trie.NewStackTrie(nil))
		for _, blk := range []*types.Block{ancestor, old, new1, new2} {
			chain.blocks[blk.Hash()] = blk
		}
		<-pool.requestReset(nil, old.Header())

		// In the pool at the old head: a's 0x0004 nonce 1, queued behind the
		// reorged nonce, and b's 0x0003 and 0x0004 nonces 0 and 1.
		a1 := a.tx(t, genesis, types.GhostSchemeSLHDSARescue, 1, 1)
		b0 := b.tx(t, genesis, types.GhostSchemeMLDSA44Rescue, 0, 1)
		b1 := b.tx(t, genesis, types.GhostSchemeSLHDSARescue, 1, 1)
		for _, tx := range []*types.Transaction{a1, b0, b1} {
			if err := pool.addRemoteSync(tx); err != nil {
				t.Fatalf("sunset %v: nonce %d refused: %v", sunset, tx.Nonce(), err)
			}
		}
		<-pool.requestReset(old.Header(), new2.Header())

		if got := pool.Get(reorged.Hash()) != nil; got == sunset {
			t.Errorf("sunset %v: the reorged 0x0003 transaction in the pool: %v", sunset, got)
		}
		if got := pool.Get(b0.Hash()) != nil; got == sunset {
			t.Errorf("sunset %v: the pending 0x0003 transaction in the pool: %v", sunset, got)
		}
		for _, tx := range []*types.Transaction{a1, b1} {
			if pool.Get(tx.Hash()) == nil {
				t.Errorf("sunset %v: 0x0004 nonce %d dropped by the reorganisation", sunset, tx.Nonce())
			}
		}
		if err := validatePoolInternals(pool); err != nil {
			t.Fatalf("sunset %v: %v", sunset, err)
		}
		pool.Close()
		restore()
	}
}
