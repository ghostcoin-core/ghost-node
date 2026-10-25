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
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
	"github.com/ethereum/go-ethereum/params/vars"
)

func ghostAccountTestConfig() *goethereum.ChainConfig {
	return &goethereum.ChainConfig{
		ChainID:                       big.NewInt(1337),
		HomesteadBlock:                big.NewInt(0),
		EIP150Block:                   big.NewInt(0),
		EIP155Block:                   big.NewInt(0),
		EIP158Block:                   big.NewInt(0),
		ByzantiumBlock:                big.NewInt(0),
		ConstantinopleBlock:           big.NewInt(0),
		PetersburgBlock:               big.NewInt(0),
		IstanbulBlock:                 big.NewInt(0),
		MuirGlacierBlock:              big.NewInt(0),
		BerlinBlock:                   big.NewInt(0),
		LondonBlock:                   big.NewInt(0),
		Ethash:                        new(ctypes.EthashConfig),
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
		ShanghaiTime:                  new(uint64),
		CancunTime:                    new(uint64),
	}
}

func ghostBlockKey(seed byte) *mldsa44.PrivateKey {
	var s [mldsa44.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	_, sk := mldsa44.NewKeyFromSeed(&s)
	return sk
}

// ghostExtraGas is the intrinsic gas an ML-DSA-44 account transaction takes
// on top of the type 0x02 intrinsic gas (spec 09, section 8.1).
var ghostExtraGas uint64 = 16*(2+types.GhostMLDSA44PublicKeySize+types.GhostMLDSA44SignatureSize) + ghost.AccountTxVerifyGasMLDSA44

// ghostSLHDSAExtraGas is the same for an SLH-DSA-SHAKE-128s transaction.
var ghostSLHDSAExtraGas uint64 = 16*(2+types.GhostSLHDSAPublicKeySize+types.GhostSLHDSASignatureSize) + ghost.AccountTxVerifyGasSLHDSA

// ghostInitCode deploys the one-byte contract 0x00.
var ghostInitCode = []byte{
	0x60, 0x00, // PUSH1 0
	0x60, 0x00, // PUSH1 0
	0x53,       // MSTORE8
	0x60, 0x01, // PUSH1 1
	0x60, 0x00, // PUSH1 0
	0xf3, // RETURN
}

func TestGhostAccountTxVerifyGasSet(t *testing.T) {
	if ghost.AccountTxVerifyGasMLDSA44 == 0 || ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44) == 0 {
		t.Fatal("the verification gas of ML-DSA-44 is not set")
	}
	if ghost.AccountTxVerifyGasSLHDSA == 0 || ghost.AccountTxVerifyGas(types.GhostSchemeSLHDSA) != ghost.AccountTxVerifyGasSLHDSA {
		t.Fatal("the verification gas of SLH-DSA-SHAKE-128s is not set")
	}
	if ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44) != ghost.AccountTxVerifyGasMLDSA44 {
		t.Fatal("scheme 0x0001 does not take the verification gas of ML-DSA-44")
	}
	if ghost.AccountTxVerifyGasMLDSA44%1000 != 0 || ghost.AccountTxVerifyGasSLHDSA%1000 != 0 {
		t.Fatal("the verification gas is not a multiple of 1,000")
	}
	for _, scheme := range []uint16{0x0000, 0x0005, 0xffff} {
		if ghost.AccountTxVerifyGas(scheme) != 0 {
			t.Errorf("scheme %#04x has verification gas", scheme)
		}
	}
	// The byte gas of an SLH-DSA transaction: 16 * (2 + 32 + 7,856).
	if ghostSLHDSAExtraGas-ghost.AccountTxVerifyGasSLHDSA != 126_240 {
		t.Fatalf("SLH-DSA byte gas %d, want 126,240", ghostSLHDSAExtraGas-ghost.AccountTxVerifyGasSLHDSA)
	}
	for _, tc := range []struct {
		scheme  uint16
		pubKey  int
		sig     int
		wantGas uint64
	}{
		{types.GhostSchemeMLDSA44, types.GhostMLDSA44PublicKeySize, types.GhostMLDSA44SignatureSize, ghostExtraGas},
		{types.GhostSchemeSLHDSA, types.GhostSLHDSAPublicKeySize, types.GhostSLHDSASignatureSize, ghostSLHDSAExtraGas},
	} {
		tx := types.NewTx(&types.GhostAccountTx{
			ChainID:   big.NewInt(1),
			GasTipCap: new(big.Int),
			GasFeeCap: new(big.Int),
			Value:     new(big.Int),
			Scheme:    types.GhostScheme(tc.scheme),
			PublicKey: make([]byte, tc.pubKey),
			Signature: make([]byte, tc.sig),
		})
		if got, err := GhostAccountExtraIntrinsicGas(tx); err != nil || got != tc.wantGas {
			t.Fatalf("scheme %#04x: extra intrinsic gas %d %v, want %d", tc.scheme, got, err, tc.wantGas)
		}
	}
	if got, err := GhostAccountExtraIntrinsicGas(types.NewTx(&types.DynamicFeeTx{})); err != nil || got != 0 {
		t.Fatalf("extra intrinsic gas of a type 0x02 transaction %d %v, want 0", got, err)
	}
}

func TestGhostAccountTxBlock(t *testing.T) {
	var (
		config    = ghostAccountTestConfig()
		key       = ghostBlockKey(1)
		pk        = key.Public().(*mldsa44.PublicKey).Bytes()
		from      = types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pk)
		recipient = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		contract  = crypto.CreateAddress(from, 1)
		gspec     = &genesisT.Genesis{
			Config: config,
			Alloc: genesisT.GenesisAlloc{
				from: {Balance: big.NewInt(1_000_000_000_000_000_000)},
			},
		}
		engine = beacon.New(ethash.NewFaker())
	)
	if ghost.AccountTxVerifyGasMLDSA44 == 0 {
		t.Fatal("the verification gas of ML-DSA-44 is not set")
	}
	signerFor := func(genesis common.Hash) types.Signer {
		return types.NewGhostAccountSigner(types.LatestSigner(config), genesis)
	}
	sign := func(genesis common.Hash, txdata *types.GhostAccountTx) *types.Transaction {
		tx, err := types.SignGhostAccountTx(signerFor(genesis), key, txdata)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	transferData := func(baseFee *big.Int, gas uint64) *types.GhostAccountTx {
		return &types.GhostAccountTx{
			ChainID:   config.ChainID,
			Nonce:     0,
			GasTipCap: big.NewInt(1),
			GasFeeCap: new(big.Int).Mul(baseFee, big.NewInt(2)),
			Gas:       gas,
			To:        &recipient,
			Value:     big.NewInt(1000),
		}
	}

	// A block with an account transfer and an account contract creation.
	var genesisHash common.Hash
	_, blocks, receipts := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetPoS()
		genesisHash = b.PrevBlock(-1).Hash()
		// The transfer takes exactly its intrinsic gas.
		b.AddTx(sign(genesisHash, transferData(b.BaseFee(), vars.TxGas+ghostExtraGas)))
		b.AddTx(sign(genesisHash, &types.GhostAccountTx{
			ChainID:   config.ChainID,
			Nonce:     1,
			GasTipCap: big.NewInt(1),
			GasFeeCap: new(big.Int).Mul(b.BaseFee(), big.NewInt(2)),
			Gas:       300_000 + ghostExtraGas,
			Value:     new(big.Int),
			Data:      ghostInitCode,
		}))
	})
	if got := receipts[0][0].GasUsed; got != vars.TxGas+ghostExtraGas {
		t.Fatalf("transfer gas used %d, want %d", got, vars.TxGas+ghostExtraGas)
	}

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if chain.Genesis().Hash() != genesisHash {
		t.Fatal("the chain's genesis differs from the generated one")
	}
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d not imported: %v", n, err)
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient).Uint64(); got != 1000 {
		t.Errorf("recipient balance %d, want 1000", got)
	}
	if got := statedb.GetNonce(from); got != 2 {
		t.Errorf("sender nonce %d, want 2", got)
	}
	if code := statedb.GetCode(contract); !bytes.Equal(code, []byte{0x00}) {
		t.Errorf("contract code %x, want 00", code)
	}
	stored := chain.GetReceiptsByHash(blocks[0].Hash())
	if len(stored) != 2 {
		t.Fatalf("%d receipts, want 2", len(stored))
	}
	for i, r := range stored {
		if r.Type != types.GhostAccountTxType || r.Status != types.ReceiptStatusSuccessful {
			t.Errorf("receipt %d: type %#x status %d", i, r.Type, r.Status)
		}
	}
	if stored[1].ContractAddress != contract {
		t.Errorf("contract address %v, want %v", stored[1].ContractAddress, contract)
	}

	// Blocks made invalid by one account transaction.
	signed := sign(genesisHash, transferData(blocks[0].BaseFee(), vars.TxGas+ghostExtraGas))
	_, pubKey, sig, _ := signed.GhostAccountAuth()
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x01
	withSig := types.NewTx(&types.GhostAccountTx{
		ChainID:   signed.ChainId(),
		Nonce:     signed.Nonce(),
		GasTipCap: signed.GasTipCap(),
		GasFeeCap: signed.GasFeeCap(),
		Gas:       signed.Gas(),
		To:        signed.To(),
		Value:     signed.Value(),
		Scheme:    types.GhostScheme(types.GhostSchemeMLDSA44),
		PublicKey: pubKey,
		Signature: badSig,
	})
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"bad signature", withSig, types.ErrInvalidSig},
		{"signed for another genesis", sign(common.HexToHash("0x01"), transferData(blocks[0].BaseFee(), vars.TxGas+ghostExtraGas)), types.ErrInvalidSig},
		{"gas below the intrinsic gas", sign(genesisHash, transferData(blocks[0].BaseFee(), vars.TxGas+ghostExtraGas-1)), ErrIntrinsicGas},
	} {
		chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		bad := GenerateBadBlock(chain.Genesis(), engine, types.Transactions{tc.tx}, config)
		if _, err := chain.InsertChain(types.Blocks{bad}); !errors.Is(err, tc.want) {
			t.Errorf("%s: import error %v, want %v", tc.name, err, tc.want)
		}
		if chain.CurrentBlock().Number.Sign() != 0 {
			t.Errorf("%s: the invalid block became the head", tc.name)
		}
		chain.Stop()
	}

	// The same transfer, correctly signed, is valid in that position.
	chain2, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain2.Stop()
	statedb2, _ := chain2.State()
	gp := new(GasPool).AddGas(blocks[0].GasLimit())
	header := types.CopyHeader(blocks[0].Header())
	header.GasUsed = 0
	if _, err := ApplyTransaction(config, chain2, &header.Coinbase, gp, statedb2, header, signed, &header.GasUsed, vm.Config{}); err != nil {
		t.Fatalf("correctly signed transfer not applied: %v", err)
	}
	// Without the chain there is no genesis hash: the transaction is refused.
	statedb3, _ := chain2.State()
	if _, err := ApplyTransaction(config, nil, &header.Coinbase, new(GasPool).AddGas(blocks[0].GasLimit()), statedb3, header, signed, new(uint64), vm.Config{}); !errors.Is(err, types.ErrGhostAccountGenesis) {
		t.Fatalf("applied without a genesis hash: %v", err)
	}
}

// TestGhostAccountTxSLHDSABlock checks that an SLH-DSA-SHAKE-128s transfer
// taking exactly its intrinsic gas, the type 0x02 intrinsic gas plus 126,240
// byte gas plus VERIFY_GAS[0x0002], is valid in a block, and that one with a
// gas limit one below it is not.
func TestGhostAccountTxSLHDSABlock(t *testing.T) {
	_, key, err := slhdsa.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 48)), slhdsa.SHAKE_128s)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var (
		config    = ghostAccountTestConfig()
		from      = types.GhostAccountAddressOf(types.GhostSchemeSLHDSA, pub)
		recipient = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		gspec     = &genesisT.Genesis{
			Config: config,
			Alloc: genesisT.GenesisAlloc{
				from: {Balance: big.NewInt(1_000_000_000_000_000_000)},
			},
		}
		engine     = beacon.New(ethash.NewFaker())
		intrinsic  = vars.TxGas + ghostSLHDSAExtraGas
		transferTx = func(genesis common.Hash, baseFee *big.Int, gas uint64) *types.Transaction {
			signer := types.NewGhostAccountSigner(types.LatestSigner(config), genesis)
			tx, err := types.SignGhostAccountTxSLHDSA(signer, &key, &types.GhostAccountTx{
				ChainID:   config.ChainID,
				GasTipCap: big.NewInt(1),
				GasFeeCap: new(big.Int).Mul(baseFee, big.NewInt(2)),
				Gas:       gas,
				To:        &recipient,
				Value:     big.NewInt(1000),
			})
			if err != nil {
				t.Fatal(err)
			}
			return tx
		}
	)
	if intrinsic != vars.TxGas+126_240+ghost.AccountTxVerifyGasSLHDSA {
		t.Fatalf("intrinsic gas %d", intrinsic)
	}
	var genesisHash common.Hash
	_, blocks, receipts := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetPoS()
		genesisHash = b.PrevBlock(-1).Hash()
		b.AddTx(transferTx(genesisHash, b.BaseFee(), intrinsic))
	})
	if got := receipts[0][0].GasUsed; got != intrinsic {
		t.Fatalf("transfer gas used %d, want %d", got, intrinsic)
	}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d not imported: %v", n, err)
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient).Uint64(); got != 1000 {
		t.Errorf("recipient balance %d, want 1000", got)
	}
	if got := statedb.GetNonce(from); got != 1 {
		t.Errorf("sender nonce %d, want 1", got)
	}

	chain2, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain2.Stop()
	bad := GenerateBadBlock(chain2.Genesis(), engine, types.Transactions{transferTx(genesisHash, blocks[0].BaseFee(), intrinsic-1)}, config)
	if _, err := chain2.InsertChain(types.Blocks{bad}); !errors.Is(err, ErrIntrinsicGas) {
		t.Errorf("gas one below the intrinsic gas: import error %v, want %v", err, ErrIntrinsicGas)
	}
}

// The intrinsic gas the rescue schemes take on top of the type 0x02
// intrinsic gas (spec 09, section 8.1): 16 * (2 + 1,344 + 2,420) + 3,000 for
// 0x0003 and 16 * (2 + 1,344 + 7,856) + 12,000 for 0x0004.
const (
	ghostRescueExtraGas       uint64 = 63_256
	ghostRescueSLHDSAExtraGas uint64 = 159_232
)

// ghostRescueFeeCap is the fee cap of the rescue test transactions, well
// above the base fee of the test blocks.
var ghostRescueFeeCap = big.NewInt(10_000_000_000)

// ghostRescueBlockKeys returns the ML-DSA-44 and SLH-DSA-SHAKE-128s keys of
// a rescue-key account made from seed, and the account's public key.
func ghostRescueBlockKeys(t *testing.T, seed byte) (*mldsa44.PrivateKey, *slhdsa.PrivateKey, []byte) {
	t.Helper()
	mlKey := ghostBlockKey(seed)
	_, slhKey, err := slhdsa.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{seed}, 48)), slhdsa.SHAKE_128s)
	if err != nil {
		t.Fatal(err)
	}
	slhPub, err := slhKey.PublicKey().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return mlKey, &slhKey, types.GhostRescuePublicKey(mlKey.Public().(*mldsa44.PublicKey).Bytes(), slhPub)
}

// ghostRescueTransfer is a transfer of value from a rescue account.
func ghostRescueTransfer(config *goethereum.ChainConfig, nonce, gas uint64, to common.Address, value int64) *types.GhostAccountTx {
	return &types.GhostAccountTx{
		ChainID:   config.ChainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(1),
		GasFeeCap: ghostRescueFeeCap,
		Gas:       gas,
		To:        &to,
		Value:     big.NewInt(value),
	}
}

// ghostSignRescue signs txdata as scheme 0x0003 with the ML-DSA-44 half of
// the account of pk.
func ghostSignRescue(t *testing.T, signer types.Signer, mlKey *mldsa44.PrivateKey, pk []byte, txdata *types.GhostAccountTx) *types.Transaction {
	t.Helper()
	tx, err := types.SignGhostAccountTxRescue(signer, mlKey, pk[types.GhostMLDSA44PublicKeySize:], txdata)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// ghostSignRescueSLHDSA signs txdata as scheme 0x0004 with the SLH-DSA half
// of the account of pk.
func ghostSignRescueSLHDSA(t *testing.T, signer types.Signer, slhKey *slhdsa.PrivateKey, pk []byte, txdata *types.GhostAccountTx) *types.Transaction {
	t.Helper()
	tx, err := types.SignGhostAccountTxRescueSLHDSA(signer, pk[:types.GhostMLDSA44PublicKeySize], slhKey, txdata)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestGhostRescueTxBlock checks rescue-key accounts in a block: a 0x0003 and
// a 0x0004 transfer of one account share its nonce and balance and bill the
// pinned intrinsic gas, and a 0x0004 transfer of an account whose ML-DSA-44
// half is 1,312 zero bytes, a key no one can sign for, moves funds: 0x0004
// never depends on the ML-DSA-44 half.
func TestGhostRescueTxBlock(t *testing.T) {
	if h, ok := ghost.MLRescueHeight(); ok {
		t.Fatalf("ML_RESCUE_HEIGHT is set to %d", h)
	}
	mlKey, slhKey, pk := ghostRescueBlockKeys(t, 3)
	_, zeroSLHKey, zeroSLHPk := ghostRescueBlockKeys(t, 4)
	zeroPk := types.GhostRescuePublicKey(make([]byte, types.GhostMLDSA44PublicKeySize), zeroSLHPk[types.GhostMLDSA44PublicKeySize:])
	const initial = 1_000_000_000_000_000_000
	var (
		config    = ghostAccountTestConfig()
		from      = types.GhostAccountAddressOf(types.GhostSchemeMLDSA44Rescue, pk)
		zeroFrom  = types.GhostAccountAddressOf(types.GhostSchemeSLHDSARescue, zeroPk)
		recipient = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		gspec     = &genesisT.Genesis{
			Config: config,
			Alloc: genesisT.GenesisAlloc{
				from:     {Balance: big.NewInt(initial)},
				zeroFrom: {Balance: big.NewInt(initial)},
			},
		}
		engine = beacon.New(ethash.NewFaker())
		gas3   = vars.TxGas + ghostRescueExtraGas
		gas4   = vars.TxGas + ghostRescueSLHDSAExtraGas
	)
	if from == zeroFrom || from == types.GhostAccountAddressOf(types.GhostSchemeMLDSA44, pk[:types.GhostMLDSA44PublicKeySize]) {
		t.Fatal("the test accounts are not distinct")
	}
	var genesisHash common.Hash
	var txs []*types.Transaction
	_, blocks, receipts := GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *BlockGen) {
		b.SetPoS()
		genesisHash = b.PrevBlock(-1).Hash()
		signer := types.NewGhostAccountSigner(types.LatestSigner(config), genesisHash)
		txs = []*types.Transaction{
			ghostSignRescue(t, signer, mlKey, pk, ghostRescueTransfer(config, 0, gas3, recipient, 1000)),
			ghostSignRescueSLHDSA(t, signer, slhKey, pk, ghostRescueTransfer(config, 1, gas4, recipient, 2000)),
			ghostSignRescueSLHDSA(t, signer, zeroSLHKey, zeroPk, ghostRescueTransfer(config, 0, gas4, recipient, 4000)),
		}
		for _, tx := range txs {
			b.AddTx(tx)
		}
	})
	// The pinned intrinsic gas, billed exactly.
	if ghostRescueExtraGas != 16*(2+types.GhostRescuePublicKeySize+types.GhostMLDSA44SignatureSize)+ghost.AccountTxVerifyGasMLDSA44 ||
		ghostRescueSLHDSAExtraGas != 16*(2+types.GhostRescuePublicKeySize+types.GhostSLHDSASignatureSize)+ghost.AccountTxVerifyGasSLHDSA {
		t.Fatal("the pinned rescue gas is not the formula of spec 09, section 8.1")
	}
	for i, want := range []uint64{ghostRescueExtraGas, ghostRescueSLHDSAExtraGas, ghostRescueSLHDSAExtraGas} {
		if got, err := GhostAccountExtraIntrinsicGas(txs[i]); err != nil || got != want {
			t.Fatalf("transaction %d: extra intrinsic gas %d %v, want %d", i, got, err, want)
		}
	}
	for i, want := range []uint64{gas3, gas4, gas4} {
		if got := receipts[0][i].GasUsed; got != want {
			t.Fatalf("transaction %d: gas used %d, want %d", i, got, want)
		}
	}

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d not imported: %v", n, err)
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetBalance(recipient).Uint64(); got != 7000 {
		t.Errorf("recipient balance %d, want 7000", got)
	}
	price := new(big.Int).Add(blocks[0].BaseFee(), big.NewInt(1))
	spent := func(gas uint64, value int64) *big.Int {
		return new(big.Int).Add(new(big.Int).Mul(new(big.Int).SetUint64(gas), price), big.NewInt(value))
	}
	wantFrom := new(big.Int).Sub(big.NewInt(initial), spent(gas3, 1000))
	wantFrom.Sub(wantFrom, spent(gas4, 2000))
	if got := statedb.GetBalance(from).ToBig(); got.Cmp(wantFrom) != 0 {
		t.Errorf("rescue account balance %v, want %v: both schemes pay from one balance", got, wantFrom)
	}
	if got := statedb.GetNonce(from); got != 2 {
		t.Errorf("rescue account nonce %d, want 2: both schemes share one nonce", got)
	}
	wantZero := new(big.Int).Sub(big.NewInt(initial), spent(gas4, 4000))
	if got := statedb.GetBalance(zeroFrom).ToBig(); got.Cmp(wantZero) != 0 {
		t.Errorf("zero ML-DSA half account balance %v, want %v", got, wantZero)
	}
	if got := statedb.GetNonce(zeroFrom); got != 1 {
		t.Errorf("zero ML-DSA half account nonce %d, want 1", got)
	}
	for i, r := range chain.GetReceiptsByHash(blocks[0].Hash()) {
		if r.Type != types.GhostAccountTxType || r.Status != types.ReceiptStatusSuccessful {
			t.Errorf("receipt %d: type %#x status %d", i, r.Type, r.Status)
		}
	}
	// One gas below the pinned intrinsic gas is refused.
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
	}{
		{"0x0003", ghostSignRescue(t, types.NewGhostAccountSigner(types.LatestSigner(config), genesisHash), mlKey, pk, ghostRescueTransfer(config, 0, gas3-1, recipient, 1000))},
		{"0x0004", ghostSignRescueSLHDSA(t, types.NewGhostAccountSigner(types.LatestSigner(config), genesisHash), slhKey, pk, ghostRescueTransfer(config, 0, gas4-1, recipient, 1000))},
	} {
		chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		bad := GenerateBadBlock(chain.Genesis(), engine, types.Transactions{tc.tx}, config)
		if _, err := chain.InsertChain(types.Blocks{bad}); !errors.Is(err, ErrIntrinsicGas) {
			t.Errorf("%s one gas below the intrinsic gas: import error %v, want %v", tc.name, err, ErrIntrinsicGas)
		}
		chain.Stop()
	}
}

// TestGhostRescueSunsetBlock checks ML_RESCUE_HEIGHT H in blocks: a block of
// height H-1 holding a 0x0003 transaction is valid, blocks at H and H+1
// holding one are invalid, and 0x0004 transactions of the same account stay
// valid at H and after.
func TestGhostRescueSunsetBlock(t *testing.T) {
	const height = 3
	h := uint64(height)
	defer ghost.SetMLRescueHeight(&h)()

	mlKey, slhKey, pk := ghostRescueBlockKeys(t, 5)
	var (
		config    = ghostAccountTestConfig()
		from      = types.GhostAccountAddressOf(types.GhostSchemeMLDSA44Rescue, pk)
		recipient = common.HexToAddress("0x00000000000000000000000000000000000000bb")
		gspec     = &genesisT.Genesis{
			Config: config,
			Alloc: genesisT.GenesisAlloc{
				from: {Balance: big.NewInt(1_000_000_000_000_000_000)},
			},
		}
		engine = beacon.New(ethash.NewFaker())
		gas3   = vars.TxGas + ghostRescueExtraGas
		gas4   = vars.TxGas + ghostRescueSLHDSAExtraGas
	)
	var signer types.Signer
	// Block 1 is empty, block H-1 holds 0x0003 (nonce 0), blocks H and H+1
	// hold 0x0004 (nonces 1 and 2).
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, height+1, func(i int, b *BlockGen) {
		b.SetPoS()
		if signer == nil {
			signer = types.NewGhostAccountSigner(types.LatestSigner(config), b.PrevBlock(-1).Hash())
		}
		switch b.Number().Uint64() {
		case height - 1:
			b.AddTx(ghostSignRescue(t, signer, mlKey, pk, ghostRescueTransfer(config, 0, gas3, recipient, 1000)))
		case height:
			b.AddTx(ghostSignRescueSLHDSA(t, signer, slhKey, pk, ghostRescueTransfer(config, 1, gas4, recipient, 1000)))
		case height + 1:
			b.AddTx(ghostSignRescueSLHDSA(t, signer, slhKey, pk, ghostRescueTransfer(config, 2, gas4, recipient, 1000)))
		}
	})
	if blocks[height-2].NumberU64() != height-1 || len(blocks[height-2].Transactions()) != 1 {
		t.Fatalf("block %d does not hold the 0x0003 transaction", height-1)
	}

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d not imported: %v", n+1, err)
	}
	statedb, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := statedb.GetNonce(from); got != 3 {
		t.Errorf("sender nonce %d, want 3", got)
	}
	if got := statedb.GetBalance(recipient).Uint64(); got != 3000 {
		t.Errorf("recipient balance %d, want 3000", got)
	}

	// A 0x0003 transaction in a block at H, and at H+1, makes it invalid.
	for _, number := range []uint64{height, height + 1} {
		parents := blocks[:number-1]
		nonce := number - 2 // the next nonce after the parent's transactions
		tx := ghostSignRescue(t, signer, mlKey, pk, ghostRescueTransfer(config, nonce, gas3, recipient, 1000))
		chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, nil, engine, vm.Config{}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := chain.InsertChain(parents); err != nil {
			t.Fatalf("parent block %d not imported: %v", n, err)
		}
		parent := parents[len(parents)-1]
		bad := GenerateBadBlock(parent, engine, types.Transactions{tx}, config)
		if bad.NumberU64() != number {
			t.Fatalf("bad block at %d, want %d", bad.NumberU64(), number)
		}
		if _, err := chain.InsertChain(types.Blocks{bad}); !errors.Is(err, ErrGhostAccountSunset) {
			t.Errorf("0x0003 in block %d (H = %d): import error %v, want %v", number, height, err, ErrGhostAccountSunset)
		}
		if chain.CurrentBlock().Number.Uint64() != parent.NumberU64() {
			t.Errorf("block %d: the invalid block became the head", number)
		}
		// The same transaction applies one block before H.
		statedb, _ := chain.State()
		header := types.CopyHeader(bad.Header())
		header.Number = new(big.Int).SetUint64(height - 1)
		header.GasUsed = 0
		if number == height {
			if _, err := ApplyTransaction(config, chain, &header.Coinbase, new(GasPool).AddGas(header.GasLimit), statedb, header, tx, &header.GasUsed, vm.Config{}); err != nil {
				t.Errorf("0x0003 in a block of height %d: %v", height-1, err)
			}
		}
		chain.Stop()
	}
}
