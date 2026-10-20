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

// ghostInitCode deploys the one-byte contract 0x00.
var ghostInitCode = []byte{
	0x60, 0x00, // PUSH1 0
	0x60, 0x00, // PUSH1 0
	0x53,       // MSTORE8
	0x60, 0x01, // PUSH1 1
	0x60, 0x00, // PUSH1 0
	0xf3,       // RETURN
}

func TestGhostAccountTxVerifyGasSet(t *testing.T) {
	if ghost.AccountTxVerifyGasMLDSA44 == 0 || ghost.AccountTxVerifyGas(types.GhostSchemeMLDSA44) == 0 {
		t.Fatal("the verification gas of ML-DSA-44 is not set")
	}
	if ghost.AccountTxVerifyGasMLDSA44%1000 != 0 {
		t.Fatal("the verification gas is not a multiple of 1,000")
	}
	for _, scheme := range []uint16{0x0000, types.GhostSchemeHashBased, 0x0003, 0xffff} {
		if ghost.AccountTxVerifyGas(scheme) != 0 {
			t.Errorf("scheme %#04x has verification gas", scheme)
		}
	}
	tx := types.NewTx(&types.GhostAccountTx{
		ChainID:   big.NewInt(1),
		GasTipCap: new(big.Int),
		GasFeeCap: new(big.Int),
		Value:     new(big.Int),
		Scheme:    types.GhostScheme(types.GhostSchemeMLDSA44),
		PublicKey: make([]byte, types.GhostMLDSA44PublicKeySize),
		Signature: make([]byte, types.GhostMLDSA44SignatureSize),
	})
	if got, err := GhostAccountExtraIntrinsicGas(tx); err != nil || got != ghostExtraGas {
		t.Fatalf("extra intrinsic gas %d %v, want %d", got, err, ghostExtraGas)
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
