// Copyright 2020 The go-ethereum Authors
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
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/types/goethereum"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"golang.org/x/crypto/sha3"
)

func u64(val uint64) *uint64 { return &val }

// TestStateProcessorErrors tests the output from the 'core' errors
// as defined in core/error.go. These errors are generated when the
// blockchain imports bad blocks, meaning blocks which have valid headers but
// contain invalid transactions
//
// The transactions are account transactions. Their signatures are hedged, so
// the transaction hashes in the errors are those of the transactions made in
// the test: each want is a format with %s for the hash of the last
// transaction of its block, the one the error is about.
func TestStateProcessorErrors(t *testing.T) {
	var (
		config = &goethereum.ChainConfig{
			ChainID:                       big.NewInt(1),
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
		key1, _, addr1 = testAccount(1)
		key2, _, addr2 = testAccount(2)

		// genesisHash is the genesis of the chain the transactions are
		// signed for, set by each part of the test before it makes them.
		genesisHash common.Hash
	)
	var makeTx = func(key *mldsa44.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
		return signTransfer(config, genesisHash, key, nonce, to, amount, gasLimit, gasPrice, data)
	}
	var mkDynamicTx = func(nonce uint64, to common.Address, gasLimit uint64, gasTipCap, gasFeeCap *big.Int) *types.Transaction {
		return signAccountTx(config, genesisHash, key1, &types.GhostAccountTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     big.NewInt(0),
		})
	}
	var mkDynamicCreationTx = func(nonce uint64, gasLimit uint64, gasTipCap, gasFeeCap *big.Int, data []byte) *types.Transaction {
		return signAccountTx(config, genesisHash, key1, &types.GhostAccountTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			Value:     big.NewInt(0),
			Data:      data,
		})
	}
	// mulGas returns gas * price + value as a decimal string.
	var mulGas = func(gas uint64, price *big.Int, value *big.Int) string {
		cost := new(big.Int).Mul(new(big.Int).SetUint64(gas), price)
		return cost.Add(cost, value).String()
	}
	// The intrinsic gas of a contract creation by account transaction with
	// 320 bytes of init code, under Shanghai.
	initCodeGas, err := IntrinsicGas(make([]byte, 320), nil, true, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	initCodeGas += ghostExtraGas

	{ // Tests against a 'recent' chain definition
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &genesisT.Genesis{
				Config: config,
				Alloc: genesisT.GenesisAlloc{
					addr1: genesisT.GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
					addr2: genesisT.GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   math.MaxUint64,
					},
				},
			}
			blockchain, _  = NewBlockChain(db, nil, gspec, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil, nil)
			tooBigInitCode = make([]byte, vars.MaxInitCodeSize+1)
			oneEther       = big.NewInt(1000000000000000000)
		)

		defer blockchain.Stop()
		genesisHash = blockchain.Genesis().Hash()
		bigNumber := new(big.Int).SetBytes(common.MaxHash.Bytes())
		tooBigNumber := new(big.Int).Set(bigNumber)
		tooBigNumber.Add(tooBigNumber, common.Big1)
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrNonceTooLow
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), accountTransferGas, big.NewInt(875000000), nil),
					makeTx(key1, 0, common.Address{}, big.NewInt(0), accountTransferGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 1 [%s]: nonce too low: address " + addr1.Hex() + ", tx: 0 state: 1",
			},
			{ // ErrNonceTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 100, common.Address{}, big.NewInt(0), accountTransferGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [%s]: nonce too high: address " + addr1.Hex() + ", tx: 100 state: 0",
			},
			{ // ErrNonceMax
				txs: []*types.Transaction{
					makeTx(key2, math.MaxUint64, common.Address{}, big.NewInt(0), accountTransferGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [%s]: nonce has max value: address " + addr2.Hex() + ", nonce: 18446744073709551615",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), 21000000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [%s]: gas limit reached",
			},
			{ // ErrInsufficientFundsForTransfer
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, oneEther, accountTransferGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [%s]: insufficient funds for gas * price + value: address " + addr1.Hex() + " have 1000000000000000000 want " + mulGas(accountTransferGas, big.NewInt(875000000), oneEther),
			},
			{ // ErrInsufficientFunds
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), accountTransferGas, big.NewInt(900000000000000000), nil),
				},
				want: "could not apply tx 0 [%s]: insufficient funds for gas * price + value: address " + addr1.Hex() + " have 1000000000000000000 want " + mulGas(accountTransferGas, big.NewInt(900000000000000000), common.Big0),
			},
			// ErrGasUintOverflow
			// One missing 'core' error is ErrGasUintOverflow: "gas uint64 overflow",
			// In order to trigger that one, we'd have to allocate a _huge_ chunk of data, such that the
			// multiplication len(data) +gas_per_byte overflows uint64. Not testable at the moment
			{ // ErrIntrinsicGas
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), accountTransferGas-1000, big.NewInt(875000000), nil),
				},
				want: fmt.Sprintf("could not apply tx 0 [%%s]: intrinsic gas too low: have %d, want %d", accountTransferGas-1000, accountTransferGas),
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), vars.TxGas*1000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [%s]: gas limit reached",
			},
			{ // ErrFeeCapTooLow
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, accountTransferGas, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [%s]: max fee per gas less than block base fee: address " + addr1.Hex() + ", maxFeePerGas: 0, baseFee: 875000000",
			},
			{ // ErrTipAboveFeeCap
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, accountTransferGas, big.NewInt(2), big.NewInt(1)),
				},
				want: "could not apply tx 0 [%s]: max priority fee per gas higher than max fee per gas: address " + addr1.Hex() + ", maxPriorityFeePerGas: 2, maxFeePerGas: 1",
			},
			{ // ErrInsufficientFunds
				// Available balance:           1000000000000000000
				// Effective cost:              accountTransferGas * (875000000 + 1)
				// FeeCap * gas:                accountTransferGas * 50000000000000
				// This test is designed to have the effective cost be covered by the balance, but
				// the extended requirement on FeeCap*gas < balance to fail
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, accountTransferGas, big.NewInt(1), big.NewInt(50000000000000)),
				},
				want: "could not apply tx 0 [%s]: insufficient funds for gas * price + value: address " + addr1.Hex() + " have 1000000000000000000 want " + mulGas(accountTransferGas, big.NewInt(50000000000000), common.Big0),
			},
			{ // Another ErrInsufficientFunds, this one to ensure that feecap/tip of max u256 is allowed
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, accountTransferGas, bigNumber, bigNumber),
				},
				want: "could not apply tx 0 [%s]: insufficient funds for gas * price + value: address " + addr1.Hex() + " required balance exceeds 256 bits",
			},
			{ // ErrMaxInitCodeSizeExceeded
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, 500000, common.Big0, big.NewInt(vars.InitialBaseFee), tooBigInitCode[:]),
				},
				want: "could not apply tx 0 [%s]: max initcode size exceeded: code size 49153 limit 49152",
			},
			{ // ErrIntrinsicGas: Not enough gas to cover init code
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, initCodeGas-1, common.Big0, big.NewInt(vars.InitialBaseFee), make([]byte, 320)),
				},
				want: fmt.Sprintf("could not apply tx 0 [%%s]: intrinsic gas too low: have %d, want %d", initCodeGas-1, initCodeGas),
			},
		} {
			mem := rawdb.NewMemoryDatabase()
			genesisBlock := MustCommitGenesis(mem, triedb.NewDatabase(mem, nil), gspec)
			block := GenerateBadBlock(genesisBlock, beacon.New(ethash.NewFaker()), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), fmt.Sprintf(tt.want, tt.txs[len(tt.txs)-1].Hash().Hex()); have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}

		// A tip or a fee cap of more than 256 bits: an account transaction
		// with one is refused by the signer, before the state transition's
		// own check. Such a transaction does not decode, so it is applied
		// directly rather than in a block the chain would store as bad.
		for i, tx := range []*types.Transaction{
			mkDynamicTx(0, common.Address{}, accountTransferGas, tooBigNumber, big.NewInt(1)),
			mkDynamicTx(0, common.Address{}, accountTransferGas, big.NewInt(1), tooBigNumber),
		} {
			statedb, err := blockchain.State()
			if err != nil {
				t.Fatal(err)
			}
			header := GenerateBadBlock(blockchain.Genesis(), beacon.New(ethash.NewFaker()), nil, gspec.Config).Header()
			gp := new(GasPool).AddGas(header.GasLimit)
			if _, err := ApplyTransaction(config, blockchain, &header.Coinbase, gp, statedb, header, tx, new(uint64), vm.Config{}); !errors.Is(err, types.ErrGhostAccountField) {
				t.Errorf("field of more than 256 bits %d: error %v, want %v", i, err, types.ErrGhostAccountField)
			}
		}
	}

	// ErrSenderNoEOA, for this we need the sender to have contract code
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &genesisT.Genesis{
				Config: config,
				Alloc: genesisT.GenesisAlloc{
					addr1: genesisT.GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
						Code:    common.FromHex("0xB0B0FACE"),
					},
				},
			}
			mem           = rawdb.NewMemoryDatabase()
			genesis       = MustCommitGenesis(mem, triedb.NewDatabase(mem, nil), gspec)
			blockchain, _ = NewBlockChain(db, nil, gspec, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil, nil)
		)
		defer blockchain.Stop()
		genesisHash = blockchain.Genesis().Hash()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrSenderNoEOA
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, accountTransferGas-1000, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [%s]: sender not an eoa: address " + addr1.Hex() + ", codehash: 0x9280914443471259d4570a8661015ae4a5b80186dbc619658fb494bebc3da3d1",
			},
		} {
			block := GenerateBadBlock(genesis, beacon.New(ethash.NewFaker()), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), fmt.Sprintf(tt.want, tt.txs[len(tt.txs)-1].Hash().Hex()); have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrMaxInitCodeSizeExceeded, for this we need extra Shanghai (EIP-3860) enabled.
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &genesisT.Genesis{
				Config: &goethereum.ChainConfig{
					ChainID:                       big.NewInt(1),
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
					ArrowGlacierBlock:             big.NewInt(0),
					GrayGlacierBlock:              big.NewInt(0),
					MergeNetsplitBlock:            big.NewInt(0),
					TerminalTotalDifficulty:       big.NewInt(0),
					TerminalTotalDifficultyPassed: true,
					ShanghaiTime:                  u64(0),
				},
				Alloc: genesisT.GenesisAlloc{
					addr1: genesisT.GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
				},
			}
			genesis        = MustCommitGenesis(db, triedb.NewDatabase(db, nil), gspec)
			blockchain, _  = NewBlockChain(db, nil, gspec, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil, nil)
			tooBigInitCode = make([]byte, vars.MaxInitCodeSize+1)
			smallInitCode  = [320]byte{}
		)
		defer blockchain.Stop()
		genesisHash = genesis.Hash()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrMaxInitCodeSizeExceeded
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, 500000, common.Big0, eip1559.CalcBaseFee(config, genesis.Header()), tooBigInitCode[:]),
				},
				want: "could not apply tx 0 [%s]: max initcode size exceeded: code size 49153 limit 49152",
			},
			{ // ErrIntrinsicGas: Not enough gas to cover init code
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, initCodeGas-1, common.Big0, eip1559.CalcBaseFee(config, genesis.Header()), smallInitCode[:]),
				},
				want: fmt.Sprintf("could not apply tx 0 [%%s]: intrinsic gas too low: have %d, want %d", initCodeGas-1, initCodeGas),
			},
		} {
			block := GenerateBadBlock(genesis, beacon.New(ethash.NewFaker()), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), fmt.Sprintf(tt.want, tt.txs[len(tt.txs)-1].Hash().Hex()); have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}
}

// GenerateBadBlock constructs a "block" which contains the transactions. The transactions are not expected to be
// valid, and no proper post-state can be made. But from the perspective of the blockchain, the block is sufficiently
// valid to be considered for import:
// - valid pow (fake), ancestry, difficulty, gaslimit etc
func GenerateBadBlock(parent *types.Block, engine consensus.Engine, txs types.Transactions, config ctypes.ChainConfigurator) *types.Block {
	difficulty := big.NewInt(0)
	if !config.GetEthashTerminalTotalDifficultyPassed() {
		fakeChainReader := newChainMaker(nil, config, engine)
		difficulty = engine.CalcDifficulty(fakeChainReader, parent.Time()+10, &types.Header{
			Number:     parent.Number(),
			Time:       parent.Time(),
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		})
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: difficulty,
		GasLimit:   parent.GasLimit(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		Time:       parent.Time() + 10,
		UncleHash:  types.EmptyUncleHash,
	}
	if config.IsEnabled(config.GetEIP1559Transition, header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(config, parent.Header())
	}
	if config.IsEnabledByTime(config.GetEIP4895TransitionTime, &header.Time) || config.IsEnabled(config.GetEIP4895Transition, header.Number) {
		header.WithdrawalsHash = &types.EmptyWithdrawalsHash
	}
	var receipts []*types.Receipt
	// The post-state result doesn't need to be correct (this is a bad block), but we do need something there
	// Preferably something unique. So let's use a combo of blocknum + txhash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(header.Number.Bytes())
	var cumulativeGas uint64
	var nBlobs int
	for _, tx := range txs {
		txh := tx.Hash()
		hasher.Write(txh[:])
		receipt := types.NewReceipt(nil, false, cumulativeGas+tx.Gas())
		receipt.TxHash = tx.Hash()
		receipt.GasUsed = tx.Gas()
		receipts = append(receipts, receipt)
		cumulativeGas += tx.Gas()
		nBlobs += len(tx.BlobHashes())
	}
	header.Root = common.BytesToHash(hasher.Sum(nil))
	isEip4844 := config.IsEnabledByTime(config.GetEIP4844TransitionTime, &header.Time) || config.IsEnabled(config.GetEIP4844Transition, header.Number)
	if isEip4844 {
		var pExcess, pUsed = uint64(0), uint64(0)
		if parent.ExcessBlobGas() != nil {
			pExcess = *parent.ExcessBlobGas()
			pUsed = *parent.BlobGasUsed()
		}
		excess := eip4844.CalcExcessBlobGas(pExcess, pUsed)
		used := uint64(nBlobs * vars.BlobTxBlobGasPerBlob)
		header.ExcessBlobGas = &excess
		header.BlobGasUsed = &used

		beaconRoot := common.HexToHash("0xbeac00")
		header.ParentBeaconRoot = &beaconRoot
	}
	// Assemble and return the final block for sealing
	if config.IsEnabledByTime(config.GetEIP4895TransitionTime, &header.Time) || config.IsEnabled(config.GetEIP4895Transition, header.Number) {
		return types.NewBlockWithWithdrawals(header, txs, nil, receipts, []*types.Withdrawal{}, trie.NewStackTrie(nil))
	}
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
}
