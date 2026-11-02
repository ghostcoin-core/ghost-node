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
	"errors"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

// frozenPolicyRuntime is the policy of these tests: it returns its first
// calldata word.
var frozenPolicyRuntime = []byte{
	byte(vm.PUSH1), 0, byte(vm.CALLDATALOAD), byte(vm.PUSH1), 0, byte(vm.MSTORE),
	byte(vm.PUSH1), 32, byte(vm.PUSH1), 0, byte(vm.RETURN),
}

// policyDeployCode returns init code that stores runtime as the code.
func policyDeployCode(runtime []byte) []byte {
	n := len(runtime)
	return append([]byte{
		byte(vm.PUSH2), byte(n >> 8), byte(n),
		byte(vm.PUSH2), 0, 15,
		byte(vm.PUSH1), 0, byte(vm.CODECOPY),
		byte(vm.PUSH2), byte(n >> 8), byte(n),
		byte(vm.PUSH1), 0, byte(vm.RETURN),
	}, runtime...)
}

// policyTestSetup is a chain on the internal network's configuration, an
// account that block 1 pays, and the policy the factory creates from
// frozenPolicyRuntime with salt 1.
type policyTestSetup struct {
	gspec    *genesisT.Genesis
	config   ctypes.ChainConfigurator
	engine   *ethash.Ethash
	key      *mldsa44.PrivateKey
	account  common.Address
	initCode []byte
	salt     common.Hash
	policy   common.Address
	tip      *big.Int
}

func newPolicyTestSetup() *policyTestSetup {
	key, _, account := testAccount(0xb7)
	gspec := ghost.InternalNetGenesis()
	initCode := policyDeployCode(frozenPolicyRuntime)
	salt := common.BigToHash(common.Big1)
	return &policyTestSetup{
		gspec:    gspec,
		config:   gspec.Config,
		engine:   ethash.NewFullFaker(),
		key:      key,
		account:  account,
		initCode: initCode,
		salt:     salt,
		policy:   ghost.PolicyAddress(salt, crypto.Keccak256Hash(initCode)),
		tip:      big.NewInt(1_000_000_000),
	}
}

// tx signs an account transaction of the setup's account in block b.
func (s *policyTestSetup) tx(b *BlockGen, genesis common.Hash, to *common.Address, value *big.Int, gas uint64, data []byte) *types.Transaction {
	return signAccountTx(s.config, genesis, s.key, &types.GhostAccountTx{
		Nonce:     b.TxNonce(s.account),
		GasTipCap: s.tip,
		GasFeeCap: new(big.Int).Add(b.BaseFee(), s.tip),
		Gas:       gas + ghostExtraGas,
		To:        to,
		Value:     value,
		Data:      data,
	})
}

// createTx sends the policy's creation to the factory.
func (s *policyTestSetup) createTx(b *BlockGen, genesis common.Hash) *types.Transaction {
	factory := ghost.PolicyFactoryAddress
	return s.tx(b, genesis, &factory, new(big.Int), 500_000, append(s.salt.Bytes(), s.initCode...))
}

func (s *policyTestSetup) newChain(t *testing.T) *BlockChain {
	t.Helper()
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, s.gspec, nil, s.engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func (s *policyTestSetup) state(t *testing.T, chain *BlockChain) *state.StateDB {
	t.Helper()
	st, err := chain.State()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestFrozenPolicyTxRecipient checks that a transaction with value to a
// registered policy is invalid, so a block holding one is refused and its
// sender pays nothing, while a transaction without value to the policy is
// valid and runs the policy.
func TestFrozenPolicyTxRecipient(t *testing.T) {
	s := newPolicyTestSetup()
	var genesis common.Hash
	_, blocks, receipts := GenerateChainWithGenesis(s.gspec, s.engine, 3, func(i int, b *BlockGen) {
		switch i {
		case 0:
			genesis = b.PrevBlock(-1).Hash()
			b.SetCoinbase(s.account)
		case 1:
			b.AddTx(s.createTx(b, genesis))
		case 2:
			b.AddTx(s.tx(b, genesis, &s.policy, new(big.Int), 100_000, common.LeftPadBytes([]byte{0x2a}, 32)))
		}
	})
	chain := s.newChain(t)
	defer chain.Stop()
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: %v", n+1, err)
	}
	if r := receipts[1][0]; r.Status != types.ReceiptStatusSuccessful {
		t.Fatal("the policy creation fails")
	}
	if r := receipts[2][0]; r.Status != types.ReceiptStatusSuccessful {
		t.Fatal("the transaction without value to the policy fails")
	}
	st := s.state(t, chain)
	if !ghost.IsRegisteredPolicy(st, s.policy) {
		t.Fatal("the policy is not registered")
	}
	nonce, balance := st.GetNonce(s.account), st.GetBalance(s.account).Clone()

	head := chain.CurrentBlock()
	parent := chain.GetBlock(head.Hash(), head.Number.Uint64())
	price := new(big.Int).Add(new(big.Int).Mul(parent.BaseFee(), big.NewInt(2)), s.tip)
	send := signAccountTx(s.config, genesis, s.key, &types.GhostAccountTx{
		Nonce:     nonce,
		GasTipCap: s.tip,
		GasFeeCap: price,
		Gas:       100_000 + ghostExtraGas,
		To:        &s.policy,
		Value:     big.NewInt(1),
	})
	bad := GenerateBadBlock(parent, s.engine, types.Transactions{send}, s.config)
	if _, err := chain.InsertChain(types.Blocks{bad}); !errors.Is(err, ErrPolicyNoBalance) {
		t.Errorf("block with value to the policy: import error %v, want %v", err, ErrPolicyNoBalance)
	}
	if chain.CurrentBlock().Hash() != head.Hash() {
		t.Fatal("the head moved")
	}
	st = s.state(t, chain)
	if _, _, _, err := chain.Processor().Process(bad, st, vm.Config{}); !errors.Is(err, ErrPolicyNoBalance) {
		t.Errorf("process error %v, want %v", err, ErrPolicyNoBalance)
	}
	if st.GetNonce(s.account) != nonce || !st.GetBalance(s.account).Eq(balance) || !st.GetBalance(s.policy).IsZero() {
		t.Error("the refused transaction changed the sender or the policy")
	}
}

// TestFrozenPolicyCoinbaseInvalid checks that a block whose coinbase is a
// registered policy after the block is invalid: one whose coinbase is a
// policy created earlier, and one whose coinbase is the policy the block
// itself creates.
func TestFrozenPolicyCoinbaseInvalid(t *testing.T) {
	s := newPolicyTestSetup()
	t.Run("created in an earlier block", func(t *testing.T) {
		var genesis common.Hash
		_, blocks, _ := GenerateChainWithGenesis(s.gspec, s.engine, 3, func(i int, b *BlockGen) {
			switch i {
			case 0:
				genesis = b.PrevBlock(-1).Hash()
				b.SetCoinbase(s.account)
			case 1:
				b.AddTx(s.createTx(b, genesis))
			case 2:
				b.SetCoinbase(s.policy)
			}
		})
		chain := s.newChain(t)
		defer chain.Stop()
		if n, err := chain.InsertChain(blocks[:2]); err != nil {
			t.Fatalf("block %d: %v", n+1, err)
		}
		if !ghost.IsRegisteredPolicy(s.state(t, chain), s.policy) {
			t.Fatal("the policy is not registered")
		}
		if _, err := chain.InsertChain(blocks[2:]); !errors.Is(err, ErrPolicyCoinbase) {
			t.Errorf("block paying the policy: import error %v, want %v", err, ErrPolicyCoinbase)
		}
		if got := chain.CurrentBlock().Number.Uint64(); got != 2 {
			t.Errorf("head at block %d, want 2", got)
		}
		if bal := s.state(t, chain).GetBalance(s.policy); !bal.IsZero() {
			t.Errorf("policy balance %v", bal)
		}
	})
	t.Run("created in the same block", func(t *testing.T) {
		var genesis common.Hash
		_, blocks, _ := GenerateChainWithGenesis(s.gspec, s.engine, 2, func(i int, b *BlockGen) {
			switch i {
			case 0:
				genesis = b.PrevBlock(-1).Hash()
				b.SetCoinbase(s.account)
			case 1:
				b.SetCoinbase(s.policy)
				b.AddTx(s.createTx(b, genesis))
			}
		})
		chain := s.newChain(t)
		defer chain.Stop()
		if n, err := chain.InsertChain(blocks[:1]); err != nil {
			t.Fatalf("block %d: %v", n+1, err)
		}
		if _, err := chain.InsertChain(blocks[1:]); !errors.Is(err, ErrPolicyCoinbase) {
			t.Errorf("block creating and paying the policy: import error %v, want %v", err, ErrPolicyCoinbase)
		}
		if got := chain.CurrentBlock().Number.Uint64(); got != 1 {
			t.Errorf("head at block %d, want 1", got)
		}
	})
}

// TestFrozenPolicyBalanceZero checks RP-11 over a sequence of transactions:
// a balance sent to the address before the policy exists is burned when it
// is created, and afterwards neither a CALL with value from a contract nor a
// SELFDESTRUCT naming it as beneficiary nor a call without value gives it a
// balance; the contracts that tried keep theirs.
func TestFrozenPolicyBalanceZero(t *testing.T) {
	s := newPolicyTestSetup()
	push20 := append([]byte{byte(vm.PUSH20)}, s.policy.Bytes()...)
	// CALL the policy with value 1 and store the success flag in slot 0.
	valueCaller := append(append([]byte{
		byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0, byte(vm.PUSH1), 0,
		byte(vm.PUSH1), 1,
	}, push20...), byte(vm.GAS), byte(vm.CALL), byte(vm.PUSH1), 0, byte(vm.SSTORE), byte(vm.STOP))
	destructor := append(append([]byte{}, push20...), byte(vm.SELFDESTRUCT))
	var (
		caller    = crypto.CreateAddress(s.account, 1)
		destroyer = crypto.CreateAddress(s.account, 2)
		genesis   common.Hash
	)
	_, blocks, receipts := GenerateChainWithGenesis(s.gspec, s.engine, 4, func(i int, b *BlockGen) {
		switch i {
		case 0:
			genesis = b.PrevBlock(-1).Hash()
			b.SetCoinbase(s.account)
		case 1:
			// The address is funded before the policy exists, and the
			// two contracts are deployed with balances.
			b.AddTx(s.tx(b, genesis, &s.policy, big.NewInt(1), 21_000, nil))
			b.AddTx(s.tx(b, genesis, nil, big.NewInt(10), 300_000, policyDeployCode(valueCaller)))
			b.AddTx(s.tx(b, genesis, nil, big.NewInt(5), 300_000, policyDeployCode(destructor)))
		default:
			if i == 2 {
				b.AddTx(s.createTx(b, genesis))
			}
			b.AddTx(s.tx(b, genesis, &caller, new(big.Int), 200_000, nil))
			b.AddTx(s.tx(b, genesis, &destroyer, new(big.Int), 200_000, nil))
			b.AddTx(s.tx(b, genesis, &s.policy, new(big.Int), 100_000, nil))
		}
	})
	chain := s.newChain(t)
	defer chain.Stop()
	for i, block := range blocks {
		if _, err := chain.InsertChain(types.Blocks{block}); err != nil {
			t.Fatalf("block %d: %v", i+1, err)
		}
		st := s.state(t, chain)
		policyBalance := st.GetBalance(s.policy).Uint64()
		switch i {
		case 0:
			continue
		case 1:
			if policyBalance != 1 {
				t.Fatalf("the address holds %d before the policy exists, want 1", policyBalance)
			}
		default:
			if policyBalance != 0 || !ghost.IsRegisteredPolicy(st, s.policy) {
				t.Errorf("after block %d: policy balance %d, registered %v", i+1, policyBalance, ghost.IsRegisteredPolicy(st, s.policy))
			}
		}
		if got := st.GetBalance(caller).Uint64(); got != 10 {
			t.Errorf("after block %d: the value caller holds %d, want 10", i+1, got)
		}
		if got := st.GetBalance(destroyer).Uint64(); got != 5 {
			t.Errorf("after block %d: the destructor holds %d, want 5", i+1, got)
		}
		if len(st.GetCode(destroyer)) == 0 {
			t.Errorf("after block %d: the destructor is gone", i+1)
		}
	}
	for i, rs := range receipts {
		for j, r := range rs {
			if r.Status != types.ReceiptStatusSuccessful && !(i >= 2 && j == len(rs)-2) {
				t.Errorf("block %d transaction %d fails", i+1, j)
			}
		}
	}
	// The SELFDESTRUCT naming the policy fails in each block.
	for i := 2; i < len(receipts); i++ {
		if r := receipts[i][len(receipts[i])-2]; r.Status != types.ReceiptStatusFailed {
			t.Errorf("block %d: the SELFDESTRUCT naming the policy succeeds", i+1)
		}
	}
	// The value caller's CALL with value failed and moved nothing.
	st := s.state(t, chain)
	if v := st.GetState(caller, common.Hash{}); v != (common.Hash{}) {
		t.Errorf("the CALL with value to the policy succeeded: %x", v)
	}
}
