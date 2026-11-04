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
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/ethereum/go-ethereum/params/vars"
)

// TestCommitDataRejectedAtSubmission checks that a transaction to a commit
// entry address whose data or value every execution refuses is refused when
// it is sent, with the reason execution gives, and never enters the pool:
// 206-byte version 2 commit data among them, which once sat in the pool
// forever and blocked its sender's later nonces. A valid version 3 commit is
// still taken, and mined.
func TestCommitDataRejectedAtSubmission(t *testing.T) {
	var (
		gspec    = ghost.InternalNetGenesis()
		engine   = ethash.NewFaker()
		oneGhost = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	)
	key, _, from := testAccount(0x47)
	gspec.Alloc = genesisT.GenesisAlloc{from: {Balance: new(big.Int).Mul(oneGhost, big.NewInt(100))}}
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	genesis := chain.Genesis().Hash()

	legacy := New(testTxPoolConfig, chain)
	pool, err := txpool.New(testTxPoolConfig.PriceLimit, chain, []txpool.SubPool{legacy})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	sign := func(k *mldsa44.PrivateKey, nonce uint64, to common.Address, value *big.Int, data []byte) *types.Transaction {
		signer := types.NewGhostAccountSigner(types.LatestSigner(gspec.Config), genesis)
		tx, err := types.SignGhostAccountTx(signer, k, &types.GhostAccountTx{
			ChainID:   gspec.Config.GetChainID(),
			Nonce:     nonce,
			GasTipCap: big.NewInt(vars.InitialBaseFee),
			GasFeeCap: big.NewInt(100 * vars.InitialBaseFee),
			Gas:       60_000 + txGas,
			To:        &to,
			Value:     value,
			Data:      data,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	// send submits tx as eth_sendRawTransaction does: one local transaction,
	// added synchronously.
	send := func(tx *types.Transaction) error {
		return pool.Add([]*types.Transaction{tx}, true, true)[0]
	}

	f := ghosttree.K("ghost/test-coin-f", []byte("commit data at submission"))
	valid, err := ghostpriv.SaltedCommitData(f, make([]byte, ghostpriv.SaltSize), make([]byte, ghostpriv.NoteSize))
	if err != nil {
		t.Fatal(err)
	}
	// Version 2 commit data: the version, F, the salt and a 156-byte note,
	// 206 bytes, the data the wallet sent.
	v2 := make([]byte, 0, 2+32+ghostpriv.SaltSize+ghostpriv.RevealNoteSize)
	v2 = binary.BigEndian.AppendUint16(v2, 2)
	v2 = append(v2, f[:]...)
	v2 = append(v2, make([]byte, ghostpriv.SaltSize+ghostpriv.RevealNoteSize)...)

	// Valid version 3 data under another version tag.
	retagged := common.CopyBytes(valid)
	binary.BigEndian.PutUint16(retagged, 2)
	zeroF, err := ghostpriv.SaltedCommitData(common.Hash{}, make([]byte, ghostpriv.SaltSize), make([]byte, ghostpriv.NoteSize))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		to     common.Address
		value  *big.Int
		data   []byte
		want   error
		reason string
	}{
		{"206-byte version 2 commit data", ghost.CommitEntryAddress, oneGhost, v2, ghostpriv.ErrCommitData, "commit data is not 430 bytes of version 3: 206 bytes"},
		{"430 bytes of version 2", ghost.CommitEntryAddress, oneGhost, retagged, ghostpriv.ErrCommitData, "commit data is not 430 bytes of version 3: 430 bytes"},
		{"valid data one byte short", ghost.CommitEntryAddress, oneGhost, valid[:len(valid)-1], ghostpriv.ErrCommitData, "commit data is not 430 bytes of version 3: 429 bytes"},
		{"no commit data", ghost.CommitEntryAddress, oneGhost, nil, ghostpriv.ErrCommitData, "commit data is not 430 bytes of version 3: 0 bytes"},
		{"zero F", ghost.CommitEntryAddress, oneGhost, zeroF, ghostpriv.ErrCommitZeroF, ghostpriv.ErrCommitZeroF.Error()},
		{"commit value zero", ghost.CommitEntryAddress, new(big.Int), valid, ghostpriv.ErrCommitAmount, ghostpriv.ErrCommitAmount.Error()},
		{"206-byte data commit", ghost.DataCommitEntryAddress, ghostpriv.DataReserve.ToBig(), v2, ghostpriv.ErrCommitData, "commit data is not 430 bytes of version 3: 206 bytes"},
		{"data commit value not the reserve", ghost.DataCommitEntryAddress, oneGhost, valid, ghostpriv.ErrDataCommitValue, ghostpriv.ErrDataCommitValue.Error()},
	} {
		tx := sign(key, 0, tc.to, tc.value, tc.data)
		err := send(tx)
		if err == nil {
			t.Errorf("%s: accepted at submission", tc.name)
			continue
		}
		if !errors.Is(err, tc.want) || !errors.Is(err, txpool.ErrInvalidCommit) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
		}
		if !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%s: error %q does not give the reason %q", tc.name, err, tc.reason)
		}
		if pool.Get(tx.Hash()) != nil || pool.Status(tx.Hash()) != txpool.TxStatusUnknown {
			t.Errorf("%s: transaction in the pool", tc.name)
		}
	}
	if pending, queued := legacy.Stats(); pending != 0 || queued != 0 {
		t.Fatalf("pool holds %d pending and %d queued transactions after the refusals, want none", pending, queued)
	}
	if nonce := pool.Nonce(from); nonce != 0 {
		t.Fatalf("pool nonce of the sender %d, want 0", nonce)
	}

	// The valid version 3 commit at the same nonce is taken, and mined.
	commit := sign(key, 0, ghost.CommitEntryAddress, oneGhost, valid)
	if err := send(commit); err != nil {
		t.Fatalf("valid version 3 commit refused: %v", err)
	}
	if pool.Status(commit.Hash()) != txpool.TxStatusPending {
		t.Fatal("valid version 3 commit is not pending")
	}
	pending := legacy.Pending(txpool.PendingFilter{})[from]
	if len(pending) != 1 || pending[0].Hash != commit.Hash() {
		t.Fatalf("pending of the sender %v, want the commit", pending)
	}
	_, blocks, receipts := core.GenerateChainWithGenesis(gspec, engine, 1, func(i int, b *core.BlockGen) {
		b.AddTx(pending[0].Resolve())
	})
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block with the commit refused: %v", err)
	}
	if len(receipts[0]) != 1 || receipts[0][0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("commit receipts %v, want one successful", receipts[0])
	}
	coin := ghosttree.TreeAccount(ghosttree.Coin)
	logged := false
	for _, l := range receipts[0][0].Logs {
		logged = logged || l.Address == coin
	}
	if !logged {
		t.Fatal("the mined commit wrote no commit receipt log")
	}
	if head := chain.CurrentBlock(); head.Hash() != blocks[0].Hash() {
		t.Fatalf("chain head %d %x, want the block with the commit", head.Number, head.Hash())
	}
}
