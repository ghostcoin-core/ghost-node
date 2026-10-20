// Copyright 2026 The go-ethereum Authors
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

package eth

import (
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// Tests that a header request for zero headers is answered with nothing, in
// every traversal mode. Before the early return, a hash-based contiguous query
// still delivered its origin header.
func TestZeroAmountHeaderRequest(t *testing.T) {
	t.Parallel()

	backend := newTestBackend(8)
	defer backend.close()

	origin := backend.chain.GetBlockByNumber(4).Hash()
	for _, reverse := range []bool{false, true} {
		for _, skip := range []uint64{0, 1} {
			queries := []GetBlockHeadersRequest{
				{Origin: HashOrNumber{Number: 4}, Amount: 0, Skip: skip, Reverse: reverse},
				{Origin: HashOrNumber{Number: 0}, Amount: 0, Skip: skip, Reverse: reverse},
				{Origin: HashOrNumber{Hash: origin}, Amount: 0, Skip: skip, Reverse: reverse},
			}
			for _, query := range queries {
				desc := query
				if headers := ServiceGetBlockHeadersQuery(backend.chain, &query, nil); len(headers) != 0 {
					t.Errorf("query %+v: have %d headers, want 0", desc, len(headers))
				}
			}
		}
	}
	// A non-zero amount by hash must still be served.
	query := &GetBlockHeadersRequest{Origin: HashOrNumber{Hash: origin}, Amount: 1}
	if headers := ServiceGetBlockHeadersQuery(backend.chain, query, nil); len(headers) != 1 {
		t.Errorf("single header by hash: have %d headers, want 1", len(headers))
	}
}

// Tests that number-based header traversal detects a wrapping skip instead of
// stepping backwards past genesis or standing still on the origin header.
func TestHeaderTraversalOverflow(t *testing.T) {
	t.Parallel()

	backend := newTestBackend(8)
	defer backend.close()

	one := backend.chain.GetBlockByNumber(1).Hash()
	tests := []GetBlockHeadersRequest{
		{Origin: HashOrNumber{Number: 1}, Amount: 2, Reverse: false, Skip: math.MaxUint64 - 1},
		{Origin: HashOrNumber{Number: 1}, Amount: 2, Reverse: true, Skip: math.MaxUint64 - 1},
		{Origin: HashOrNumber{Number: 1}, Amount: 2, Reverse: false, Skip: math.MaxUint64},
		{Origin: HashOrNumber{Number: 1}, Amount: 2, Reverse: true, Skip: math.MaxUint64},
		// A large amount must not turn a zero step into maxHeadersServe copies.
		{Origin: HashOrNumber{Number: 1}, Amount: maxHeadersServe, Reverse: false, Skip: math.MaxUint64},
		{Origin: HashOrNumber{Number: 1}, Amount: maxHeadersServe, Reverse: true, Skip: math.MaxUint64},
	}
	for i, query := range tests {
		desc := query
		headers := ServiceGetBlockHeadersQuery(backend.chain, &query, nil)
		if len(headers) != 1 {
			t.Errorf("test %d (%+v): have %d headers, want 1", i, desc, len(headers))
			continue
		}
		var header types.Header
		if err := rlp.DecodeBytes(headers[0], &header); err != nil {
			t.Fatalf("test %d: failed to decode header: %v", i, err)
		}
		if header.Hash() != one {
			t.Errorf("test %d (%+v): have header %d, want the origin", i, desc, header.Number)
		}
	}
	// Ordinary skips stay served.
	query := GetBlockHeadersRequest{Origin: HashOrNumber{Number: 6}, Amount: 3, Reverse: true, Skip: 2}
	if headers := ServiceGetBlockHeadersQuery(backend.chain, &query, nil); len(headers) != 3 {
		t.Errorf("reverse skip: have %d headers, want 3", len(headers))
	}
	query = GetBlockHeadersRequest{Origin: HashOrNumber{Number: 0}, Amount: 3, Reverse: false, Skip: 2}
	if headers := ServiceGetBlockHeadersQuery(backend.chain, &query, nil); len(headers) != 3 {
		t.Errorf("forward skip: have %d headers, want 3", len(headers))
	}
}

// Tests that pooled transaction retrievals stop after maxPooledTxServe lookups,
// even if the requested hashes are unknown and the response stays empty.
func TestPooledTxLookupCap(t *testing.T) {
	t.Parallel()

	backend := newTestBackend(0)
	defer backend.close()

	tx := signTestTx(backend.chain.Genesis().Hash(), testKey, &types.GhostAccountTx{
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(1_000_000_000),
		Gas:       testTransferGas,
		To:        &common.Address{0x01},
		Value:     big.NewInt(10_000),
	})
	if errs := backend.txpool.Add([]*types.Transaction{tx}, true, true); errs[0] != nil {
		t.Fatal(errs[0])
	}
	// Pad the request with unknown hashes so the known one lands at the given index
	request := func(index int) GetPooledTransactionsRequest {
		query := make(GetPooledTransactionsRequest, index+1)
		for i := range index {
			query[i] = common.BigToHash(big.NewInt(int64(i + 1)))
		}
		query[index] = tx.Hash()
		return query
	}
	if hashes, _ := answerGetPooledTransactions(backend, request(maxPooledTxServe-1)); len(hashes) != 1 {
		t.Errorf("transaction within lookup cap not served: have %d, want 1", len(hashes))
	}
	if hashes, _ := answerGetPooledTransactions(backend, request(maxPooledTxServe)); len(hashes) != 0 {
		t.Errorf("transaction beyond lookup cap served: have %d, want 0", len(hashes))
	}
}

// expectResponseRejected issues a request on a fresh peer, answers it with the
// given payload and checks that the peer is dropped with an error mentioning
// want, without anything reaching the sink.
func expectResponseRejected(t *testing.T, backend *testBackend, request func(*Peer, chan *Response) error, code uint64, response func(reqID uint64) any, want string) {
	t.Helper()

	peer, errc := newTestPeer("peer", ETH68, backend)
	defer peer.close()

	sink := make(chan *Response, 1)
	sent := make(chan error, 1)
	go func() { sent <- request(peer.Peer, sink) }()

	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read query: %v", err)
	}
	// Both body and receipt queries are a request id followed by a hash list.
	var query struct {
		RequestId uint64
		Hashes    []common.Hash
	}
	if err := msg.Decode(&query); err != nil {
		t.Fatalf("failed to decode query: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	if err := p2p.Send(peer.app, code, response(query.RequestId)); err != nil {
		t.Fatalf("failed to send response: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error mismatch: have %v, want it to mention %q", err, want)
		}
	case res := <-sink:
		res.Done <- nil
		t.Fatalf("response with impossible item count delivered")
	case <-time.After(2 * time.Second):
		t.Fatalf("peer not dropped for impossible item count")
	}
}

// Tests that block bodies listing more transactions or withdrawals than their
// encoded size can hold are rejected before any of their items are hashed.
func TestServeBodiesRejectOversizedCount(t *testing.T) {
	t.Parallel()

	// The smallest possible encodings must be accepted.
	txs := []*types.Transaction{
		types.NewTx(&types.LegacyTx{}),
		types.NewTx(&types.AccessListTx{}),
		types.NewTx(&types.DynamicFeeTx{}),
	}
	wds := []*types.Withdrawal{{}, {}}
	for _, tx := range txs {
		enc, _ := tx.MarshalBinary()
		if tx.Type() == types.LegacyTxType && len(enc) != minTxEncodedSize {
			t.Fatalf("minimal legacy tx has size %d, want %d", len(enc), minTxEncodedSize)
		}
	}
	if enc, _ := rlp.EncodeToBytes(wds[0]); len(enc) != minWithdrawalEncodedSize {
		t.Fatalf("minimal withdrawal has size %d, want %d", len(enc), minWithdrawalEncodedSize)
	}
	wdList := encodeRL(wds)
	body := BlockBody{Transactions: encodeRL(txs), Withdrawals: &wdList}
	if err := checkBodyItemCounts(&body); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}

	// Lists of elements too small to be valid must be rejected.
	var tinyTxs rlp.RawList[*types.Transaction]
	var tinyWds rlp.RawList[*types.Withdrawal]
	for range 1000 {
		tinyTxs.AppendRaw([]byte{0x01})
		tinyWds.AppendRaw([]byte{0x01})
	}
	if err := checkBodyItemCounts(&BlockBody{Transactions: tinyTxs}); err == nil {
		t.Fatal("body with tiny transactions accepted")
	}
	if err := checkBodyItemCounts(&BlockBody{Withdrawals: &tinyWds}); err == nil {
		t.Fatal("body with tiny withdrawals accepted")
	}

	// A peer answering a body request with such a body must be dropped.
	backend := newTestBackend(1)
	defer backend.close()

	hash := backend.chain.GetBlockByNumber(1).Hash()
	request := func(p *Peer, sink chan *Response) error {
		_, err := p.RequestBodies([]common.Hash{hash}, sink)
		return err
	}
	for want, bad := range map[string]BlockBody{
		"transactions in": {Transactions: tinyTxs},
		"withdrawals in":  {Withdrawals: &tinyWds},
	} {
		expectResponseRejected(t, backend, request, BlockBodiesMsg, func(id uint64) any {
			return &BlockBodiesPacket{RequestId: id, List: encodeRL([]BlockBody{bad})}
		}, want)
	}
}

// Tests that receipt lists holding more receipts than their encoded size can
// hold are rejected before any of their items are hashed.
func TestServeReceiptsRejectOversizedCount(t *testing.T) {
	t.Parallel()

	// The smallest possible encoding must be accepted, and pins the constant:
	// eth/68 carries the consensus encoding, bloom included.
	receipts := []*types.Receipt{
		{Type: types.LegacyTxType, Status: types.ReceiptStatusFailed},
		{Type: types.DynamicFeeTxType, Status: types.ReceiptStatusSuccessful},
	}
	for _, r := range receipts {
		enc, _ := rlp.EncodeToBytes(r)
		if r.Type == types.LegacyTxType && len(enc) != minReceiptEncodedSize {
			t.Fatalf("minimal legacy receipt has size %d, want %d", len(enc), minReceiptEncodedSize)
		}
		if len(enc) < minReceiptEncodedSize {
			t.Fatalf("minimal type %d receipt has size %d, below %d", r.Type, len(enc), minReceiptEncodedSize)
		}
		var dec types.Receipt
		if err := rlp.DecodeBytes(enc, &dec); err != nil {
			t.Fatalf("minimal receipt is not decodable: %v", err)
		}
	}
	if err := checkReceiptItemCounts([]ReceiptList{encodeRL(receipts)}); err != nil {
		t.Fatalf("valid receipts rejected: %v", err)
	}

	// Lists of elements too small to be valid must be rejected. The two-byte
	// element is a list holding a single empty string.
	tinyLists := make([]ReceiptList, 0, 2)
	for _, elem := range [][]byte{{0x01}, {0xc1, 0x80}} {
		var tiny ReceiptList
		for range 1000 {
			tiny.AppendRaw(elem)
		}
		if err := checkReceiptItemCounts([]ReceiptList{tiny}); err == nil {
			t.Fatalf("receipt list of %d-byte elements accepted", len(elem))
		}
		tinyLists = append(tinyLists, tiny)
	}

	// A peer answering a receipt request with such a list must be dropped.
	backend := newTestBackend(1)
	defer backend.close()

	hash := backend.chain.GetBlockByNumber(1).Hash()
	request := func(p *Peer, sink chan *Response) error {
		_, err := p.RequestReceipts([]common.Hash{hash}, sink)
		return err
	}
	for _, tiny := range tinyLists {
		expectResponseRejected(t, backend, request, ReceiptsMsg, func(id uint64) any {
			var lists rlp.RawList[ReceiptList]
			lists.Append(tiny)
			return &ReceiptsPacket{RequestId: id, List: lists}
		}, "receipts in")
	}
}
