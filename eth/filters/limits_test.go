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

package filters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rpc"
)

// writeTestHeaders stores a canonical chain of n empty headers and returns
// their hashes.
func writeTestHeaders(db ethdb.Database, n int) []common.Hash {
	var (
		hashes []common.Hash
		parent common.Hash
	)
	for i := 0; i < n; i++ {
		header := &types.Header{ParentHash: parent, Number: big.NewInt(int64(i)), Difficulty: common.Big1}
		hash := header.Hash()
		rawdb.WriteHeader(db, header)
		rawdb.WriteCanonicalHash(db, hash, uint64(i))
		rawdb.WriteHeadBlockHash(db, hash)
		hashes = append(hashes, hash)
		parent = hash
	}
	return hashes
}

// TestLogFilterValidation checks that eth_getLogs rejects a block hash
// combined with a block range, and reports an unknown block hash with
// errUnknownBlock.
func TestLogFilterValidation(t *testing.T) {
	t.Parallel()

	var (
		db               = rawdb.NewMemoryDatabase()
		_, sys           = newTestFilterSystem(t, db, Config{})
		api              = NewFilterAPI(sys, false)
		blockHash        = writeTestHeaders(db, 10)[0]
		unknownBlockHash = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
		addresses        = []common.Address{common.HexToAddress("0x2222222222222222222222222222222222222222")}
	)

	testCases := []struct {
		f   FilterCriteria
		err error
	}{
		{FilterCriteria{BlockHash: &blockHash, FromBlock: big.NewInt(100)}, errBlockHashWithRange},
		{FilterCriteria{BlockHash: &blockHash, ToBlock: big.NewInt(500)}, errBlockHashWithRange},
		{FilterCriteria{BlockHash: &blockHash, FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, errBlockHashWithRange},
		{FilterCriteria{BlockHash: &unknownBlockHash}, errUnknownBlock},
		{FilterCriteria{BlockHash: &blockHash, Topics: [][]common.Hash{{}, {}, {}, {}, {}}}, errExceedMaxTopics},
		{FilterCriteria{BlockHash: &blockHash, Addresses: make([]common.Address, maxAddresses+1)}, errExceedMaxAddresses},
		{FilterCriteria{BlockHash: &blockHash, Addresses: addresses}, nil},
	}
	for i, test := range testCases {
		_, err := api.GetLogs(context.Background(), test.f)
		if !errors.Is(err, test.err) {
			t.Errorf("case %d: wrong error: %v\nwant: %v", i, err, test.err)
		}
	}
}

// TestGetLogsAddressLimit checks that eth_getLogs, eth_newFilter and the JSON
// decoding of a filter criteria accept at most maxAddresses addresses.
func TestGetLogsAddressLimit(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(t, db, Config{})
		api    = NewFilterAPI(sys, false)
	)

	// eth_getLogs
	if _, err := api.GetLogs(context.Background(), FilterCriteria{Addresses: make([]common.Address, maxAddresses+1)}); !errors.Is(err, errExceedMaxAddresses) {
		t.Errorf("GetLogs: want %v, got %v", errExceedMaxAddresses, err)
	}

	// eth_newFilter
	if id, err := api.NewFilter(FilterCriteria{Addresses: make([]common.Address, maxAddresses+1)}); !errors.Is(err, errExceedMaxAddresses) {
		if err == nil {
			api.UninstallFilter(id)
		}
		t.Errorf("NewFilter: want %v, got %v", errExceedMaxAddresses, err)
	}
	id, err := api.NewFilter(FilterCriteria{Addresses: make([]common.Address, maxAddresses)})
	if err != nil {
		t.Errorf("NewFilter with %d addresses: unexpected error %v", maxAddresses, err)
	} else {
		api.UninstallFilter(id)
	}

	// JSON decoding
	addresses := func(n int) string {
		list := make([]string, n)
		for i := range list {
			list[i] = fmt.Sprintf("%q", common.BigToAddress(common.Big1).Hex())
		}
		return fmt.Sprintf(`{"address":[%s]}`, strings.Join(list, ","))
	}
	var crit FilterCriteria
	if err := json.Unmarshal([]byte(addresses(maxAddresses+1)), &crit); !errors.Is(err, errExceedMaxAddresses) {
		t.Errorf("UnmarshalJSON: want %v, got %v", errExceedMaxAddresses, err)
	}
	if err := json.Unmarshal([]byte(addresses(maxAddresses)), &crit); err != nil {
		t.Errorf("UnmarshalJSON with %d addresses: unexpected error %v", maxAddresses, err)
	} else if len(crit.Addresses) != maxAddresses {
		t.Errorf("UnmarshalJSON: want %d addresses, got %d", maxAddresses, len(crit.Addresses))
	}
}

// TestLogFilterRangeValidation checks that a log filter installed through
// eth_newFilter, whose range is later served by eth_getFilterLogs, cannot
// have an end block before its begin block, including an end block of 0.
func TestLogFilterRangeValidation(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(t, db, Config{})
		api    = NewFilterAPI(sys, false)
	)
	writeTestHeaders(db, 10)

	testCases := []struct {
		from, to int64
		err      error
	}{
		{5, 0, errInvalidBlockRange},
		{1, 0, errInvalidBlockRange},
		{2, 1, errInvalidBlockRange},
		{0, 0, nil},
		{0, 5, nil},
		{5, 5, nil},
	}
	for i, test := range testCases {
		crit := FilterCriteria{FromBlock: big.NewInt(test.from), ToBlock: big.NewInt(test.to)}
		id, err := api.NewFilter(crit)
		if !errors.Is(err, test.err) {
			t.Errorf("case %d (%d..%d): wrong error: %v\nwant: %v", i, test.from, test.to, err, test.err)
		}
		if err == nil {
			api.UninstallFilter(id)
		}
	}
}

// TestLogFilterRangeCheck checks that eth_getLogs rejects a range whose end
// block is before its begin block, including when the end block is the
// genesis block 0.
func TestLogFilterRangeCheck(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(t, db, Config{})
		api    = NewFilterAPI(sys, false)
	)
	writeTestHeaders(db, 10)

	// The test headers have empty blooms, so this address keeps the filter
	// from reading receipts.
	addresses := []common.Address{common.HexToAddress("0x2222222222222222222222222222222222222222")}

	testCases := []struct {
		from, to int64
		err      error
	}{
		{5, 0, errInvalidBlockRange},
		{1, 0, errInvalidBlockRange},
		{2, 1, errInvalidBlockRange},
		{0, 0, nil},
		{0, 5, nil},
		{5, 5, nil},
		{0, rpc.LatestBlockNumber.Int64(), nil},
	}
	for i, test := range testCases {
		crit := FilterCriteria{FromBlock: big.NewInt(test.from), ToBlock: big.NewInt(test.to), Addresses: addresses}
		if _, err := api.GetLogs(context.Background(), crit); !errors.Is(err, test.err) {
			t.Errorf("case %d (%d..%d): wrong error: %v\nwant: %v", i, test.from, test.to, err, test.err)
		}
	}
}
