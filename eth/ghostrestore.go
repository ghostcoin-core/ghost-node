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

package eth

import (
	"sync"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostpir"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// restoreService keeps the node's PIR restore server at the canonical head:
// it updates the server on every new head, in the background, one update
// at a time, skipping heads that arrive while one runs.
type restoreService struct {
	server *ghostpir.BulkServer
	chain  *core.BlockChain

	quit chan struct{}
	wg   sync.WaitGroup
}

// newRestoreService serves the snapshots of the chain's tree history,
// reading the indexed trees and block lookup lists from its state.
func newRestoreService(db ethdb.Reader, chain *core.BlockChain, history *ghosttree.History) (*restoreService, error) {
	server, err := ghostpir.NewBulkServer(db, history, ghostpir.DefaultBudget, nil)
	if err != nil {
		return nil, err
	}
	server.SetState(func(h *types.Header) (ghosttree.StateDB, error) { return chain.StateAt(h.Root) })
	return &restoreService{server: server, chain: chain, quit: make(chan struct{})}, nil
}

func (r *restoreService) start() {
	heads := make(chan core.ChainHeadEvent, 1)
	sub := r.chain.SubscribeChainHeadEvent(heads)
	next := make(chan *types.Header, 1)
	if head := r.chain.CurrentBlock(); head != nil {
		next <- head
	}

	// The newest head waits in next; an update takes it when the last one
	// ends, so a slow rebuild never queues the heads behind it.
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		defer sub.Unsubscribe()
		for {
			select {
			case ev := <-heads:
				select {
				case <-next:
				default:
				}
				next <- ev.Block.Header()
			case <-sub.Err():
				return
			case <-r.quit:
				return
			}
		}
	}()
	go func() {
		defer r.wg.Done()
		for {
			select {
			case head := <-next:
				if err := r.server.Update(head); err != nil {
					log.Debug("PIR restore server not updated", "number", head.Number, "err", err)
				}
			case <-r.quit:
				return
			}
		}
	}()
}

func (r *restoreService) stop() {
	close(r.quit)
	r.wg.Wait()
}
