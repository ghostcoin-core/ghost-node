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

package ethapi

import (
	"context"
	"errors"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/ghostpir"
	"github.com/ethereum/go-ethereum/rpc"
)

// GhostRestoreAPI serves a private wallet restore from the node's PIR
// restore server (core/ghostpir): the header of the snapshot served, the
// tree tops and the blocks after the snapshot in bulk, and PIR answers to
// queries over the snapshot's databases. No method names a tag, a marker, a
// position or a note: what a wallet reads whole is the same for every
// wallet, and the rest is a PIR query that hides which record it fetches.
// Every call is charged to the restore server's budget and to the node's
// ghost read limits before any work.
type GhostRestoreAPI struct {
	server *ghostpir.BulkServer
	limit  *ghostReadLimiter
}

// NewGhostRestoreAPI returns the restore reads over a restore server. Its
// reads share the node's ghost read limits (ghostReads).
func NewGhostRestoreAPI(server *ghostpir.BulkServer) *GhostRestoreAPI {
	return &GhostRestoreAPI{server: server, limit: ghostReads}
}

// ghostRestoreQueryCost is the page units of one PIR answer: it reads a whole
// database once, so the node answers at most two at a time.
const ghostRestoreQueryCost = ghostReadUnits / 2

var errNoRestoreServer = errors.New("restore server unavailable")

// RPCRestoreEntry is one database of a snapshot: what it holds, its shape
// and the root its records verify against.
type RPCRestoreEntry struct {
	Table      string         `json:"table"`
	Kind       TreeKind       `json:"kind"`
	TreeIndex  hexutil.Uint64 `json:"treeIndex"`
	RecordSize hexutil.Uint64 `json:"recordSize"`
	Records    hexutil.Uint64 `json:"records"`
	Root       common.Hash    `json:"root"`
	Digest     common.Hash    `json:"digest"`
	Rows       hexutil.Uint64 `json:"rows"`
	Cols       hexutil.Uint64 `json:"cols"`
}

// RPCRestoreHeader is the header of the snapshot served. Encoded is its
// canonical encoding, whose hash under the snapshot label is ID and seeds
// every database; the other fields repeat it.
type RPCRestoreHeader struct {
	ID             common.Hash       `json:"id"`
	Scheme         string            `json:"scheme"`
	Number         hexutil.Uint64    `json:"number"`
	Anchor         common.Hash       `json:"anchor"`
	CoinTreeRoot   common.Hash       `json:"coinTreeRoot"`
	DataTreeRoot   common.Hash       `json:"dataTreeRoot"`
	DataMarkerRoot common.Hash       `json:"dataMarkerRoot"`
	Entries        []RPCRestoreEntry `json:"entries"`
	Encoded        hexutil.Bytes     `json:"encoded"`
}

// restoreClient names the caller of ctx for the restore server's budget:
// its source address over HTTP and WebSocket, as for the read limits, and
// the node itself over IPC and in process.
func restoreClient(ctx context.Context) string {
	if info := rpc.PeerInfoFromContext(ctx); info.Transport == "http" || info.Transport == "ws" {
		return rpcSource(info)
	}
	return "local"
}

// restoreError gives a refusal for the restore server's budget the JSON-RPC
// code of a limit (-32005), so that a client knows to try again later.
func restoreError(err error) error {
	if errors.Is(err, ghostpir.ErrClientBudget) || errors.Is(err, ghostpir.ErrTotalBudget) {
		return &limitError{err.Error()}
	}
	return err
}

func (api *GhostRestoreAPI) admit(ctx context.Context, cost int64) (func(), error) {
	if api == nil || api.server == nil {
		return nil, errNoRestoreServer
	}
	return api.limit.acquire(ctx, cost)
}

// RestoreHeader, ghost_restoreHeader, returns the header of the snapshot
// served: its anchor block, the anchor's roots and every database with its
// table, kind, record size and count, root, digest and PIR shape.
func (api *GhostRestoreAPI) RestoreHeader(ctx context.Context) (*RPCRestoreHeader, error) {
	release, err := api.admit(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer release()
	h, err := api.server.Header(restoreClient(ctx))
	if err != nil {
		return nil, restoreError(err)
	}
	out := &RPCRestoreHeader{
		ID: h.ID(), Scheme: ghostpir.SchemeName, Number: hexutil.Uint64(h.Number), Anchor: h.Anchor,
		CoinTreeRoot: h.CoinTreeRoot, DataTreeRoot: h.DataTreeRoot, DataMarkerRoot: h.DataMarkerRoot,
		Entries: make([]RPCRestoreEntry, len(h.Entries)), Encoded: h.Encode(),
	}
	for i, e := range h.Entries {
		out.Entries[i] = RPCRestoreEntry{
			Table: e.Table.String(), Kind: TreeKind(e.Kind), TreeIndex: hexutil.Uint64(e.TreeIndex),
			RecordSize: hexutil.Uint64(e.RecordSize), Records: hexutil.Uint64(e.Records), Root: e.Root, Digest: e.Digest,
		}
		if shape, err := ghostpir.EntryShape(h, i); err == nil {
			out.Entries[i].Rows, out.Entries[i].Cols = hexutil.Uint64(shape.Rows), hexutil.Uint64(shape.Cols)
		}
	}
	return out, nil
}

// RestoreTops, ghost_restoreTops, returns the tops of every coin and data
// tree of the snapshot, each in its wire encoding (ghostpir.TreeTops.Encode).
func (api *GhostRestoreAPI) RestoreTops(ctx context.Context) ([]hexutil.Bytes, error) {
	release, err := api.admit(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer release()
	tops, err := api.server.Tops(restoreClient(ctx))
	if err != nil {
		return nil, restoreError(err)
	}
	out := make([]hexutil.Bytes, len(tops))
	for i := range tops {
		out[i] = tops[i].Encode()
	}
	return out, nil
}

// RestoreBlocks, ghost_restoreBlocks, returns every block after the
// snapshot's anchor and after block after, up to the head, each in its wire
// encoding (ghostpir.BlockTags.Encode): its leaves and markers and its
// lookup lists, which hash to the block header's lookupDigest.
func (api *GhostRestoreAPI) RestoreBlocks(ctx context.Context, after hexutil.Uint64) ([]hexutil.Bytes, error) {
	release, err := api.admit(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer release()
	blocks, err := api.server.Blocks(restoreClient(ctx), uint64(after))
	if err != nil {
		return nil, restoreError(err)
	}
	out := make([]hexutil.Bytes, len(blocks))
	for i := range blocks {
		out[i] = blocks[i].Encode()
	}
	return out, nil
}

// RestoreQuery, ghost_restoreQuery, answers a PIR query to the database of
// entry of the snapshot served. A query of another shape, or made under
// another snapshot's seed, is refused before any work.
func (api *GhostRestoreAPI) RestoreQuery(ctx context.Context, entry hexutil.Uint64, query hexutil.Bytes) (hexutil.Bytes, error) {
	if entry > math.MaxInt32 {
		return nil, ghostpir.ErrNoDatabase
	}
	release, err := api.admit(ctx, ghostRestoreQueryCost)
	if err != nil {
		return nil, err
	}
	defer release()
	answer, err := api.server.Query(restoreClient(ctx), int(entry), query)
	if err != nil {
		return nil, restoreError(err)
	}
	return answer, nil
}
