package ghostpir

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// Server answers PIR queries to one snapshot's database. It holds no key and
// asks for no permission: the database and the a_j are built from public
// data, and a query is answered for whoever sends it. What the server sees
// of a query (its bytes, the answer, their sizes and the work done) is the
// same for every record, and that is all it logs.
type Server struct {
	db  *Database
	log log.Logger
}

// NewServer serves db, logging to logger (the root logger when nil).
func NewServer(db *Database, logger log.Logger) *Server {
	if logger == nil {
		logger = log.Root()
	}
	return &Server{db: db, log: logger}
}

// Shape is the public description of the database served.
func (s *Server) Shape() Shape { return s.db.shape }

// Answer computes the answer to a query from client, an opaque label of the
// requester used only in the log. A query of another shape or snapshot is
// refused before any work.
func (s *Server) Answer(client string, query []byte) ([]byte, error) {
	start := time.Now()
	shape := s.db.shape
	snapshot := hex.EncodeToString(shape.Seed[:8])
	b, err := decodeQuery(shape, query)
	if err != nil {
		s.log.Debug("Refused PIR query", "snapshot", snapshot, "client", client, "query", len(query), "err", err)
		return nil, err
	}
	ans := make([]uint32, shape.Rows*N)
	parallel(shape.Rows, func(lo, hi int) {
		acc := newAccumulator()
		for r := lo; r < hi; r++ {
			s.db.rowProduct(acc, r, b, ans[r*N:(r+1)*N])
		}
	})
	out := encodeAnswer(shape.Seed, shape.Rows, s.db.hint, ans)
	s.log.Debug("Answered PIR query", "snapshot", snapshot, "client", client,
		"query", len(query), "answer", len(out), "elapsed", common.PrettyDuration(time.Since(start)))
	return out, nil
}

// EntryShape is the shape of the PIR database of entry i of a snapshot
// header: the records the header lists for it, under the entry's seed. A
// client derives every shape from the header alone. An entry without
// records has no database (ErrShape).
func EntryShape(h *SnapshotHeader, i int) (Shape, error) {
	if h == nil || i < 0 || i >= len(h.Entries) {
		return Shape{}, fmt.Errorf("%w: entry %d", ErrNoDatabase, i)
	}
	e := h.Entries[i]
	return NewShape(DatabaseSeed(h.ID(), i), e.RecordSize, e.Records)
}

// Query answers a PIR query to the database of entry i of the snapshot
// served (the hint buckets and overflow entries of a tree, its notes, its
// witness or lookup records, or a marker list), as Server.Answer does. The
// request is charged to client's budget before anything else: one past it is
// refused with ErrClientBudget or ErrTotalBudget and no work is done. A
// query made under another snapshot's seed is refused (ErrStaleSnapshot).
func (s *BulkServer) Query(client string, i int, query []byte) ([]byte, error) {
	st, err := s.state(client, "query")
	if err != nil {
		return nil, err
	}
	if i < 0 || i >= len(st.servers) || st.servers[i] == nil {
		return nil, fmt.Errorf("%w: entry %d of %d", ErrNoDatabase, i, len(st.servers))
	}
	return st.servers[i].Answer(client, query)
}
