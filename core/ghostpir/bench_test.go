package ghostpir

import (
	"testing"

	"github.com/ethereum/go-ethereum/log"
)

// BenchmarkAnswer measures the server's work per query on a database of
// 16,384 note-sized records (6.6 MB), and reports the bytes of a query and
// of an answer. The figures at target chain sizes are a separate run.
func BenchmarkAnswer(b *testing.B) {
	recs := testRecords(1, 1<<14, 380)
	db, err := NewDatabase(testSeed("bench"), 380, recs)
	if err != nil {
		b.Fatal(err)
	}
	srv := NewServer(db, log.NewLogger(log.DiscardHandler()))
	c, err := NewClient(srv.Shape())
	if err != nil {
		b.Fatal(err)
	}
	query, _, err := c.Query(1234, nil)
	if err != nil {
		b.Fatal(err)
	}
	s := srv.Shape()
	b.ReportMetric(float64(s.QueryBytes()), "query-bytes")
	b.ReportMetric(float64(s.AnswerBytes()), "answer-bytes")
	b.ReportMetric(float64(s.DatabaseBytes()), "db-bytes")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := srv.Answer("bench", query); err != nil {
			b.Fatal(err)
		}
	}
}
