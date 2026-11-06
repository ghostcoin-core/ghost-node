package ghostpir

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/log"
)

// benchMachine names the machine a benchmark measures on: its host name,
// CPU model (from /proc/cpuinfo where there is one), CPU count, platform and
// Go version.
func benchMachine() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown host"
	}
	cpu := "unknown CPU"
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
				cpu = strings.TrimSpace(v)
				break
			}
		}
		f.Close()
	}
	return fmt.Sprintf("%s (%s, %d CPUs, %s/%s, %s)", host, cpu, runtime.NumCPU(), runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// BenchmarkAnswer measures the server's work per query on a database of
// 16,384 note-sized records (6.6 MB), and reports the bytes of a query and
// of an answer. The figures at the one-year and five-year chain sizes are
// BenchmarkRestoreSizes.
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
	b.StopTimer()
	b.Logf("measured on %s, all CPUs", benchMachine())
}
