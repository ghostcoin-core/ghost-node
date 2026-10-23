package randomx

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRemoteSealZProbe(t *testing.T) {
	bin := filepath.Join(runtime.GOROOT(), "bin")
	out, err := exec.Command(filepath.Join(bin, "gofmt"), "-l", "-d", "remote.go", "hasher.go", "remote_test.go", "randomx.go", "sealer.go", "consensus.go", "../../eth/solo_mining_test.go").CombinedOutput()
	t.Errorf("gofmt err=%v\n%s", err, out)
	out, err = exec.Command(filepath.Join(bin, "go"), "vet", "-tags", "integrationtests", ".", "../../eth/").CombinedOutput()
	t.Errorf("vet err=%v\n%s", err, out)
}
