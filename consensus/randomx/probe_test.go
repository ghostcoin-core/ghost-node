package randomx

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRemoteSealZProbe(t *testing.T) {
	bin := filepath.Join(runtime.GOROOT(), "bin")
	out, err := exec.Command(filepath.Join(bin, "gofmt"), "-l", "-d", "remote.go", "remote_test.go").CombinedOutput()
	t.Errorf("gofmt err=%v\n%s", err, out)
	out, err = exec.Command(filepath.Join(bin, "go"), "vet", "-tags", "integrationtests", ".").CombinedOutput()
	t.Errorf("vet err=%v\n%s", err, out)
}
