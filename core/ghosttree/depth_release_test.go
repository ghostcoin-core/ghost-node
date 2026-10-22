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

//go:build !ghosttreetest14

package ghosttree

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestReleaseDepthIsThirtyTwo(t *testing.T) {
	if Release.Depth != 32 {
		t.Fatalf("release depth %d", Release.Depth)
	}
	if err := Release.Check(); err != nil {
		t.Fatalf("release parameters refused: %v", err)
	}
	if Release.capacity() != 1<<32 {
		t.Errorf("release capacity %d", Release.capacity())
	}
	for _, d := range []int{0, 1, 3, 14, 16, 31, 33, 64} {
		if err := (Params{Depth: d}).Check(); !errors.Is(err, ErrDepth) {
			t.Errorf("depth %d: Check %v, want %v", d, err, ErrDepth)
		}
	}
	for _, d := range []int{0, 33} {
		if _, err := root(Params{Depth: d}, newState(t), Coin); !errors.Is(err, ErrDepth) {
			t.Errorf("depth %d: root %v, want %v", d, err, ErrDepth)
		}
	}
	// The frontier of the release tree fills slots 4 to 35 and no more.
	st := newState(t)
	prefill(st, Release, Coin, 0, Release.capacity()-1, 0)
	if _, err := Append(st, Coin, 1, testLeaf(0)); err != nil {
		t.Fatal(err)
	}
	if got := st.GetState(TreeAccount(Coin), Slot(SlotFrontier+32)); got != (common.Hash{}) {
		t.Error("a 33rd frontier slot was written")
	}
	if SlotFrontier+MaxDepth-1 != 35 {
		t.Errorf("the last frontier slot is %d, want 35", SlotFrontier+MaxDepth-1)
	}
}

// refusalName is the undefined name of depth_refuse.go that the compiler
// reports when a release build asks for the test depth.
const refusalName = "ghosttreetest14_is_a_test_only_tree_depth_and_cannot_be_built_with_ghostrelease"

// moduleRoot returns the directory of the go.mod above the package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}

func goTool(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	path := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("go tool not found: %v", err)
	}
	return path
}

func TestReleaseBuildRefusesTestDepth(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the package twice")
	}
	root, gobin := moduleRoot(t), goTool(t)
	build := func(tags string) (string, error) {
		cmd := exec.Command(gobin, "build", "-tags", tags, "./core/ghosttree/")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := build("ghostrelease,ghosttreetest14")
	if err == nil {
		t.Fatal("a build with ghostrelease and ghosttreetest14 succeeded")
	}
	if !strings.Contains(out, refusalName) {
		t.Fatalf("the build failed without the refusal message:\n%s", out)
	}
	if out, err := build("ghostrelease"); err != nil {
		t.Fatalf("the release build failed: %v\n%s", err, out)
	}
}
