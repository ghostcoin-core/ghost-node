// Copyright 2026 The Ghost Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mainnetHeaders reads testdata/mainnet.headers.hex, real Bitcoin mainnet
// headers 971712 to 971714, the first of them the checkpoint.
func mainnetHeaders(t *testing.T) []byte {
	t.Helper()
	stored, err := os.ReadFile(filepath.Join("testdata", "mainnet.headers.hex"))
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, line := range strings.Fields(string(stored)) {
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != BitcoinHeaderSize {
			t.Fatalf("testdata/mainnet.headers.hex: bad line %q", line)
		}
		raw = append(raw, b...)
	}
	return raw
}

// mainnetHashes are the hashes of the mainnet headers, as Bitcoin prints
// them.
var mainnetHashes = []string{
	"00000000000000000000c185f0906690a08d62d6fe842682a888d5560217e467",
	"000000000000000000001124b83cb51bf2f9b8f74172ef0a5f2eef429a666b27",
	"0000000000000000000138485e62e351a291965229fce91e716331049000095b",
}

// writeHeaders writes raw headers to a temporary file and returns its path.
func writeHeaders(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runRelease runs the command as the binary runs it, on a header file.
func runRelease(t *testing.T, raw []byte) error {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run([]string{"derive", "-tl", strconv.Itoa(fixtureTL), "-headers", writeHeaders(t, raw)}, &stdout, &stderr)
	if err != nil && stdout.Len() != 0 {
		t.Fatalf("a refused derivation printed %q", stdout.String())
	}
	return err
}

func TestRealMainnetHeadersAccepted(t *testing.T) {
	raw := mainnetHeaders(t)
	c := mainnetChain()
	tree, err := readHeaders(c, raw)
	if err != nil {
		t.Fatalf("real mainnet headers refused: %v", err)
	}
	if len(tree.nodes) != len(mainnetHashes) {
		t.Fatalf("%d headers read, want %d", len(tree.nodes), len(mainnetHashes))
	}
	for i, n := range tree.nodes {
		display := Display(n.hash)
		if got := hex.EncodeToString(display[:]); got != mainnetHashes[i] {
			t.Errorf("header %d hash %s, want %s", i, got, mainnetHashes[i])
		}
		if n.height != 971712+i {
			t.Errorf("header %d height %d, want %d", i, n.height, 971712+i)
		}
		if n.header.Bits != 0x17020093 {
			t.Errorf("header %d bits %#08x", i, n.header.Bits)
		}
	}
	// The headers pass every check; three are too few for a median time
	// past, so no block reaches T_L yet, through Derive and the command.
	if _, err := Derive(fixtureTL, raw); !errors.Is(err, ErrNotReached) {
		t.Errorf("Derive: error %v, want %v", err, ErrNotReached)
	}
	if err := runRelease(t, raw); !errors.Is(err, ErrNotReached) {
		t.Errorf("command: error %v, want %v", err, ErrNotReached)
	}
	// Any one of them changed is refused.
	tampered := append([]byte{}, raw...)
	tampered[2*BitcoinHeaderSize+72]++ // the bits of 971714
	if _, err := Derive(fixtureTL, tampered); err == nil {
		t.Error("real headers with changed bits accepted")
	}
}

func TestCheckpointRejectsWrongFirstHeader(t *testing.T) {
	// The pinned checkpoint is the first real header, at a period start.
	raw := mainnetHeaders(t)
	c := mainnetChain()
	first, err := decodeBitcoinHeader(raw[:BitcoinHeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if first.Hash() != c.checkpointHash || first.Bits != c.checkpointBits || c.checkpointHeight != 971712 {
		t.Fatalf("mainnet checkpoint %x at %d, bits %#08x, is not header 971712", Display(c.checkpointHash), c.checkpointHeight, c.checkpointBits)
	}
	if c.checkpointHeight%RetargetInterval != 0 {
		t.Fatalf("mainnet checkpoint height %d does not start a difficulty period", c.checkpointHeight)
	}

	// Real mainnet headers with valid proof of work, starting after the
	// checkpoint, or with the checkpoint later in the file.
	for name, headers := range map[string][]byte{
		"starts at 971713":      raw[BitcoinHeaderSize:],
		"starts at 971714":      raw[2*BitcoinHeaderSize:],
		"checkpoint at the end": append(append([]byte{}, raw[BitcoinHeaderSize:]...), raw[:BitcoinHeaderSize]...),
	} {
		if _, err := Derive(fixtureTL, headers); !errors.Is(err, ErrCheckpoint) {
			t.Errorf("%s: error %v, want %v", name, err, ErrCheckpoint)
		}
		if err := runRelease(t, headers); !errors.Is(err, ErrCheckpoint) {
			t.Errorf("%s, command: error %v, want %v", name, err, ErrCheckpoint)
		}
	}

	// On a test chain, a first header other than its checkpoint is refused,
	// and so is the checkpoint with bits other than the checkpoint's.
	main := mainBranch(t, fixtureMainLen)
	headers := rawHeaders(main)
	if _, err := deriveOn(fixtureChain(t, main[1], 1), fixtureTL, headers); !errors.Is(err, ErrCheckpoint) {
		t.Errorf("test chain, block 0 first: error %v, want %v", err, ErrCheckpoint)
	}
	otherBits := fixtureChain(t, main[0], 0)
	otherBits.checkpointBits = 0x201fffff
	if _, err := deriveOn(otherBits, fixtureTL, headers); !errors.Is(err, ErrCheckpoint) {
		t.Errorf("test chain, checkpoint bits differ: error %v, want %v", err, ErrCheckpoint)
	}
	if _, err := deriveOn(fixtureChain(t, main[0], 0), fixtureTL, headers); err != nil {
		t.Errorf("test chain at its checkpoint: %v", err)
	}
}

func TestRejectsSyntheticEasyChain(t *testing.T) {
	checkpoint := mainnetHeaders(t)[:BitcoinHeaderSize]
	c := mainnetChain()

	// The pinned checkpoint followed by cheaply mined headers at 0x207fffff:
	// their proof of work meets their own bits, but those bits are above
	// mainnet's proof-of-work limit and not the checkpoint's.
	var synthetic []fixtureHeader
	prev := c.checkpointHash
	for i := 0; i < fixtureMainLen; i++ {
		h := mineFixtureHeader(t, prev, "on the checkpoint "+strconv.Itoa(i), 1_780_000_000+uint32(i)*fixtureSpacing)
		synthetic = append(synthetic, h)
		prev = h.hash
	}
	onCheckpoint := append(append([]byte{}, checkpoint...), rawHeaders(synthetic)...)
	if _, err := Derive(fixtureTL, onCheckpoint); !errors.Is(err, ErrBits) {
		t.Errorf("checkpoint and easy headers: error %v, want %v", err, ErrBits)
	}
	if err := runRelease(t, onCheckpoint); !errors.Is(err, ErrBits) {
		t.Errorf("checkpoint and easy headers, command: error %v, want %v", err, ErrBits)
	}
	// The difficulty rules refuse them on their own, even under a
	// proof-of-work limit that admits their bits.
	easy := c
	easy.powLimit = fixturePowLimit(t)
	if _, err := deriveOn(easy, fixtureTL, onCheckpoint); !errors.Is(err, ErrDifficulty) {
		t.Errorf("checkpoint and easy headers, easy limit: error %v, want %v", err, ErrDifficulty)
	}
	h, _ := decodeBitcoinHeader(synthetic[0].raw[:])
	if _, err := h.checkProofOfWork(c.powLimit); !errors.Is(err, ErrBits) {
		t.Errorf("an easy header under mainnet's limit: error %v, want %v", err, ErrBits)
	}

	// A whole chain of easy headers, the normal fixture, which derives a
	// genesis on its own test chain.
	_, whole := loadFixture(t, "normal")
	if _, err := deriveOn(normalChain(t), fixtureTL, whole); err != nil {
		t.Fatalf("the normal fixture on its test chain: %v", err)
	}
	if _, err := Derive(fixtureTL, whole); !errors.Is(err, ErrBits) {
		t.Errorf("easy chain: error %v, want %v", err, ErrBits)
	}
	if err := runRelease(t, whole); !errors.Is(err, ErrBits) {
		t.Errorf("easy chain, command: error %v, want %v", err, ErrBits)
	}
	// The checkpoint refuses it on its own, even under the easy limit.
	if _, err := deriveOn(easy, fixtureTL, whole); !errors.Is(err, ErrCheckpoint) {
		t.Errorf("easy chain, easy limit: error %v, want %v", err, ErrCheckpoint)
	}
}

// minePeriod mines a branch of n test-chain headers at fixtureBits, spacing
// seconds apart.
func minePeriod(t *testing.T, label string, n int, spacing uint32) []fixtureHeader {
	t.Helper()
	var out []fixtureHeader
	prev := fixtureAnchorParent()
	for i := 0; i < n; i++ {
		h := mineFixtureHeader(t, prev, label+" "+strconv.Itoa(i), 1_700_000_000+uint32(i)*spacing)
		out = append(out, h)
		prev = h.hash
	}
	return out
}

func TestDifficultyRetarget(t *testing.T) {
	limit := mainnetChain().powLimit
	want := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1))
	if limit.Cmp(want) != 0 {
		t.Fatalf("mainnet proof-of-work limit %x, want 2^224 - 1", limit)
	}
	const start = 1_700_000_000
	for _, c := range []struct {
		name     string
		bits     uint32
		timespan int64
		want     uint32
	}{
		{"on time", 0x17020093, TargetTimespan, 0x17020093},
		{"half the time", 0x17020093, TargetTimespan / 2, 0x17010049},
		{"a quarter of the time", 0x17020093, TargetTimespan / 4, 0x17008024},
		{"faster than a quarter, clamped", 0x17020093, TargetTimespan/4 - 1, 0x17008024},
		{"one second, clamped", 0x17020093, 1, 0x17008024},
		{"backwards in time, clamped", 0x17020093, -TargetTimespan, 0x17008024},
		{"twice the time", 0x17020093, TargetTimespan * 2, 0x17040126},
		{"four times the time", 0x17020093, TargetTimespan * 4, 0x1708024c},
		{"slower than four times, clamped", 0x17020093, TargetTimespan*4 + 1, 0x1708024c},
		{"ten times the time, clamped", 0x17020093, TargetTimespan * 10, 0x1708024c},
		{"at the limit, on time", 0x1d00ffff, TargetTimespan, 0x1d00ffff},
		{"at the limit, slow, capped", 0x1d00ffff, TargetTimespan * 4, 0x1d00ffff},
		{"near the limit, slow, capped", 0x1c7fffff, TargetTimespan * 4, 0x1d00ffff},
		{"at the limit, fast", 0x1d00ffff, TargetTimespan / 4, 0x1c3fffc0},
	} {
		got, err := nextBits(limit, c.bits, start, uint32(start+c.timespan))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: bits %#08x, want %#08x", c.name, got, c.want)
		}
	}
	for _, bits := range []uint32{0x17020093, 0x1d00ffff, 0x207fffff, 0x1c3fffc0, 0x03123456, 0x02008000} {
		target, err := compactTarget(bits)
		if err != nil {
			t.Fatal(err)
		}
		if got := compactBits(target); got != bits {
			t.Errorf("compact bits of the target of %#08x: %#08x", bits, got)
		}
	}

	// On a test chain from a checkpoint at height 2016, the period's 2016
	// blocks one second apart: block 4032 retargets to a quarter of the
	// target, the clamp, and must carry those bits.
	fast := minePeriod(t, "fast", RetargetInterval, 1)
	fastChain := fixtureChain(t, fast[0], RetargetInterval)
	last := fast[len(fast)-1]
	lastTime := uint32(1_700_000_000 + RetargetInterval - 1)
	for _, c := range []struct {
		name string
		bits uint32
		want error
	}{
		{"retarget bits", 0x201fffff, nil},
		{"the parent's bits at a retarget", fixtureBits, ErrDifficulty},
		{"bits other than the retarget's", 0x200fffff, ErrDifficulty},
	} {
		h := mineHeader(t, last.hash, "fast 4032 "+c.name, lastTime+1, c.bits)
		raw := append(rawHeaders(fast), h.raw[:]...)
		if _, err := readHeaders(fastChain, raw); !errors.Is(err, c.want) {
			t.Errorf("block 4032, %s: error %v, want %v", c.name, err, c.want)
		}
	}
	// Bits change only at a retarget: block 4031 must keep its parent's.
	h4031 := mineHeader(t, fast[len(fast)-2].hash, "fast 4031 retargeted", lastTime, 0x201fffff)
	if _, err := readHeaders(fastChain, append(rawHeaders(fast[:len(fast)-1]), h4031.raw[:]...)); !errors.Is(err, ErrDifficulty) {
		t.Errorf("block 4031 with new bits: error %v, want %v", err, ErrDifficulty)
	}

	// A slow period, ten hours a block, would ease the target past the
	// test chain's limit: block 4032 is capped at the limit.
	slow := minePeriod(t, "slow", RetargetInterval, 36000)
	slowChain := fixtureChain(t, slow[0], RetargetInterval)
	slowTime := uint32(1_700_000_000 + (RetargetInterval-1)*36000)
	for _, c := range []struct {
		name string
		bits uint32
		want error
	}{
		{"the limit", fixtureBits, nil},
		{"harder than the limit", 0x201fffff, ErrDifficulty},
	} {
		h := mineHeader(t, slow[len(slow)-1].hash, "slow 4032 "+c.name, slowTime+1, c.bits)
		if _, err := readHeaders(slowChain, append(rawHeaders(slow), h.raw[:]...)); !errors.Is(err, c.want) {
			t.Errorf("slow block 4032, %s: error %v, want %v", c.name, err, c.want)
		}
	}

	// No minimum-difficulty rule: a block two hours after its parent, off a
	// retarget, keeps its parent's bits and may not take the limit's.
	hard := mineHeader(t, fixtureAnchorParent(), "hard checkpoint", 1_700_000_000, 0x201fffff)
	hardChain := fixtureChain(t, hard, 1)
	for _, c := range []struct {
		name string
		bits uint32
		want error
	}{
		{"the parent's bits", 0x201fffff, nil},
		{"the limit's bits", fixtureBits, ErrDifficulty},
	} {
		h := mineHeader(t, hard.hash, "two hours later "+c.name, 1_700_000_000+7200, c.bits)
		if _, err := readHeaders(hardChain, append(append([]byte{}, hard.raw[:]...), h.raw[:]...)); !errors.Is(err, c.want) {
			t.Errorf("two hours later, %s: error %v, want %v", c.name, err, c.want)
		}
	}

	// A retarget whose period starts before the checkpoint is refused.
	late := fixtureChain(t, fast[0], 2*RetargetInterval-1)
	h := mineHeader(t, fast[0].hash, "after a late checkpoint", 1_700_000_001, fixtureBits)
	if _, err := readHeaders(late, append(append([]byte{}, fast[0].raw[:]...), h.raw[:]...)); !errors.Is(err, ErrDifficulty) {
		t.Errorf("retarget before the checkpoint: error %v, want %v", err, ErrDifficulty)
	}
}

// releaseViolations reads the non-test Go files of dir and returns every
// way they could give the shipped command a chain other than mainnet: a
// chain value built outside mainnetChain, a chain variable, a change to a
// chain's fields, the easy bits of the test chains, an environment variable,
// a flag other than -tl and -headers, or a package variable other than an
// error.
func releaseViolations(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no command source in %s", dir)
	}
	var out []string
	report := func(n ast.Node, format string, args ...any) {
		out = append(out, fset.Position(n.Pos()).String()+": "+fmt.Sprintf(format, args...))
	}
	isChain := func(e ast.Expr) bool {
		if s, ok := e.(*ast.StarExpr); ok {
			e = s.X
		}
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "chain"
	}
	// The fields of the chain type.
	fields := make(map[string]bool)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.Name == "chain" {
				if st, ok := ts.Type.(*ast.StructType); ok {
					for _, field := range st.Fields.List {
						for _, name := range field.Names {
							fields[name.Name] = true
						}
					}
				}
			}
			return true
		})
	}
	if !fields["checkpointHash"] || !fields["powLimit"] {
		out = append(out, "no chain type with a checkpoint and a proof-of-work limit")
	}
	literals := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			fn := ""
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
			}
			if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						var value ast.Expr
						if i < len(vs.Values) {
							value = vs.Values[i]
						}
						if call, ok := value.(*ast.CallExpr); !ok || !isSelector(call.Fun, "errors", "New") {
							report(name, "package variable %s is not an error", name.Name)
						}
					}
				}
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					v := strings.ToLower(n.Value)
					if n.Kind == token.INT {
						if u, err := strconv.ParseUint(strings.ReplaceAll(v, "_", ""), 0, 64); err == nil && u == fixtureBits {
							report(n, "the easy bits %s", n.Value)
						}
					}
					if n.Kind == token.STRING && strings.Contains(v, "207fffff") {
						report(n, "the easy bits in %s", n.Value)
					}
				case *ast.CompositeLit:
					if isChain(n.Type) {
						literals++
						if fn != "mainnetChain" {
							report(n, "a chain built outside mainnetChain")
						}
					}
				case *ast.ValueSpec:
					if n.Type != nil && isChain(n.Type) {
						report(n, "a chain variable")
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 && isChain(n.Args[0]) {
						report(n, "a chain built with new")
					}
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
						if inner, ok := sel.X.(*ast.SelectorExpr); ok && fields[inner.Sel.Name] && sel.Sel.Name != "Cmp" {
							report(n, "the chain field %s changed by %s", inner.Sel.Name, sel.Sel.Name)
						}
						if isSelector(sel, "os", "Getenv") || isSelector(sel, "os", "LookupEnv") || isSelector(sel, "os", "Environ") {
							report(n, "the environment read")
						}
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "fs" && len(n.Args) > 0 {
							if lit, ok := n.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && lit.Value != `"tl"` && lit.Value != `"headers"` {
								report(n, "the flag %s", lit.Value)
							}
						}
					}
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && fields[sel.Sel.Name] {
							report(n, "the chain field %s assigned", sel.Sel.Name)
						}
					}
				}
				return true
			})
		}
	}
	if literals != 1 {
		out = append(out, fmt.Sprintf("%d chain values built, want mainnetChain's alone", literals))
	}
	return out
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}

func TestReleaseHasNoTestCheckpoint(t *testing.T) {
	// The command's source builds mainnet's chain alone.
	for _, v := range releaseViolations(t, ".") {
		t.Error(v)
	}
	// Its one chain is mainnet's, at the pinned checkpoint.
	c := mainnetChain()
	display := Display(c.checkpointHash)
	if hex.EncodeToString(display[:]) != mainnetHashes[0] || c.checkpointHeight != 971712 || c.checkpointBits != 0x17020093 {
		t.Errorf("mainnet chain checkpoint %x at %d, bits %#08x", display, c.checkpointHeight, c.checkpointBits)
	}
	if c.powLimit.Cmp(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 224), big.NewInt(1))) != 0 {
		t.Errorf("mainnet chain proof-of-work limit %x", c.powLimit)
	}

	// The check finds each way a test chain could reach the command.
	const good = `package main

import "errors"

var ErrX = errors.New("x")

type chain struct {
	checkpointHash [32]byte
	powLimit       int
}

func mainnetChain() chain { return chain{} }
`
	for name, src := range map[string]string{
		"test checkpoint variable": "var testChain = chain{}\n",
		"test checkpoint function": "func testChain() chain { return chain{powLimit: 1} }\n",
		"easy bits":                "const easyBits = 0x207fffff\n",
		"easy bits in a string":    "const easyBits = \"207fffff\"\n",
		"easy pow limit variable":  "var easyLimit = 1\n",
		"changed limit":            "func ease(c *chain) { c.powLimit = 1 }\n",
		"local chain variable":     "func zero() { var c chain; _ = c }\n",
		"environment":              "import \"os\"\n\nfunc env() string { return os.Getenv(\"X\") }\n",
		"another flag":             "import \"flag\"\n\nfunc flags(fs *flag.FlagSet) { fs.String(\"checkpoint\", \"\", \"\") }\n",
	} {
		if len(sourceViolations(t, good, src)) == 0 {
			t.Errorf("%s: not found", name)
		}
	}
	// A test file may hold all of it.
	if v := sourceViolations(t, good, ""); len(v) != 0 {
		t.Errorf("a test chain in a test file: %v", v)
	}
}

// sourceViolations writes a package of the source main, a non-test file of
// extra if it is not empty, and a test file that builds a test chain, and
// returns the violations releaseViolations finds in it.
func sourceViolations(t *testing.T, main, extra string) []string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"main.go":       main,
		"main_test.go":  "package main\n\nvar testChain = chain{powLimit: 1}\n\nconst easyBits = 0x207fffff\n",
		"extra_test.go": "package main\n\nfunc ease(c *chain) { c.powLimit = 1 }\n",
	}
	if extra != "" {
		files["extra.go"] = "package main\n\n" + extra
	}
	for file, content := range files {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return releaseViolations(t, dir)
}
