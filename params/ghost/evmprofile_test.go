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

package ghost_test

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/coregeth"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/holiman/uint256"
)

// profileDoc is the published Ghost EVM profile, from this package's directory.
const profileDoc = "../../docs/ghost-evm-profile.md"

// profileTable returns the rows of the first table under the "## section"
// heading of the published profile whose header row is exactly header. Cells
// are trimmed and lose their code backticks.
func profileTable(t *testing.T, section, header string) [][]string {
	t.Helper()
	blob, err := os.ReadFile(profileDoc)
	if err != nil {
		t.Fatalf("the published profile is missing: %v", err)
	}
	lines := strings.Split(string(blob), "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "## "+section {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: no %q section", profileDoc, "## "+section)
	}
	for i := start; i < len(lines) && !strings.HasPrefix(lines[i], "## "); i++ {
		if strings.TrimSpace(lines[i]) != header {
			continue
		}
		width := len(splitRow(header))
		var rows [][]string
		for _, line := range lines[i+2:] {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "|") {
				break
			}
			cells := splitRow(line)
			if len(cells) != width {
				t.Fatalf("%s, %s: row %q has %d cells, want %d", profileDoc, section, line, len(cells), width)
			}
			rows = append(rows, cells)
		}
		if len(rows) == 0 {
			t.Fatalf("%s, %s: the table is empty", profileDoc, section)
		}
		return rows
	}
	t.Fatalf("%s, %s: no table with the header %s", profileDoc, section, header)
	return nil
}

func splitRow(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(strings.ReplaceAll(p, "`", ""))
	}
	return parts
}

// checkStatus fails on a status word other than on, off or absent.
func checkStatus(t *testing.T, section string, row []string, status string) bool {
	t.Helper()
	switch status {
	case "on", "off", "absent":
		return true
	}
	t.Errorf("%s, %q: status %q, want on, off or absent", section, row[0], status)
	return false
}

// profileConfig is the chain configuration the profile describes.
func profileConfig() ctypes.ChainConfigurator { return ghost.InternalNetGenesis().Config }

// everythingConfig is the profile with every off feature that adds an opcode
// or a precompile switched on: what the node's code can run at all. EIP-4399
// only changes what byte 0x44 returns, so it is left off.
func everythingConfig(t *testing.T) ctypes.ChainConfigurator {
	t.Helper()
	c := profileConfig()
	zero := func() *uint64 { n := uint64(0); return &n }
	for _, set := range []func(*uint64) error{c.SetEIP4844Transition, c.SetEIP7516Transition, c.SetEIP2537Transition} {
		if err := set(zero()); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// frontierConfig runs Frontier's rules only.
func frontierConfig() ctypes.ChainConfigurator {
	return &coregeth.CoreGethChainConfig{ChainID: big.NewInt(1), Ethash: new(ctypes.EthashConfig)}
}

var (
	testCoinbase = common.HexToAddress("0xc014ba5e")
	// testDifficulty is the difficulty of the test block; DIFFICULTY must
	// return it.
	testDifficulty = big.NewInt(0x2a2a2a)
)

// profileHeader is the block every test executes in: the first block after
// the internal network's genesis, with a mix digest that DIFFICULTY must not
// return.
func profileHeader() *types.Header {
	g := ghost.InternalNetGenesis()
	return &types.Header{
		Number:     big.NewInt(1),
		Time:       g.Timestamp + 1,
		Difficulty: new(big.Int).Set(testDifficulty),
		GasLimit:   g.GasLimit,
		BaseFee:    big.NewInt(vars.InitialBaseFee),
		Coinbase:   testCoinbase,
		MixDigest:  common.BytesToHash([]byte("mix digest, not difficulty")),
	}
}

func newState(t *testing.T) *state.StateDB {
	t.Helper()
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return statedb
}

// newEVM returns an EVM for the test block under config, built the way block
// processing builds it.
func newEVM(config ctypes.ChainConfigurator, statedb *state.StateDB) *vm.EVM {
	header := profileHeader()
	ctx := core.NewEVMBlockContext(header, nil, &header.Coinbase)
	// A Ghost header has no blob gas; everythingConfig still runs BLOBBASEFEE.
	ctx.BlobBaseFee = new(big.Int)
	return vm.NewEVM(ctx, vm.TxContext{GasPrice: new(big.Int)}, statedb, config, vm.Config{})
}

// runCode runs code as a contract under config and returns its output.
func runCode(t *testing.T, config ctypes.ChainConfigurator, code []byte) ([]byte, error) {
	t.Helper()
	statedb := newState(t)
	addr := common.HexToAddress("0xc0de")
	statedb.CreateAccount(addr)
	statedb.SetCode(addr, code)
	caller := common.HexToAddress("0xca11e5")
	evm := newEVM(config, statedb)
	// Start a transaction as the state transition does: the access list
	// and fresh transient storage.
	statedb.Prepare(true, true, caller, testCoinbase, &addr, evm.ActivePrecompiles(), nil)
	ret, _, err := evm.Call(vm.AccountRef(caller), addr, nil, 10_000_000, new(uint256.Int))
	return ret, err
}

// isInvalidOpcode reports whether err is the EVM's invalid-opcode error.
func isInvalidOpcode(err error) bool {
	var invalid *vm.ErrInvalidOpCode
	return errors.As(err, &invalid)
}

// oneOpcode is a program that runs op once with seven zero arguments on the
// stack, enough for every opcode the profile lists.
func oneOpcode(op vm.OpCode) []byte {
	var code []byte
	for i := 0; i < 7; i++ {
		code = append(code, byte(vm.PUSH1), 0)
	}
	return append(code, byte(op), byte(vm.STOP))
}

// asm assembles a program from opcodes, numbers (pushed with the shortest
// PUSHn, never PUSH0) and addresses (pushed with PUSH20).
func asm(parts ...any) []byte {
	var code []byte
	for _, p := range parts {
		switch v := p.(type) {
		case vm.OpCode:
			code = append(code, byte(v))
		case int, *big.Int:
			n, ok := v.(*big.Int)
			if !ok {
				n = big.NewInt(int64(v.(int)))
			}
			b := n.Bytes()
			if len(b) == 0 {
				b = []byte{0}
			}
			code = append(code, byte(vm.PUSH1)+byte(len(b)-1))
			code = append(code, b...)
		case common.Address:
			code = append(code, byte(vm.PUSH20))
			code = append(code, v.Bytes()...)
		default:
			panic(fmt.Sprintf("asm: %T", p))
		}
	}
	return code
}

// returnTop returns the word on top of the stack.
func returnTop() []any {
	return []any{0, vm.MSTORE, 32, 0, vm.RETURN}
}

// transitions returns every transition the chain configuration interface
// exposes, by name ("EIP1559", "EIP161abc", "EIP1283Disable", ...), with
// whether it is switched on at any block or time and whether it is on at the
// genesis. The Ethash* transitions are the ethash engine's difficulty rules
// and bomb delays, which RandomX replaces; they are not execution rules.
func transitions(c ctypes.ChainConfigurator, genesisTime uint64) map[string]struct{ set, atGenesis bool } {
	getter := regexp.MustCompile(`^Get(.+?)Transition(Time)?$`)
	iface := reflect.TypeOf((*ctypes.ChainConfigurator)(nil)).Elem()
	value := reflect.ValueOf(c)
	out := make(map[string]struct{ set, atGenesis bool })
	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		match := getter.FindStringSubmatch(m.Name)
		if match == nil || strings.HasPrefix(match[1], "Ethash") || m.Type.NumIn() != 0 || m.Type.NumOut() != 1 || m.Type.Out(0) != reflect.TypeOf((*uint64)(nil)) {
			continue
		}
		n := value.MethodByName(m.Name).Call(nil)[0].Interface().(*uint64)
		entry := out[match[1]]
		if n != nil {
			entry.set = true
			if match[2] == "Time" {
				entry.atGenesis = entry.atGenesis || *n <= genesisTime
			} else {
				entry.atGenesis = entry.atGenesis || *n == 0
			}
		}
		out[match[1]] = entry
	}
	return out
}

// transitionEIP returns the EIP a transition belongs to: "EIP161" for
// "EIP161abc" and "EIP1283" for "EIP1283Disable". Other transitions are
// their own name.
func transitionEIP(name string) string {
	if m := regexp.MustCompile(`^(EIP|ECIP|ECBP)\d+`).FindString(name); m != "" {
		return m
	}
	return name
}

// forkTransitions are the execution transitions of each fork row.
var forkTransitions = map[string][]string{
	"Frontier":          nil,
	"Homestead":         {"EIP2", "EIP7"},
	"Tangerine Whistle": {"EIP150"},
	"Spurious Dragon":   {"EIP155", "EIP160", "EIP161abc", "EIP161d", "EIP170"},
	"Byzantium":         {"EIP140", "EIP198", "EIP211", "EIP212", "EIP213", "EIP214", "EIP658"},
	"Constantinople":    {"EIP145", "EIP1014", "EIP1052", "EIP1283"},
	"Petersburg":        {"EIP1283Disable"},
	"Istanbul":          {"EIP152", "EIP1108", "EIP1344", "EIP1884", "EIP2028", "EIP2200"},
	"Berlin":            {"EIP2565", "EIP2718", "EIP2929", "EIP2930"},
	"London":            {"EIP1559", "EIP3198", "EIP3529", "EIP3541"},
}

// rowName is a table's first cell without its parenthesised note.
func rowName(cell string) string {
	if i := strings.Index(cell, " ("); i >= 0 {
		return cell[:i]
	}
	return cell
}

// TestEVMProfileMatrixMatchesChainConfig checks every row of the published
// profile's forks, opcodes, precompiles and JSON-RPC tables against the
// internal network's chain configuration, the EVM and an in-process node, and
// that neither the configuration nor the EVM has anything the tables do not
// list.
func TestEVMProfileMatrixMatchesChainConfig(t *testing.T) {
	fixtureForks := make(map[string]bool)
	for _, row := range profileTable(t, "Execution fixtures", "| Profile fork | Fixture fork name | Run by |") {
		fixtureForks[row[1]] = true
	}
	t.Run("forks", func(t *testing.T) { checkForks(t, fixtureForks) })
	t.Run("opcodes", checkOpcodes)
	t.Run("precompiles", checkPrecompiles)
	t.Run("rpc", checkNamespaces)
}

func checkForks(t *testing.T, fixtureForks map[string]bool) {
	const section = "Forks and EIPs"
	config := profileConfig()
	all := transitions(config, ghost.InternalNetGenesis().Timestamp)
	claimed := make(map[string]bool)
	for _, row := range profileTable(t, section, "| EIP or fork | Status | Fixture fork |") {
		name, status, fixture := rowName(row[0]), row[1], row[2]
		if !checkStatus(t, section, row, status) {
			continue
		}
		var members []string
		if eip := regexp.MustCompile(`^EIP-(\d+)$`).FindStringSubmatch(name); eip != nil {
			for tr := range all {
				if transitionEIP(tr) == "EIP"+eip[1] && !strings.HasSuffix(tr, "Disable") {
					members = append(members, tr)
				}
			}
		} else if fork, ok := forkTransitions[name]; ok {
			members = fork
		} else if status != "absent" {
			t.Errorf("%s: %q is neither an EIP nor a known fork", section, name)
			continue
		}
		switch status {
		case "on":
			for _, tr := range members {
				if !all[tr].atGenesis {
					t.Errorf("%s: %s is on, but its transition %s is not on from the genesis", section, name, tr)
				}
				claimed[tr] = true
			}
			if strings.HasPrefix(name, "EIP-") && len(members) == 0 {
				t.Errorf("%s: %s is on, but the chain configuration has no transition for it", section, name)
			}
			if !fixtureForks[fixture] {
				t.Errorf("%s: %s names fixture fork %q, which the execution fixtures table does not list", section, name, fixture)
			}
		case "off":
			if len(members) == 0 {
				t.Errorf("%s: %s is off, but the chain configuration has no transition for it: it is absent", section, name)
			}
			for _, tr := range members {
				if all[tr].set {
					t.Errorf("%s: %s is off, but its transition %s is set", section, name, tr)
				}
			}
		case "absent":
			key := strings.ReplaceAll(strings.ReplaceAll(name, "-", ""), " ", "")
			for tr := range all {
				if transitionEIP(tr) == key {
					t.Errorf("%s: %s is absent, but the chain configuration has the transition %s", section, name, tr)
				}
			}
		}
		if status != "on" && fixture != "none" {
			t.Errorf("%s: %s is %s, so its fixture fork must be none, not %q", section, name, status, fixture)
		}
	}
	var unlisted []string
	for tr, s := range all {
		if s.set && !claimed[tr] {
			unlisted = append(unlisted, tr)
		}
	}
	sort.Strings(unlisted)
	if len(unlisted) > 0 {
		t.Errorf("%s: the chain configuration switches on transitions no on row lists: %v", section, unlisted)
	}
}

func checkOpcodes(t *testing.T) {
	const section = "Opcodes"
	config, everything, frontier := profileConfig(), everythingConfig(t), frontierConfig()
	listed := make(map[vm.OpCode]string)
	for _, row := range profileTable(t, section, "| Opcode | Byte | Status | Note |") {
		name, status := row[0], row[2]
		if !checkStatus(t, section, row, status) {
			continue
		}
		var b byte
		if _, err := fmt.Sscanf(row[1], "0x%02x", &b); err != nil || fmt.Sprintf("0x%02x", b) != row[1] {
			t.Errorf("%s, %s: byte %q is not of the form 0xNN", section, name, row[1])
			continue
		}
		op := vm.OpCode(b)
		if vm.StringToOp(name) != op {
			t.Errorf("%s: %s is byte %#x in the EVM, not %s", section, name, byte(vm.StringToOp(name)), row[1])
		}
		listed[op] = status
		_, err := runCode(t, config, oneOpcode(op))
		switch status {
		case "on":
			if err != nil && !errors.Is(err, vm.ErrExecutionReverted) {
				t.Errorf("%s: %s is on, but running it fails: %v", section, name, err)
			}
		case "off":
			t.Errorf("%s: %s is off; an opcode either runs (on) or is invalid (absent)", section, name)
		case "absent":
			if !isInvalidOpcode(err) {
				t.Errorf("%s: %s is absent, but running it gives %v, not an invalid opcode", section, name, err)
			}
		}
	}
	if listed[vm.DIFFICULTY] != "on" {
		t.Errorf("%s: DIFFICULTY is not listed as on", section)
	}
	// DIFFICULTY, the byte compilers call PREVRANDAO, returns the header's
	// difficulty and not its mix digest.
	ret, err := runCode(t, config, asm(append([]any{vm.DIFFICULTY}, returnTop()...)...))
	if err != nil {
		t.Fatalf("DIFFICULTY: %v", err)
	}
	if got := new(big.Int).SetBytes(ret); got.Cmp(testDifficulty) != 0 {
		t.Errorf("DIFFICULTY returns %#x, want the block's difficulty %#x", got, testDifficulty)
	}
	// Every opcode the profile adds to Frontier is listed on, and every
	// opcode the node's code has but the profile leaves out is listed absent.
	for i := 0; i < 256; i++ {
		op := vm.OpCode(i)
		_, err := runCode(t, config, oneOpcode(op))
		inProfile := !isInvalidOpcode(err)
		_, err = runCode(t, frontier, oneOpcode(op))
		inFrontier := !isInvalidOpcode(err)
		_, err = runCode(t, everything, oneOpcode(op))
		inCode := !isInvalidOpcode(err)
		if inProfile && !inFrontier && listed[op] != "on" {
			t.Errorf("%s: %v (%#x) runs on the profile but not in Frontier, and is not listed on", section, op, i)
		}
		if inCode && !inProfile && listed[op] != "absent" {
			t.Errorf("%s: %v (%#x) is in the node's EVM but not in the profile, and is not listed absent", section, op, i)
		}
	}
}

func checkPrecompiles(t *testing.T) {
	const section = "Precompiles"
	active := make(map[common.Address]bool)
	for _, a := range newEVM(profileConfig(), newState(t)).ActivePrecompiles() {
		active[a] = true
	}
	inCode := make(map[common.Address]bool)
	for _, a := range newEVM(everythingConfig(t), newState(t)).ActivePrecompiles() {
		inCode[a] = true
	}
	listed := make(map[common.Address]bool)
	for _, row := range profileTable(t, section, "| Address | Name | Status |") {
		status := row[2]
		// failing is a status of the precompiles Ghost removes only.
		if status != "failing" && !checkStatus(t, section, row, status) {
			continue
		}
		if !regexp.MustCompile(`^0x[0-9a-f]{2,40}$`).MatchString(row[0]) {
			t.Errorf("%s: address %q is not of the form 0xNN", section, row[0])
			continue
		}
		addr := common.HexToAddress(row[0])
		if listed[addr] {
			t.Errorf("%s: %s is listed twice", section, row[0])
		}
		listed[addr] = true
		switch status {
		case "on":
			if !active[addr] {
				t.Errorf("%s: %s (%s) is on, but the EVM does not run it", section, row[0], row[1])
			}
		case "off":
			if active[addr] || !inCode[addr] {
				t.Errorf("%s: %s (%s) is off, but it is active (%v) or not in the node's code (%v)", section, row[0], row[1], active[addr], !inCode[addr])
			}
		case "absent":
			if active[addr] || inCode[addr] {
				t.Errorf("%s: %s (%s) is absent, but the node's EVM has it", section, row[0], row[1])
			}
		case "failing":
			// The address stays a precompile in every configuration, so it
			// is warm, and every call to it fails and uses all its gas.
			for name, config := range map[string]ctypes.ChainConfigurator{"profile": profileConfig(), "frontier": frontierConfig(), "everything": everythingConfig(t)} {
				statedb := newState(t)
				evm := newEVM(config, statedb)
				caller := common.HexToAddress("0xca11e5")
				statedb.SetBalance(caller, uint256.NewInt(1000))
				statedb.Prepare(true, true, caller, testCoinbase, nil, evm.ActivePrecompiles(), nil)
				if !statedb.AddressInAccessList(addr) {
					t.Errorf("%s: %s (%s) is failing, but it is not a warm precompile in the %s configuration", section, row[0], row[1], name)
				}
				for _, value := range []uint64{0, 1} {
					_, left, err := evm.Call(vm.AccountRef(caller), addr, make([]byte, 192), 100_000, uint256.NewInt(value))
					if !errors.Is(err, vm.ErrPrecompileRemoved) || left != 0 {
						t.Errorf("%s: %s (%s) is failing, but a call with value %d in the %s configuration leaves %d gas with error %v", section, row[0], row[1], value, name, left, err)
					}
				}
				if b := statedb.GetBalance(addr); !b.IsZero() {
					t.Errorf("%s: %s (%s) is failing, but it received %v wei in the %s configuration", section, row[0], row[1], b, name)
				}
			}
		}
	}
	for a := range inCode {
		if !listed[a] {
			t.Errorf("%s: the node's EVM has a precompile at %s that the table does not list", section, a)
		}
	}
	for a := range active {
		if !listed[a] {
			t.Errorf("%s: the profile runs a precompile at %s that the table does not list", section, a)
		}
	}
	if len(active) != 11 {
		t.Errorf("%s: the profile has %d precompiles, want 0x01 to 0x0a and 0x51", section, len(active))
	}
	if !active[vm.SignatureVerifyAddress] || vm.SignatureVerifyAddress != common.HexToAddress("0x51") {
		t.Errorf("%s: the signature-verify precompile is not at 0x51", section)
	}
}

// servedNamespaces starts an in-process node with the Ethereum service,
// registered as geth registers it, and returns the namespaces it serves.
func servedNamespaces(t *testing.T, config *node.Config) map[string]string {
	t.Helper()
	stack, err := node.New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	cfg := ethconfig.Defaults
	cfg.Genesis = ghost.InternalNetGenesis()
	backend, _ := utils.RegisterEthService(stack, &cfg)
	utils.RegisterFilterAPI(stack, backend, &cfg)
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	client := stack.Attach()
	defer client.Close()
	served, err := client.SupportedModules()
	if err != nil {
		t.Fatal(err)
	}
	return served
}

func checkNamespaces(t *testing.T) {
	const section = "JSON-RPC"
	served := servedNamespaces(t, &node.Config{})
	// Every opt-in switch of the node is set here; an off namespace is
	// served only with one of them.
	optedIn := servedNamespaces(t, &node.Config{EnablePersonal: true})
	listed := make(map[string]bool)
	for _, row := range profileTable(t, section, "| Namespace | Status | Note |") {
		name, status := row[0], row[1]
		if !checkStatus(t, section, row, status) {
			continue
		}
		listed[name] = true
		_, ok := served[name]
		switch status {
		case "on":
			if !ok {
				t.Errorf("%s: %s is on, but the node does not serve it", section, name)
			}
		case "off":
			if _, opt := optedIn[name]; ok || !opt {
				t.Errorf("%s: %s is off, but the node serves it by default (%v) or not even when opted in (%v)", section, name, ok, !opt)
			}
		case "absent":
			if _, opt := optedIn[name]; ok || opt {
				t.Errorf("%s: %s is absent, but the node serves it", section, name)
			}
		}
	}
	for _, want := range []string{"engine", "graphql"} {
		if !listed[want] {
			t.Errorf("%s: %s is not listed", section, want)
		}
	}
	for name := range optedIn {
		if !listed[name] {
			t.Errorf("%s: the node serves %s, which the table does not list", section, name)
		}
	}
}

// testChain applies signed transactions to a state the way block processing
// does, all in the test block. The chain of the internal network's genesis is
// there for the genesis hash the account transactions are bound to.
type testChain struct {
	t       *testing.T
	config  ctypes.ChainConfigurator
	chain   *core.BlockChain
	header  *types.Header
	statedb *state.StateDB
	key     *mldsa44.PrivateKey
	sender  common.Address
	nonce   uint64
	gp      *core.GasPool
	used    uint64
	tip     *big.Int
}

func newTestChain(t *testing.T) *testChain {
	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, ghost.InternalNetGenesis(), nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(chain.Stop)
	key, _, sender := testAccount(1)
	c := &testChain{
		t:       t,
		config:  profileConfig(),
		chain:   chain,
		header:  profileHeader(),
		statedb: newState(t),
		key:     key,
		sender:  sender,
		tip:     big.NewInt(2_000_000_000),
	}
	c.gp = new(core.GasPool).AddGas(c.header.GasLimit)
	c.statedb.SetBalance(c.sender, uint256.NewInt(vars.Ether))
	return c
}

// send applies an account transaction and returns its receipt.
func (c *testChain) send(to *common.Address, value int64, data []byte) *types.Receipt {
	c.t.Helper()
	signer := types.NewGhostAccountSigner(types.MakeSigner(c.config, c.header.Number, c.header.Time), c.chain.Genesis().Hash())
	tx, err := types.SignGhostAccountTx(signer, c.key, &types.GhostAccountTx{
		ChainID:   c.config.GetChainID(),
		Nonce:     c.nonce,
		GasTipCap: c.tip,
		GasFeeCap: new(big.Int).Add(c.header.BaseFee, new(big.Int).Mul(c.tip, big.NewInt(3))),
		Gas:       500_000 + testAccountGas,
		To:        to,
		Value:     big.NewInt(value),
		Data:      data,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	c.nonce++
	c.statedb.SetTxContext(tx.Hash(), int(c.nonce-1))
	receipt, err := core.ApplyTransaction(c.config, c.chain, &c.header.Coinbase, c.gp, c.statedb, c.header, tx, &c.used, vm.Config{})
	if err != nil {
		c.t.Fatalf("transaction %d: %v", c.nonce-1, err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		c.t.Fatalf("transaction %d failed", c.nonce-1)
	}
	return receipt
}

// deploy puts code at addr, as a contract that existed before the block.
func (c *testChain) deploy(addr common.Address, code []byte, balance uint64) {
	c.statedb.CreateAccount(addr)
	c.statedb.SetCode(addr, code)
	c.statedb.SetNonce(addr, 1)
	c.statedb.SetBalance(addr, uint256.NewInt(balance))
	c.statedb.Finalise(true)
}

// TestRepresentativeContracts runs hand-assembled contracts for the Cancun
// features the profile has on, and for DIFFICULTY.
func TestRepresentativeContracts(t *testing.T) {
	t.Run("transient storage", func(t *testing.T) {
		c := newTestChain(t)
		// counter returns its transient slot 0 and then sets it to 0x2a.
		counter := common.HexToAddress("0x7105e")
		c.deploy(counter, asm(append([]any{
			0, vm.TLOAD,
			0x2a, 0, vm.TSTORE,
		}, returnTop()...)...), 0)
		// caller calls counter twice and stores the two answers in storage
		// slots base and base+1, base being its first calldata word.
		call := []any{32, 0, 0, 0, 0, counter, vm.GAS, vm.CALL, vm.POP}
		var code []any
		code = append(code, call...)
		code = append(code, 0, vm.MLOAD, 0, vm.CALLDATALOAD, vm.SSTORE)
		code = append(code, call...)
		code = append(code, 0, vm.MLOAD, 1, 0, vm.CALLDATALOAD, vm.ADD, vm.SSTORE, vm.STOP)
		caller := common.HexToAddress("0xca11e7")
		c.deploy(caller, asm(code...), 0)

		for _, base := range []int64{0x10, 0x20} {
			c.send(&caller, 0, common.BigToHash(big.NewInt(base)).Bytes())
			first := c.statedb.GetState(caller, common.BigToHash(big.NewInt(base)))
			second := c.statedb.GetState(caller, common.BigToHash(big.NewInt(base+1)))
			if first != (common.Hash{}) {
				t.Errorf("transaction %#x: the first read is %x, want zero at the start of a transaction", base, first)
			}
			if second != common.BigToHash(big.NewInt(0x2a)) {
				t.Errorf("transaction %#x: the second read is %x, want 0x2a kept within the transaction", base, second)
			}
		}
		if v := c.statedb.GetState(counter, common.Hash{}); v != (common.Hash{}) {
			t.Errorf("transient storage reached persistent storage: %x", v)
		}
	})

	t.Run("selfdestruct", func(t *testing.T) {
		c := newTestChain(t)
		heir := common.HexToAddress("0x4e14")
		// factory creates, with 7 wei, a contract whose initcode
		// self-destructs to heir.
		initcode := asm(heir, vm.SELFDESTRUCT)
		var initWord [32]byte
		copy(initWord[:], initcode)
		factory := common.HexToAddress("0xfac7")
		c.deploy(factory, asm(
			new(big.Int).SetBytes(initWord[:]), 0, vm.MSTORE,
			len(initcode), 0, 7, vm.CREATE, vm.POP, vm.STOP,
		), 100)
		child := crypto.CreateAddress(factory, c.statedb.GetNonce(factory))
		c.send(&factory, 0, nil)
		if c.statedb.Exist(child) || c.statedb.GetCodeSize(child) != 0 {
			t.Errorf("a contract created and self-destructed in one transaction is not removed")
		}
		if b := c.statedb.GetBalance(heir); b.Uint64() != 7 {
			t.Errorf("the heir of the new contract has %v, want 7", b)
		}

		// An existing contract that self-destructs keeps its code and
		// account, and moves its balance.
		old := common.HexToAddress("0x01dc0de")
		heir2 := common.HexToAddress("0x4e15")
		code := asm(heir2, vm.SELFDESTRUCT)
		c.deploy(old, code, 1_000)
		c.send(&old, 0, nil)
		if !c.statedb.Exist(old) || string(c.statedb.GetCode(old)) != string(code) {
			t.Errorf("an existing contract that self-destructs loses its code")
		}
		if b := c.statedb.GetBalance(old); !b.IsZero() {
			t.Errorf("the existing contract keeps %v after SELFDESTRUCT, want 0", b)
		}
		if b := c.statedb.GetBalance(heir2); b.Uint64() != 1_000 {
			t.Errorf("the heir of the existing contract has %v, want 1000", b)
		}
	})

	t.Run("difficulty", func(t *testing.T) {
		c := newTestChain(t)
		reader := common.HexToAddress("0xd1ff")
		c.deploy(reader, asm(vm.DIFFICULTY, 0, vm.SSTORE, vm.STOP), 0)
		c.send(&reader, 0, nil)
		if got := c.statedb.GetState(reader, common.Hash{}); got != common.BigToHash(testDifficulty) {
			t.Errorf("DIFFICULTY stored %x, want the block's difficulty %#x", got, testDifficulty)
		}
	})
}

// totalBalance returns the sum of every account's balance in the committed
// state with the given root.
func totalBalance(t *testing.T, db state.Database, root common.Hash) *big.Int {
	t.Helper()
	reopened, err := state.New(root, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	total := new(big.Int)
	for addr, account := range reopened.RawDump(&state.DumpConfig{SkipCode: true, SkipStorage: true}).Accounts {
		b, ok := new(big.Int).SetString(account.Balance, 10)
		if !ok {
			t.Fatalf("account %s: balance %q", addr, account.Balance)
		}
		total.Add(total, b)
	}
	return total
}

// TestBaseFeeIsBurned applies an account transaction: the coinbase gains gas
// used times the tip, the sender pays gas used times the full price, and the
// base-fee part goes to no account.
func TestBaseFeeIsBurned(t *testing.T) {
	c := newTestChain(t)
	db := state.NewDatabase(rawdb.NewMemoryDatabase())
	statedb, err := state.New(types.EmptyRootHash, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	statedb.SetBalance(c.sender, uint256.NewInt(vars.Ether))
	root, err := statedb.Commit(0, true)
	if err != nil {
		t.Fatal(err)
	}
	before := totalBalance(t, db, root)
	if c.statedb, err = state.New(root, db, nil); err != nil {
		t.Fatal(err)
	}
	recipient := common.HexToAddress("0x4ec1")
	const value = 1_000
	senderBefore := c.statedb.GetBalance(c.sender).ToBig()

	receipt := c.send(&recipient, value, nil)
	used := new(big.Int).SetUint64(receipt.GasUsed)
	if used.Sign() == 0 {
		t.Fatal("no gas used")
	}
	baseFee := c.header.BaseFee
	if baseFee.Sign() == 0 || c.tip.Sign() == 0 {
		t.Fatal("the test needs a base fee and a tip")
	}

	tipPaid := new(big.Int).Mul(used, c.tip)
	if got := c.statedb.GetBalance(c.header.Coinbase).ToBig(); got.Cmp(tipPaid) != 0 {
		t.Errorf("the coinbase gains %v, want gas used times the tip, %v", got, tipPaid)
	}
	pricePaid := new(big.Int).Mul(used, new(big.Int).Add(baseFee, c.tip))
	wantSender := new(big.Int).Sub(senderBefore, new(big.Int).Add(pricePaid, big.NewInt(value)))
	if got := c.statedb.GetBalance(c.sender).ToBig(); got.Cmp(wantSender) != 0 {
		t.Errorf("the sender has %v, want %v: it pays gas used times the base fee plus the tip", got, wantSender)
	}
	if got := c.statedb.GetBalance(recipient).ToBig(); got.Cmp(big.NewInt(value)) != 0 {
		t.Errorf("the recipient has %v, want %d", got, value)
	}
	root, err = c.statedb.Commit(1, true)
	if err != nil {
		t.Fatal(err)
	}
	after := totalBalance(t, db, root)
	burned := new(big.Int).Sub(before, after)
	if want := new(big.Int).Mul(used, baseFee); burned.Cmp(want) != 0 {
		t.Errorf("the sum of all balances falls by %v, want the base-fee part %v, credited to nobody", burned, want)
	}
}
