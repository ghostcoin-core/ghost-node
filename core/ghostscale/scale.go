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

// Package ghostscale is the scale benchmark of one block: a block of private
// reveals, in bundles, and public transactions, binding transactions under
// one public root, built with the chain maker and then imported, timed, into
// a fresh on-disk node database through the node's block import: the body
// checks, the state processor with its tree and marker updates, the state,
// receipt and tree root checks, the state commit and the header MMR append.
//
// The root proofs of the bundles and the public root are checked by whatever
// verifier is active, which for the benchmark is the stub verifier of the
// tests: the real root proof verifier waits for the stage 2 prover, so the
// time recorded is block execution without root proof verification.
package ghostscale

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/randomx"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/ghostmmr"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
	"github.com/holiman/uint256"
)

const (
	// FullCount is the number of reveals, and of public transactions, of the
	// benchmark block.
	FullCount = 3_500

	// BudgetMs is the time budget of spec 07, section 4, in milliseconds.
	BudgetMs = 3_000

	// BudgetSource names where the budget comes from.
	BudgetSource = "spec 07, section 4"

	// BlocksPerDay is the number of 30-second blocks in a day.
	BlocksPerDay = 2_880

	// Label says how the result was obtained, and Scope what it covers.
	Label = "measured"
	Scope = "block execution without root proof verification"
)

var (
	oneGhost = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	gwei     = big.NewInt(1_000_000_000)

	// miner is the coinbase of the benchmark block.
	miner = common.Address{0xcb, 0x5c}

	// revealOut is what each reveal pays out, and publicValue what each
	// public transaction sends.
	revealOut   = uint256.NewInt(1_000_000_000_000_000)
	publicValue = big.NewInt(1_000_000_000_000)
)

// Config is a benchmark's setting.
type Config struct {
	Reveals int // reveals in the block, in bundles of at most ghostpriv.BundleMaxReveals
	Public  int // public transactions, binding transactions under one public root
	Runs    int // timed imports, each into a fresh database

	// Dir is a directory for the databases of the runs.
	Dir string

	// BundleProof and PublicRootProof return the root proof the active
	// verifier accepts for a bundle or a public root of the given binding
	// digest: the stub proofs of core/ghostpriv/ghostprivtest.
	BundleProof     func(binding common.Hash) []byte
	PublicRootProof func(binding common.Hash) []byte
}

// Bench is a built benchmark: its genesis and the block to import.
type Bench struct {
	cfg        Config
	gspec      *genesisT.Genesis
	genesis    *types.Block
	block      *types.Block
	bundles    int
	recipients []common.Address // of the public transactions
	totalOut   *uint256.Int     // what the reveals take from the hidden set
	bindingGas uint64
}

// synthetic is the i-th value of a tag, a synthetic hash.
func synthetic(tag string, i int) common.Hash {
	return crypto.Keccak256Hash([]byte("ghost/scale-bench/"+tag), binary.BigEndian.AppendUint64(nil, uint64(i)))
}

func syntheticAddress(tag string, i int) common.Address {
	return common.BytesToAddress(synthetic(tag, i).Bytes())
}

// slot is the storage key of slot i of a system account.
func slot(i uint64) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], i)
	return h
}

// Build builds the genesis and the benchmark block. The genesis funds the
// senders of the public transactions, records their key identities as key
// registrations do, and seeds the hidden set with what the reveals take; the
// reveals spend the genesis coin root. The active verifier must accept the
// proofs of Config.BundleProof and Config.PublicRootProof.
func Build(cfg Config) (b *Bench, err error) {
	if cfg.Reveals < 1 || cfg.Public < 1 || cfg.Public > 65_535 {
		return nil, fmt.Errorf("ghostscale: %d reveals and %d public transactions", cfg.Reveals, cfg.Public)
	}
	if cfg.BundleProof == nil || cfg.PublicRootProof == nil {
		return nil, errors.New("ghostscale: no root proofs")
	}
	extra, err := core.GhostBindingExtraIntrinsicGas(types.GhostSchemeMLDSA44)
	if err != nil {
		return nil, err
	}
	b = &Bench{cfg: cfg, bindingGas: 21_000 + extra}

	// The genesis, with a gas limit that holds the block: a bundle takes
	// G_PRIV a reveal, far above the consensus maximum of 30,000,000.
	gspec := ghost.InternalNetGenesis()
	gspec.GasLimit = uint64(cfg.Reveals)*ghostpriv.GasPriv + uint64(cfg.Public)*b.bindingGas
	alloc := genesisT.GenesisAlloc{}
	for addr, acc := range gspec.Alloc {
		alloc[addr] = acc
	}
	registry := make(map[common.Hash]common.Hash, cfg.Public)
	senders := make([]common.Address, cfg.Public)
	identities := make([]common.Hash, cfg.Public)
	for i := range cfg.Public {
		senders[i], identities[i] = syntheticAddress("sender", i), synthetic("key identity", i)
		alloc[senders[i]] = genesisT.GenesisAccount{Balance: new(big.Int).Set(oneGhost)}
		registry[types.GhostKeyRegistryKey(senders[i])] = identities[i]
	}
	alloc[types.GhostKeyRegistryAccount] = genesisT.GenesisAccount{Balance: new(big.Int), Nonce: 1, Storage: registry}
	gspec.Alloc = alloc

	// The window fee of a reveal in block 1.
	genesis0 := core.GenesisToBlock(gspec, nil)
	bRef := genesis0.BaseFee()
	if ghostpriv.WindowStart(1) == 1 {
		bRef = calcBaseFee(gspec, genesis0.Header())
	}
	fee, err := ghostpriv.WindowFeeGas(bRef, ghostpriv.GasPriv)
	if err != nil {
		return nil, err
	}
	perReveal := new(uint256.Int).Add(revealOut, fee.Total)
	b.totalOut = new(uint256.Int).Mul(perReveal, uint256.NewInt(uint64(cfg.Reveals)))
	totalIn := new(uint256.Int).Add(b.totalOut, uint256.MustFromBig(oneGhost))
	alloc[ghost.PrivTotalsAccount] = genesisT.GenesisAccount{
		Balance: new(big.Int),
		Nonce:   1,
		Storage: map[common.Hash]common.Hash{slot(ghostpriv.SlotTotalIn): common.Hash(totalIn.Bytes32())},
	}
	b.gspec = gspec
	b.genesis = core.GenesisToBlock(gspec, nil)
	chainID := gspec.Config.GetChainID().Uint64()
	genesisHash := b.genesis.Hash()
	if b.genesis.Header().CoinTreeRoot == nil || b.genesis.Header().HeaderMmrRoot == nil {
		return nil, errors.New("ghostscale: the genesis has no tree roots or header MMR root")
	}
	root := *b.genesis.Header().CoinTreeRoot

	// The reveals, in bundles.
	reveals := make([]*ghostpriv.Reveal, cfg.Reveals)
	for i := range reveals {
		r := &ghostpriv.Reveal{
			Version:   ghostpriv.RevealVersion,
			ChainID:   chainID,
			Marker:    synthetic("marker", i),
			Root:      root,
			Remainder: synthetic("remainder", i),
			Recipient: syntheticAddress("reveal recipient", i),
			Out:       new(uint256.Int).Set(revealOut),
			Fee:       new(uint256.Int).Set(fee.Total),
		}
		note := synthetic("note", i)
		copy(r.Note[:], note[:])
		reveals[i] = r
	}
	var txs []*types.Transaction
	for chunk := range slices.Chunk(reveals, ghostpriv.BundleMaxReveals) {
		bundle := &ghostpriv.Bundle{Version: ghostpriv.BundleVersion, ChainID: chainID, Reveals: chunk}
		bundle.Proof = cfg.BundleProof(bundle.Inputs(chainID, genesisHash).Binding)
		env, err := bundle.MarshalBinary()
		if err != nil {
			return nil, err
		}
		tx, err := types.NewGhostBundleTx(env)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
		b.bundles++
	}

	// The public transactions under one public root.
	baseFee := calcBaseFee(gspec, b.genesis.Header())
	feeCap := new(big.Int).Add(new(big.Int).Mul(baseFee, big.NewInt(2)), gwei)
	bindingTxs := make([]*types.Transaction, cfg.Public)
	bindings := make([]types.GhostBinding, cfg.Public)
	b.recipients = make([]common.Address, cfg.Public)
	for i := range cfg.Public {
		to := syntheticAddress("public recipient", i)
		b.recipients[i] = to
		inner := &types.GhostBindingTx{
			ChainID:   new(big.Int).SetUint64(chainID),
			GasTipCap: new(big.Int).Set(gwei),
			GasFeeCap: new(big.Int).Set(feeCap),
			Gas:       b.bindingGas,
			To:        &to,
			Value:     new(big.Int).Set(publicValue),
			Scheme:    types.GhostScheme(types.GhostSchemeMLDSA44),
		}
		hash, ok := types.NewTx(inner).GhostBindingTxHash(genesisHash)
		if !ok {
			return nil, errors.New("ghostscale: no binding transaction hash")
		}
		inner.Binding = types.NewGhostBinding(senders[i], identities[i], hash)
		bindings[i] = inner.Binding
		bindingTxs[i] = types.NewTx(inner)
	}
	pr := &ghostpriv.PublicRoot{Version: ghostpriv.PublicRootVersion, ChainID: chainID, Bindings: bindings}
	pr.Proof = cfg.PublicRootProof(pr.Inputs(chainID, genesisHash).Binding)
	env, err := pr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rootTx, err := types.NewGhostPublicRootTx(env)
	if err != nil {
		return nil, err
	}
	txs = append(txs, rootTx)
	txs = append(txs, bindingTxs...)

	// The block, built by the chain maker, which runs every transaction and
	// panics on one that fails.
	engine, err := newEngine()
	if err != nil {
		return nil, err
	}
	defer engine.Close()
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("ghostscale: building the block: %v", r)
		}
	}()
	_, blocks, _ := core.GenerateChainWithGenesis(gspec, engine, 1, func(i int, g *core.BlockGen) {
		g.SetCoinbase(miner)
		for _, tx := range txs {
			g.AddTx(tx)
		}
	})
	b.block = blocks[0]
	if b.block.Hash() == (common.Hash{}) || b.block.Header().HeaderMmrRoot == nil {
		return nil, errors.New("ghostscale: the block has no header MMR root")
	}
	return b, nil
}

// calcBaseFee is the base fee of a child of parent.
func calcBaseFee(gspec *genesisT.Genesis, parent *types.Header) *big.Int {
	return eip1559.CalcBaseFee(gspec.Config, parent)
}

// Block returns the benchmark block.
func (b *Bench) Block() *types.Block { return b.block }

// Genesis returns the genesis of the benchmark chain.
func (b *Bench) Genesis() *genesisT.Genesis { return b.gspec }

// Bundles returns the number of bundles in the block.
func (b *Bench) Bundles() int { return b.bundles }

// Measure is one timed import.
type Measure struct {
	Elapsed    time.Duration
	DiskBefore int64 // table bytes of the database with the genesis, after compaction
	DiskAfter  int64 // with the block, after compaction
}

// cacheConfig is the cache of the runs: the hash scheme with every block's
// state trie written to the database (no dirty trie cache) and no snapshot,
// so that the database holds all the block wrote when the import returns.
func cacheConfig() *core.CacheConfig {
	return &core.CacheConfig{
		TrieCleanLimit:    256,
		TrieDirtyDisabled: true,
		TrieTimeLimit:     5 * time.Minute,
		StateScheme:       rawdb.HashScheme,
	}
}

// Execute imports block, the benchmark block or a changed copy of it, into a
// fresh pebble database in dir holding the genesis, timing the import, and
// checks what the benchmark block must have done: every reveal applied, every
// public transaction sent, the header MMR state stored. dir is removed.
func (b *Bench) Execute(dir string, block *types.Block) (m Measure, err error) {
	defer os.RemoveAll(dir)
	db, err := rawdb.NewPebbleDBDatabase(dir, 512, 256, "", false, false)
	if err != nil {
		return m, err
	}
	closed := false
	defer func() {
		if !closed {
			db.Close()
		}
	}()
	engine, err := newEngine()
	if err != nil {
		return m, err
	}
	defer engine.Close()
	chain, err := core.NewBlockChain(db, cacheConfig(), b.gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		return m, err
	}
	stopped := false
	defer func() {
		if !stopped {
			chain.Stop()
		}
	}()
	if m.DiskBefore, err = settledBytes(db, dir); err != nil {
		return m, err
	}

	start := time.Now()
	_, err = chain.InsertChain(types.Blocks{block})
	m.Elapsed = time.Since(start)
	if err != nil {
		return m, err
	}
	if err := b.check(chain, db, block); err != nil {
		return m, err
	}
	chain.Stop()
	stopped = true
	if m.DiskAfter, err = settledBytes(db, dir); err != nil {
		return m, err
	}
	closed = true
	return m, db.Close()
}

// check checks the imported block's effects.
func (b *Bench) check(chain *core.BlockChain, db ethdb.Database, block *types.Block) error {
	hash := block.Hash()
	if head := chain.CurrentBlock(); head.Hash() != hash {
		return fmt.Errorf("ghostscale: head %d %x, not the block", head.Number, head.Hash())
	}
	receipts := chain.GetReceiptsByHash(hash)
	if len(receipts) != len(block.Transactions()) {
		return fmt.Errorf("ghostscale: %d receipts for %d transactions", len(receipts), len(block.Transactions()))
	}
	applied := 0
	for i, r := range receipts {
		if r.Status != types.ReceiptStatusSuccessful {
			return fmt.Errorf("ghostscale: transaction %d failed", i)
		}
		if r.Type == types.GhostBundleTxType {
			applied += len(r.Logs) // one reveal log for each applied reveal
		}
	}
	if applied != b.cfg.Reveals {
		return fmt.Errorf("ghostscale: %d of %d reveals applied", applied, b.cfg.Reveals)
	}
	st, err := chain.StateAt(block.Root())
	if err != nil {
		return err
	}
	if _, out := ghostpriv.Totals(st); !out.Eq(b.totalOut) {
		return fmt.Errorf("ghostscale: total out %v, want %v", out, b.totalOut)
	}
	for i, to := range b.recipients {
		if got := st.GetBalance(to); got.ToBig().Cmp(publicValue) != 0 {
			return fmt.Errorf("ghostscale: public recipient %d holds %v", i, got)
		}
	}
	want := uint64(b.cfg.Reveals)*ghostpriv.GasPriv + uint64(b.cfg.Public)*b.bindingGas
	if block.GasUsed() != want {
		return fmt.Errorf("ghostscale: gas used %d, want %d", block.GasUsed(), want)
	}
	// The header MMR append: the block's state, one leaf, the genesis, whose
	// root is the block's header MMR root, is stored by the block's hash.
	enc, err := rawdb.ReadHeaderMMRState(db, hash)
	if err != nil || enc == nil {
		return fmt.Errorf("ghostscale: no header MMR state stored for the block: %v", err)
	}
	state, err := ghostmmr.DecodeState(enc)
	if err != nil {
		return err
	}
	root, err := state.Root()
	if err != nil {
		return err
	}
	if state.N != 1 || common.Hash(root) != *block.Header().HeaderMmrRoot {
		return fmt.Errorf("ghostscale: stored header MMR state of %d leaves, root %x, header %x", state.N, root, *block.Header().HeaderMmrRoot)
	}
	return nil
}

// settledBytes compacts the database, so that what was written is in its
// tables, and returns the bytes of its table files. The database deletes the
// tables a compaction made obsolete in the background, so a table can go
// between listing the folder and reading its size: it is no longer part of
// the database and is not counted. The folder is measured until two walks in
// a row agree, so that obsolete tables not yet deleted are not counted.
func settledBytes(db ethdb.Database, dir string) (int64, error) {
	if err := db.Compact(nil, nil); err != nil {
		return 0, err
	}
	const (
		walks = 50
		pause = 20 * time.Millisecond
	)
	last := int64(-1)
	for range walks {
		total, err := tableBytes(dir)
		if err != nil {
			return 0, err
		}
		if total == last {
			return total, nil
		}
		last = total
		time.Sleep(pause)
	}
	return last, nil
}

// tableBytes returns the bytes of the table files under dir, skipping a
// table deleted while the folder is walked.
func tableBytes(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path != dir {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sst") {
			return nil
		}
		info, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// engine is the RandomX engine of the internal network without the checks
// that cannot hold for the benchmark block or that take the same time for any
// block: its header checks are the parent link, the gas used and the header
// MMR root; not the gas limit, which is far above the consensus maximum, nor
// the difficulty, the timestamp or the seal. Building, rewards and the tree
// and header MMR roots are the RandomX engine's.
type engine struct {
	*randomx.RandomX
}

func newEngine() (*engine, error) {
	rx, err := randomx.New(randomx.Config{Params: ghost.InternalNetParams()})
	if err != nil {
		return nil, err
	}
	return &engine{rx}, nil
}

// headerMMRReader is a chain that keeps the header MMR.
type headerMMRReader interface {
	HeaderMMR(hash common.Hash, number uint64) (ghostmmr.State, error)
}

func (e *engine) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	number := header.Number.Uint64()
	if number == 0 {
		return consensus.ErrUnknownAncestor
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	reader, ok := chain.(headerMMRReader)
	if !ok {
		return errors.New("ghostscale: the chain keeps no header MMR")
	}
	parentState, err := reader.HeaderMMR(parent.Hash(), parent.Number.Uint64())
	if err != nil {
		return err
	}
	work, err := ghostmmr.WorkFromBig(parent.Difficulty)
	if err != nil {
		return err
	}
	state, _, err := parentState.Append(ghostmmr.Leaf(parent.Hash(), work))
	if err != nil {
		return err
	}
	root, err := state.Root()
	if err != nil {
		return err
	}
	if header.HeaderMmrRoot == nil || *header.HeaderMmrRoot != common.Hash(root) {
		return fmt.Errorf("%w: have %v, want %x", randomx.ErrHeaderMmrRoot, header.HeaderMmrRoot, root)
	}
	return nil
}

func (e *engine) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort, results := make(chan struct{}), make(chan error, len(headers))
	for i, h := range headers {
		results <- e.VerifyHeader(chain, h, seals[i])
	}
	return abort, results
}

// Machine names the machine a result was measured on.
type Machine struct {
	Hostname    string `json:"hostname"`
	CPU         string `json:"cpu"`
	Cores       int    `json:"cores"`
	Arch        string `json:"architecture"`
	OS          string `json:"os"`
	MemoryBytes uint64 `json:"memory_bytes,omitempty"`
	GoVersion   string `json:"go_version"`
	Date        string `json:"date"`
}

// ThisMachine describes the machine the process runs on.
func ThisMachine(now time.Time) Machine {
	host, _ := os.Hostname()
	return Machine{
		Hostname:    host,
		CPU:         cpuModel(),
		Cores:       runtime.NumCPU(),
		Arch:        runtime.GOARCH,
		OS:          runtime.GOOS,
		MemoryBytes: memTotal(),
		GoVersion:   runtime.Version(),
		Date:        now.UTC().Format("2006-01-02"),
	}
}

// cpuImplementers names the ARM CPU implementer codes of /proc/cpuinfo.
var cpuImplementers = map[string]string{
	"0x41": "Arm", "0x42": "Broadcom", "0x43": "Cavium", "0x46": "Fujitsu", "0x48": "HiSilicon",
	"0x4e": "NVIDIA", "0x51": "Qualcomm", "0x61": "Apple", "0xc0": "Ampere",
}

// cpuModel reads the CPU model from /proc/cpuinfo: the model name, or on ARM
// the implementer and part when there is none.
func cpuModel() string {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, seen := fields[k]; !seen {
			fields[k] = v
		}
	}
	if m := fields["model name"]; m != "" {
		return m
	}
	if impl := fields["CPU implementer"]; impl != "" {
		name := cpuImplementers[impl]
		if name == "" {
			name = "unknown implementer"
		}
		return fmt.Sprintf("%s (CPU implementer %s, part %s; /proc/cpuinfo has no model name)", name, impl, fields["CPU part"])
	}
	return "unknown"
}

// memTotal reads MemTotal from /proc/meminfo, in bytes, or 0.
func memTotal() uint64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		var kb uint64
		if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &kb); err == nil {
			return kb * 1024
		}
	}
	return 0
}
