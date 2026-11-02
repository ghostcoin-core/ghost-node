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

package ghostpriv

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghosttree"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/ghost"
	"github.com/holiman/uint256"
)

// Offsets of the policy reveal payload (spec 10, section 5.1), a fixed layout
// and not RLP.
const (
	offPolicyVersion    = 0
	offPolicyChainID    = 2
	offPolicyMarker     = 10
	offPolicyRoot       = 42
	offPolicyRemainder  = 74
	offPolicyOut        = 106
	offPolicyFee        = 138
	offPolicyAddress    = 170
	offPolicyCodeHash   = 190
	offPolicyParamsHash = 222
	offPolicyActionTag  = 254
	offPolicyActionSalt = 286
	offPolicyInstr      = 318
	offPolicyProof      = 350
	offPolicyNote       = offPolicyProof + ProofSize

	// PolicyBindingSize is the length of a policy reveal's binding digest
	// input.
	PolicyBindingSize = 767

	// policyRevealLogSize is the length of the data of a policy reveal's
	// receipt log: the location (8), the remainder (32), its note (380), the
	// policy address (20), out (32) and the instruction (32).
	policyRevealLogSize = 8 + 32 + NoteSize + 20 + 32 + 32
)

// The errors of the policy reveal checks, one per check, in the order they
// run (spec 10, section 5.2). Check 5 computes the binding digest and cannot
// fail.
var (
	ErrPolicyRevealLength   = errors.New("policy reveal is not a 0x53 envelope of 1,311,451 bytes")
	ErrPolicyRevealVersion  = errors.New("policy reveal version is not 1")
	ErrPolicyRevealAmount   = errors.New("policy reveal out or fee not below 2^96")
	ErrPolicyRevealChainID  = errors.New("policy reveal chain id is not this chain's")
	ErrPolicyRevealFee      = errors.New("policy reveal fee is not the window fee")
	ErrPolicyRevealRoot     = errors.New("policy reveal root is not an ancestor's coin tree root")
	ErrPolicyRevealMarker   = errors.New("policy reveal marker already used")
	ErrPolicyRevealBackstop = errors.New("policy reveal takes more than the hidden set holds")
	ErrPolicyRevealPolicy   = errors.New("policy reveal address is not a frozen policy of an earlier block with that code hash")
	ErrPolicyRevealTree     = errors.New("coin tree cannot take the policy reveal's remainder")
	ErrPolicyRevealProof    = errors.New("policy reveal proof rejected")
)

// PolicyReveal is a decoded policy reveal payload. It spends a coin of the
// coin tree, whose marker it shares with the ordinary reveal, into the escrow
// slot of the policy at Policy, which must have the code hash CodeHash; the
// remainder, of value zero, goes back to the coin tree with its note.
type PolicyReveal struct {
	Version    uint16
	ChainID    uint64
	Marker     common.Hash
	Root       common.Hash
	Remainder  common.Hash
	Out        *uint256.Int
	Fee        *uint256.Int
	Policy     common.Address // policy_address
	CodeHash   common.Hash    // policy_codehash
	ParamsHash common.Hash
	ActionTag  common.Hash
	ActionSalt common.Hash
	Instr      common.Hash
	Proof      []byte // ProofSize bytes, or fewer to be padded with zeros
	Note       [NoteSize]byte
}

// MarshalBinary returns the policy reveal's envelope: the type byte 0x53 and
// the payload. A shorter proof is padded with zeros; a longer one is an
// error.
func (r *PolicyReveal) MarshalBinary() ([]byte, error) {
	if len(r.Proof) > ProofSize {
		return nil, fmt.Errorf("proof of %d bytes, the field holds %d", len(r.Proof), ProofSize)
	}
	env := make([]byte, types.GhostPolicyRevealEnvelopeSize)
	env[0] = types.GhostPolicyRevealTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[offPolicyVersion:], r.Version)
	binary.BigEndian.PutUint64(p[offPolicyChainID:], r.ChainID)
	copy(p[offPolicyMarker:], r.Marker[:])
	copy(p[offPolicyRoot:], r.Root[:])
	copy(p[offPolicyRemainder:], r.Remainder[:])
	if r.Out != nil {
		copy(p[offPolicyOut:offPolicyFee], amountWord(r.Out))
	}
	if r.Fee != nil {
		copy(p[offPolicyFee:offPolicyAddress], amountWord(r.Fee))
	}
	copy(p[offPolicyAddress:], r.Policy[:])
	copy(p[offPolicyCodeHash:], r.CodeHash[:])
	copy(p[offPolicyParamsHash:], r.ParamsHash[:])
	copy(p[offPolicyActionTag:], r.ActionTag[:])
	copy(p[offPolicyActionSalt:], r.ActionSalt[:])
	copy(p[offPolicyInstr:], r.Instr[:])
	copy(p[offPolicyProof:offPolicyNote], r.Proof)
	copy(p[offPolicyNote:], r.Note[:])
	return env, nil
}

// DecodePolicyReveal decodes a policy reveal envelope and runs the first two
// checks: the shape, type 0x53, the exact length (ErrPolicyRevealLength) and
// version 1 (ErrPolicyRevealVersion); and the encoding, out and fee amount
// words below 2^96 (ErrPolicyRevealAmount). The policy address is its 20
// bytes. An envelope of any other reveal type fails the first.
func DecodePolicyReveal(envelope []byte) (*PolicyReveal, error) {
	if len(envelope) != types.GhostPolicyRevealEnvelopeSize || envelope[0] != types.GhostPolicyRevealTxType {
		return nil, fmt.Errorf("%w: %d bytes", ErrPolicyRevealLength, len(envelope))
	}
	p := envelope[1:]
	r := &PolicyReveal{
		Version:    binary.BigEndian.Uint16(p[offPolicyVersion:]),
		ChainID:    binary.BigEndian.Uint64(p[offPolicyChainID:]),
		Marker:     common.BytesToHash(p[offPolicyMarker:offPolicyRoot]),
		Root:       common.BytesToHash(p[offPolicyRoot:offPolicyRemainder]),
		Remainder:  common.BytesToHash(p[offPolicyRemainder:offPolicyOut]),
		Policy:     common.BytesToAddress(p[offPolicyAddress:offPolicyCodeHash]),
		CodeHash:   common.BytesToHash(p[offPolicyCodeHash:offPolicyParamsHash]),
		ParamsHash: common.BytesToHash(p[offPolicyParamsHash:offPolicyActionTag]),
		ActionTag:  common.BytesToHash(p[offPolicyActionTag:offPolicyActionSalt]),
		ActionSalt: common.BytesToHash(p[offPolicyActionSalt:offPolicyInstr]),
		Instr:      common.BytesToHash(p[offPolicyInstr:offPolicyProof]),
		Proof:      common.CopyBytes(p[offPolicyProof:offPolicyNote]),
	}
	copy(r.Note[:], p[offPolicyNote:])
	if r.Version != PolicyRevealVersion {
		return nil, fmt.Errorf("%w: %d", ErrPolicyRevealVersion, r.Version)
	}
	var err error
	if r.Out, err = readAmount(p[offPolicyOut:offPolicyFee]); err != nil {
		return nil, fmt.Errorf("%w: out", ErrPolicyRevealAmount)
	}
	if r.Fee, err = readAmount(p[offPolicyFee:offPolicyAddress]); err != nil {
		return nil, fmt.Errorf("%w: fee", ErrPolicyRevealAmount)
	}
	return r, nil
}

// BindingDigest returns the binding digest a policy reveal's proof must
// commit to, K("ghost/policy-reveal-binding/v1", fields) over the 767 bytes
// of BindingInput. Its tag and statement differ from the ordinary reveal's,
// so it never equals an ordinary reveal's digest.
func (r *PolicyReveal) BindingDigest(chainID uint64, genesis common.Hash) common.Hash {
	return ghosttree.K(TagPolicyRevealBinding, r.BindingInput(chainID, genesis))
}

// BindingInput returns the 767 bytes the policy binding digest hashes: the
// chain id (8), the version 1 (2), the domain, which is the genesis hash
// (32), the statement 0x04 and its version 0x01 (1 each), the type COIN
// version 2 (2), the purpose 0x05 (1), the root, marker and remainder (32
// each), out and fee (32 each), the policy address (20), its code hash, the
// parameters hash, the action tag, the action salt and the instruction (32
// each) and the remainder note (380). The node supplies the version,
// statement, type and purpose; the proof is not covered.
func (r *PolicyReveal) BindingInput(chainID uint64, genesis common.Hash) []byte {
	b := make([]byte, 0, PolicyBindingSize)
	b = binary.BigEndian.AppendUint64(b, chainID)
	b = binary.BigEndian.AppendUint16(b, PolicyRevealVersion)
	b = append(b, genesis[:]...)
	b = append(b, statementPolicyReveal, statementVersion)
	b = append(b, CoinV2[:]...)
	b = append(b, PurposePolicySpend)
	b = append(b, r.Root[:]...)
	b = append(b, r.Marker[:]...)
	b = append(b, r.Remainder[:]...)
	b = append(b, amountWord(amountOrZero(r.Out))...)
	b = append(b, amountWord(amountOrZero(r.Fee))...)
	b = append(b, r.Policy[:]...)
	b = append(b, r.CodeHash[:]...)
	b = append(b, r.ParamsHash[:]...)
	b = append(b, r.ActionTag[:]...)
	b = append(b, r.ActionSalt[:]...)
	b = append(b, r.Instr[:]...)
	b = append(b, r.Note[:]...)
	return b
}

// VerifyInputs returns the inputs the verifier receives for the policy
// reveal's proof on the chain of chainID and genesis: Kind ghosttree.Coin
// with PurposePolicySpend, no recipient, and the policy fields.
func (r *PolicyReveal) VerifyInputs(chainID uint64, genesis common.Hash) *VerifyInputs {
	return &VerifyInputs{
		Kind:           ghosttree.Coin,
		Purpose:        PurposePolicySpend,
		Binding:        r.BindingDigest(chainID, genesis),
		ChainID:        chainID,
		Domain:         genesis,
		Root:           r.Root,
		Marker:         r.Marker,
		Remainder:      r.Remainder,
		Out:            new(uint256.Int).Set(amountOrZero(r.Out)),
		Fee:            new(uint256.Int).Set(amountOrZero(r.Fee)),
		Note:           r.Note,
		Policy:         r.Policy,
		PolicyCodeHash: r.CodeHash,
		ParamsHash:     r.ParamsHash,
		ActionTag:      r.ActionTag,
		ActionSalt:     r.ActionSalt,
		Instr:          r.Instr,
	}
}

// policyAllowed is check 9: addr is a frozen policy that the registry
// records as created in a block before number, with codeHash as both its
// registered code hash and its EXTCODEHASH, and not a reserved address.
func policyAllowed(st StateDB, addr common.Address, codeHash common.Hash, number uint64) error {
	if ghost.IsReservedAddress(addr) {
		return fmt.Errorf("%w: %v is reserved", ErrPolicyRevealPolicy, addr)
	}
	height, registered, ok := ghost.PolicyRegistryEntry(st, addr)
	if !ok {
		return fmt.Errorf("%w: %v is not registered", ErrPolicyRevealPolicy, addr)
	}
	if height >= number {
		return fmt.Errorf("%w: %v created at height %d, not before %d", ErrPolicyRevealPolicy, addr, height, number)
	}
	if registered != codeHash || st.GetCodeHash(addr) != codeHash {
		return fmt.Errorf("%w: %v has code hash %x, registered %x, not %x", ErrPolicyRevealPolicy, addr, st.GetCodeHash(addr), registered, codeHash)
	}
	return nil
}

// treeRoom is check 10: the coin tree takes a leaf in the block at height.
// The append is tried and rewound, so nothing changes.
func treeRoom(st StateDB, height uint64, leaf common.Hash) error {
	snap := st.Snapshot()
	defer st.RevertToSnapshot(snap)
	if _, err := ghosttree.Append(st, ghosttree.Coin, height, leaf); err != nil {
		return fmt.Errorf("%w: %w", ErrPolicyRevealTree, err)
	}
	return nil
}

// CheckPolicyReveal runs checks 1 to 11 of a policy reveal (spec 10, section
// 5.2) against the state before it, in order, stopping at the first that
// fails, and returns the decoded policy reveal and the window fee it pays,
// split by the cover rule for G_POLICY. The proof is verified last, so a
// policy reveal refused by any other check costs no proof verification. It
// changes nothing.
func CheckPolicyReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) (*PolicyReveal, Fee, error) {
	// Checks 1 and 2: the shape and the encoding.
	r, err := DecodePolicyReveal(envelope)
	if err != nil {
		return nil, Fee{}, err
	}
	if env == nil || env.Header == nil || env.Header.Number == nil {
		return nil, Fee{}, fmt.Errorf("%w: no including block", ErrRevealChainInfo)
	}
	// Check 3: the chain id.
	if env.ChainID == nil || !env.ChainID.IsUint64() || env.ChainID.Uint64() != r.ChainID {
		return nil, Fee{}, fmt.Errorf("%w: have %d, chain %v", ErrPolicyRevealChainID, r.ChainID, env.ChainID)
	}
	chainID := env.ChainID.Uint64()
	height := env.Header.Number.Uint64()
	// Check 4: the window fee for G_POLICY of the including block's window
	// or of the window before it, which must cover G_POLICY times the
	// including block's base fee.
	fee, err := env.windowFee(r.Fee, GasPolicy)
	if err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrPolicyRevealFee, err)
	}
	// Check 5: the node's own binding digest, in the verifier's inputs.
	in := r.VerifyInputs(chainID, env.Genesis)
	// Check 6: the root, a coin tree root of the ancestry.
	if !env.rootEligible(ghosttree.Coin, r.Root) {
		return nil, Fee{}, fmt.Errorf("%w: %x", ErrPolicyRevealRoot, r.Root)
	}
	// Check 7: the marker, against the coin spent set the ordinary reveal
	// uses, which holds the markers of earlier reveals of both classes in
	// this block too. The zero marker is never spendable.
	if r.Marker == (common.Hash{}) {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrPolicyRevealMarker, ghosttree.ErrZeroMarker)
	}
	if ghosttree.IsSpent(st, ghosttree.Coin, r.Marker) {
		return nil, Fee{}, fmt.Errorf("%w: %x", ErrPolicyRevealMarker, r.Marker)
	}
	// Check 8: the backstop.
	hidden, err := Hidden(st)
	if err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrPolicyRevealBackstop, err)
	}
	if need := new(uint256.Int).Add(r.Out, r.Fee); need.Gt(hidden) {
		return nil, Fee{}, fmt.Errorf("%w: out plus fee %v, hidden %v", ErrPolicyRevealBackstop, need, hidden)
	}
	// Check 9: the policy.
	if err := policyAllowed(st, r.Policy, r.CodeHash, height); err != nil {
		return nil, Fee{}, err
	}
	// Check 10: room in the coin tree for the remainder.
	if err := treeRoom(st, height, r.Remainder); err != nil {
		return nil, Fee{}, err
	}
	// Check 11: the proof, for the inputs the node computed.
	if verifier == nil {
		verifier = DefaultVerifier()
	}
	if err := verifier.VerifyReveal(in, common.CopyBytes(r.Proof)); err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrPolicyRevealProof, err)
	}
	return r, fee, nil
}

// ApplyPolicyReveal checks a policy reveal and makes its one atomic change
// (spec 10, section 5.3): it records the marker as spent; appends the
// zero-value remainder and writes the policy reveal receipt; opens the
// escrow slot of the marker with remaining = out when out > 0, and none when
// out = 0; pays the fee, burning G_POLICY times the larger of the window
// price and the block's base fee, credited to nobody, and the rest to the
// coinbase as the tip; and adds out plus fee to total_out and out to
// total_escrow. No balance is credited but the tip and no code runs. The gas
// is the caller's. On an error nothing is changed.
func ApplyPolicyReveal(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) error {
	r, fee, err := CheckPolicyReveal(st, env, verifier, envelope)
	if err != nil {
		return err
	}
	height := env.Header.Number.Uint64()
	snap := st.Snapshot()
	fail := func(err error) error {
		st.RevertToSnapshot(snap)
		return err
	}
	if err := ghosttree.MarkSpent(st, ghosttree.Coin, r.Marker); err != nil {
		return fail(fmt.Errorf("%w: %w", ErrPolicyRevealMarker, err))
	}
	res, err := ghosttree.Append(st, ghosttree.Coin, height, r.Remainder)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", ErrPolicyRevealTree, err))
	}
	loc, err := receiptLocation(res)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", ErrPolicyRevealTree, err))
	}
	data := make([]byte, 0, policyRevealLogSize)
	data = append(data, loc...)
	data = append(data, r.Remainder[:]...)
	data = append(data, r.Note[:]...)
	data = append(data, r.Policy[:]...)
	data = append(data, amountWord(r.Out)...)
	data = append(data, r.Instr[:]...)
	st.AddLog(&types.Log{
		Address:     ghosttree.TreeAccount(ghosttree.Coin),
		Topics:      []common.Hash{ghosttree.K(TagPolicyRevealReceipt), r.Marker},
		Data:        data,
		BlockNumber: height,
	})
	// The slot takes out into total_out and total_escrow.
	if !r.Out.IsZero() {
		err := OpenEscrowSlot(st, r.Marker, &EscrowSlot{
			Policy:     r.Policy,
			Out:        r.Out,
			Height:     height,
			Timestamp:  env.Header.Time,
			ParamsHash: r.ParamsHash,
			ActionTag:  r.ActionTag,
			ActionSalt: r.ActionSalt,
			Instr:      r.Instr,
		})
		if err != nil {
			return fail(err)
		}
	}
	if err := addTotal(st, SlotTotalOut, r.Fee); err != nil {
		return fail(err)
	}
	st.AddBalance(env.Header.Coinbase, fee.Tip)
	return nil
}
