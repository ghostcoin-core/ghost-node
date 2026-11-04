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

// Policy actions (spec 10, section 8). A policy action, the native
// transaction 0x54, debits an open escrow slot by an exact amount against a
// proof of the slot's action key, burns G_ACTION times the including block's
// base fee of that debit, tips the rest to the coinbase, spends the slot's
// action nonce, and then calls the slot's policy with its calldata from
// ACTION_CALLER under ACTION_CALL_GAS. The checks that need no EVM are here;
// the execution, which runs the policy call, is core.ApplyPolicyAction.
const (
	TagPolicyActionBinding = "ghost/action-binding/v1"
	TagPolicyActionKey     = "ghost/policy-action/v1"
	TagActionCalldata      = "ghost/action-calldata/v1"
	TagActionResult        = "ghost/action-result/v1"
	TagActionReturn        = "ghost/action-return/v1"

	// PolicyActionVersion is the only version of the policy action payload.
	PolicyActionVersion uint16 = 0x0001

	// PurposeAction is the purpose of a policy action's statement, the
	// proof of the action key (KNOW_ACTION).
	PurposeAction byte = 0x06

	// ActionCalldataSize is ACTION_CALLDATA_MAX, the length of the calldata
	// field: the calldata, as long as the length field says, then zeros
	// (spec 10, section 8.1).
	ActionCalldataSize = 1_024

	// ActionProofSize is ACTION_PROOF_BYTES, the length of the proof field
	// of a policy action: the serialized proof followed by zeros. It is the
	// proof-length bound of the small statements, 947,283 bytes, rounded up
	// to a multiple of 1,024 (spec 10, section 8.1).
	ActionProofSize = 948_224

	// ActionBindingSize is the length of a policy action's binding digest
	// input (spec 10, section 8.2).
	ActionBindingSize = 273

	// ActionCallGas is ACTION_CALL_GAS, the gas the policy call gets, paid
	// inside G_ACTION.
	ActionCallGas uint64 = 250_000

	// GasAction is G_ACTION, the gas of the policy action. All of it is
	// taken from the block gas pool and none is refunded.
	GasAction = types.GhostPolicyActionGas

	// actionResultLogSize is the length of the data of the action-result log:
	// the nonce the action spent, the debit, the call's status, the gas the
	// call used and the hash of its return data, 32 bytes each.
	actionResultLogSize = 5 * 32

	statementPolicyAction = 0x05
)

// Offsets of the policy action payload, a fixed layout and not RLP.
const (
	offActionVersion   = 0
	offActionChainID   = 2
	offActionMarker    = 10
	offActionNonce     = 42
	offActionExpected  = 50
	offActionDebit     = 82
	offActionExpiry    = 114
	offActionCallLen   = 122
	offActionCalldata  = 124
	offActionProof     = offActionCalldata + ActionCalldataSize
	actionPayloadSize  = offActionProof + ActionProofSize
	actionEnvelopeSize = 1 + actionPayloadSize
)

// The payload layout fills the type's payload exactly.
var _ = [1]struct{}{}[actionPayloadSize-types.GhostPolicyActionPayloadSize]
var _ = [1]struct{}{}[types.GhostPolicyActionPayloadSize-actionPayloadSize]

// The errors of the policy action checks, one per check, in the order they
// run (spec 10, section 8.3). Check 9 computes the binding digest and cannot
// fail; the proof is check 10, last.
var (
	ErrActionLength    = errors.New("policy action is not a 0x54 envelope of 949,373 bytes")
	ErrActionVersion   = errors.New("policy action version is not 1")
	ErrActionEncoding  = errors.New("policy action fields are not well encoded")
	ErrActionChainID   = errors.New("policy action chain id is not this chain's")
	ErrActionExpired   = errors.New("policy action expired")
	ErrActionSlot      = errors.New("policy action names no open slot of a frozen policy of an earlier block")
	ErrActionNonce     = errors.New("policy action nonce is not the slot's")
	ErrActionRemaining = errors.New("policy action expected remaining is not the slot's")
	ErrActionDebit     = errors.New("policy action debit below G_ACTION times the base fee or above the remaining")
	ErrActionProof     = errors.New("policy action proof rejected")
)

// Action is a decoded policy action payload. It acts on the escrow slot of
// Marker, whose action nonce must be Nonce and whose remaining must be
// ExpectedRemaining, in a block at a height of at most Expiry; it takes
// exactly Debit from the slot and calls the slot's policy with Calldata.
type Action struct {
	Version           uint16
	ChainID           uint64
	Marker            common.Hash
	Nonce             uint64
	ExpectedRemaining *uint256.Int
	Debit             *uint256.Int
	Expiry            uint64
	Calldata          []byte // at most ActionCalldataSize bytes
	Proof             []byte // ActionProofSize bytes, or fewer to be padded with zeros
}

// MarshalBinary returns the policy action's envelope: the type byte 0x54 and
// the payload. A shorter proof is padded with zeros; a longer proof or
// calldata is an error.
func (a *Action) MarshalBinary() ([]byte, error) {
	if len(a.Proof) > ActionProofSize {
		return nil, fmt.Errorf("proof of %d bytes, the field holds %d", len(a.Proof), ActionProofSize)
	}
	if len(a.Calldata) > ActionCalldataSize {
		return nil, fmt.Errorf("calldata of %d bytes, the field holds %d", len(a.Calldata), ActionCalldataSize)
	}
	env := make([]byte, actionEnvelopeSize)
	env[0] = types.GhostPolicyActionTxType
	p := env[1:]
	binary.BigEndian.PutUint16(p[offActionVersion:], a.Version)
	binary.BigEndian.PutUint64(p[offActionChainID:], a.ChainID)
	copy(p[offActionMarker:], a.Marker[:])
	binary.BigEndian.PutUint64(p[offActionNonce:], a.Nonce)
	copy(p[offActionExpected:offActionDebit], amountWord(amountOrZero(a.ExpectedRemaining)))
	copy(p[offActionDebit:offActionExpiry], amountWord(amountOrZero(a.Debit)))
	binary.BigEndian.PutUint64(p[offActionExpiry:], a.Expiry)
	binary.BigEndian.PutUint16(p[offActionCallLen:], uint16(len(a.Calldata)))
	copy(p[offActionCalldata:offActionProof], a.Calldata)
	copy(p[offActionProof:], a.Proof)
	return env, nil
}

// DecodeAction decodes a policy action envelope and runs the first two
// checks: the shape, type 0x54, the exact length (ErrActionLength) and
// version 1 (ErrActionVersion); and the encoding (ErrActionEncoding): the
// expected remaining and the debit are amount words below 2^96, the calldata
// length fits its field, and the bytes of the field past the calldata are
// zero. An envelope of any other type fails the first.
func DecodeAction(envelope []byte) (*Action, error) {
	if len(envelope) != actionEnvelopeSize || envelope[0] != types.GhostPolicyActionTxType {
		return nil, fmt.Errorf("%w: %d bytes", ErrActionLength, len(envelope))
	}
	p := envelope[1:]
	a := &Action{
		Version: binary.BigEndian.Uint16(p[offActionVersion:]),
		ChainID: binary.BigEndian.Uint64(p[offActionChainID:]),
		Marker:  common.BytesToHash(p[offActionMarker:offActionNonce]),
		Nonce:   binary.BigEndian.Uint64(p[offActionNonce:]),
		Expiry:  binary.BigEndian.Uint64(p[offActionExpiry:]),
		Proof:   common.CopyBytes(p[offActionProof:]),
	}
	if a.Version != PolicyActionVersion {
		return nil, fmt.Errorf("%w: %d", ErrActionVersion, a.Version)
	}
	var err error
	if a.ExpectedRemaining, err = readAmount(p[offActionExpected:offActionDebit]); err != nil {
		return nil, fmt.Errorf("%w: expected remaining: %w", ErrActionEncoding, err)
	}
	if a.Debit, err = readAmount(p[offActionDebit:offActionExpiry]); err != nil {
		return nil, fmt.Errorf("%w: debit: %w", ErrActionEncoding, err)
	}
	n := int(binary.BigEndian.Uint16(p[offActionCallLen:]))
	if n > ActionCalldataSize {
		return nil, fmt.Errorf("%w: calldata of %d bytes, the field holds %d", ErrActionEncoding, n, ActionCalldataSize)
	}
	field := p[offActionCalldata:offActionProof]
	for _, b := range field[n:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: calldata field not zero past its %d bytes", ErrActionEncoding, n)
		}
	}
	a.Calldata = common.CopyBytes(field[:n])
	return a, nil
}

// ActionCalldataHash is the hash of a policy call's calldata the action's
// binding carries: K("ghost/action-calldata/v1", calldata_len, calldata),
// the length as two bytes big endian (spec 10, section 8.2). Calldata longer
// than its field never decodes.
func ActionCalldataHash(calldata []byte) common.Hash {
	return ghosttree.K(TagActionCalldata, binary.BigEndian.AppendUint16(nil, uint16(len(calldata))), calldata)
}

// PolicyActionTag is the action tag of an action key: K("ghost/policy-action/v1",
// actionRoot, actionSalt). A policy action's proof shows knowledge of the
// actionRoot behind its slot's tag and salt.
func PolicyActionTag(actionRoot, actionSalt common.Hash) common.Hash {
	return ghosttree.K(TagPolicyActionKey, actionRoot[:], actionSalt[:])
}

// ActionReturnHash is the hash of a policy call's return data the
// action-result log carries: K("ghost/action-return/v1", ret).
func ActionReturnHash(ret []byte) common.Hash {
	return ghosttree.K(TagActionReturn, ret)
}

// CalldataHash returns ActionCalldataHash of the action's calldata.
func (a *Action) CalldataHash() common.Hash { return ActionCalldataHash(a.Calldata) }

// BindingDigest returns the binding digest a policy action's proof must
// commit to, K("ghost/action-binding/v1", fields) over the 273 bytes of
// BindingInput, for the action on the slot it names.
func (a *Action) BindingDigest(chainID uint64, genesis common.Hash, slot *EscrowSlot) common.Hash {
	return ghosttree.K(TagPolicyActionBinding, a.BindingInput(chainID, genesis, slot))
}

// BindingInput returns the 273 bytes the action binding digest hashes
// (spec 10, section 8.2): the chain id (8), the version 1 (2), the domain,
// which is the genesis hash (32), the statement 0x05 and its version 0x01
// (1 each), the purpose 0x06 (1), the slot's policy address (20), the marker
// (32), the action's nonce (8), the slot's action tag and action salt (32
// each), the action's expected remaining and debit (32 each), expiry (8) and
// calldata hash (32). The node supplies the version, statement and purpose
// and reads the slot's fields from the state; the proof is not covered.
func (a *Action) BindingInput(chainID uint64, genesis common.Hash, slot *EscrowSlot) []byte {
	if slot == nil {
		slot = new(EscrowSlot)
	}
	cd := a.CalldataHash()
	b := make([]byte, 0, ActionBindingSize)
	b = binary.BigEndian.AppendUint64(b, chainID)
	b = binary.BigEndian.AppendUint16(b, PolicyActionVersion)
	b = append(b, genesis[:]...)
	b = append(b, statementPolicyAction, statementVersion, PurposeAction)
	b = append(b, slot.Policy[:]...)
	b = append(b, a.Marker[:]...)
	b = binary.BigEndian.AppendUint64(b, a.Nonce)
	b = append(b, slot.ActionTag[:]...)
	b = append(b, slot.ActionSalt[:]...)
	b = append(b, amountWord(amountOrZero(a.ExpectedRemaining))...)
	b = append(b, amountWord(amountOrZero(a.Debit))...)
	b = binary.BigEndian.AppendUint64(b, a.Expiry)
	b = append(b, cd[:]...)
	return b
}

// VerifyInputs returns the inputs the verifier receives for the policy
// action's proof on the chain of chainID and genesis, against the slot the
// action names: Kind ghosttree.Coin with PurposeAction, the slot's policy
// fields, and the action's nonce, expected remaining, debit, expiry and
// calldata hash. Both a block's checks and the pool build them here.
func (a *Action) VerifyInputs(chainID uint64, genesis common.Hash, slot *EscrowSlot) *VerifyInputs {
	if slot == nil {
		slot = new(EscrowSlot)
	}
	return &VerifyInputs{
		Kind:              ghosttree.Coin,
		Purpose:           PurposeAction,
		Version:           a.Version,
		Binding:           a.BindingDigest(chainID, genesis, slot),
		ChainID:           chainID,
		Domain:            genesis,
		Marker:            a.Marker,
		Out:               new(uint256.Int),
		Fee:               new(uint256.Int),
		Policy:            slot.Policy,
		ParamsHash:        slot.ParamsHash,
		ActionTag:         slot.ActionTag,
		ActionSalt:        slot.ActionSalt,
		Instr:             slot.Instr,
		ActionNonce:       a.Nonce,
		ExpectedRemaining: new(uint256.Int).Set(amountOrZero(a.ExpectedRemaining)),
		Debit:             new(uint256.Int).Set(amountOrZero(a.Debit)),
		Expiry:            a.Expiry,
		CalldataHash:      a.CalldataHash(),
	}
}

// ActionBurn is the part of a debit an action in a block with base fee
// baseFee burns: G_ACTION times the base fee. A missing or unpriceable base
// fee is ErrBaseFee.
func ActionBurn(baseFee *uint256.Int) (*uint256.Int, error) {
	if baseFee == nil {
		return nil, ErrBaseFee
	}
	burn, overflow := new(uint256.Int).MulOverflow(uint256.NewInt(GasAction), baseFee)
	if overflow {
		return nil, ErrBaseFee
	}
	return burn, nil
}

// PolicyRevealAllowed is check 9 of a policy reveal (spec 10, section 5.2)
// on its own, for the transaction pool's checks before the proof: addr is a
// frozen policy of a block before number with codeHash as its registered
// code hash and its EXTCODEHASH (ErrPolicyRevealPolicy).
func PolicyRevealAllowed(st StateDB, addr common.Address, codeHash common.Hash, number uint64) error {
	return policyAllowed(st, addr, codeHash, number)
}

// PolicyRevealTreeRoom is check 10 of a policy reveal on its own: the coin
// tree takes the remainder leaf in the block at height
// (ErrPolicyRevealTree). It changes nothing.
func PolicyRevealTreeRoom(st StateDB, height uint64, remainder common.Hash) error {
	return treeRoom(st, height, remainder)
}

// actionSlot is check 5: the marker has an open slot, and the slot's policy
// is a frozen policy the registry records as created in a block before
// number, whose registered code hash is its EXTCODEHASH.
func actionSlot(st StateDB, marker common.Hash, number uint64) (*EscrowSlot, error) {
	slot, ok := ReadEscrowSlot(st, marker)
	if !ok {
		return nil, fmt.Errorf("%w: no slot of marker %x", ErrActionSlot, marker)
	}
	if !slot.Open {
		return nil, fmt.Errorf("%w: slot of marker %x closed", ErrActionSlot, marker)
	}
	height, codeHash, ok := ghost.PolicyRegistryEntry(st, slot.Policy)
	if !ok || height >= number || ghost.IsReservedAddress(slot.Policy) || st.GetCodeHash(slot.Policy) != codeHash {
		return nil, fmt.Errorf("%w: %v is not a callable policy", ErrActionSlot, slot.Policy)
	}
	return slot, nil
}

// CheckAction runs checks 1 to 10 of a policy action (spec 10, section 8.3)
// against the state before it, in order, stopping at the first that fails,
// and returns the decoded action and how its debit is paid: Total is the
// debit, Burn G_ACTION times the including block's base fee, Tip the rest
// and Price the base fee. The checks are
//
//  1. the shape: type 0x54, the exact length and version 1;
//  2. the encoding: amount words, the calldata length and its zero padding;
//  3. the chain id;
//  4. the expiry: the including block's height is at most the expiry;
//  5. the slot: the marker's slot is open and its policy is a frozen policy
//     of an earlier block with its registered code;
//  6. the nonce is the slot's action nonce;
//  7. the expected remaining is the slot's remaining;
//  8. the debit is at least G_ACTION times the base fee and at most the
//     remaining;
//  9. the node computes the binding digest itself, which cannot fail;
//  10. the verifier accepts the proof.
//
// The proof is verified last, through verifier, so an action refused by any
// other check costs no proof verification, and a caller that passes a
// verifier accepting every proof runs checks 1 to 8 alone. It changes
// nothing.
func CheckAction(st StateDB, env *BlockEnv, verifier Verifier, envelope []byte) (*Action, Fee, error) {
	// Checks 1 and 2: the shape and the encoding.
	a, err := DecodeAction(envelope)
	if err != nil {
		return nil, Fee{}, err
	}
	if env == nil || env.Header == nil || env.Header.Number == nil {
		return nil, Fee{}, fmt.Errorf("%w: no including block", ErrRevealChainInfo)
	}
	// Check 3: the chain id.
	if env.ChainID == nil || !env.ChainID.IsUint64() || env.ChainID.Uint64() != a.ChainID {
		return nil, Fee{}, fmt.Errorf("%w: have %d, chain %v", ErrActionChainID, a.ChainID, env.ChainID)
	}
	chainID := env.ChainID.Uint64()
	height := env.Header.Number.Uint64()
	// Check 4: the expiry.
	if height > a.Expiry {
		return nil, Fee{}, fmt.Errorf("%w: expiry %d, block %d", ErrActionExpired, a.Expiry, height)
	}
	// Check 5: the open slot of a callable policy.
	slot, err := actionSlot(st, a.Marker, height)
	if err != nil {
		return nil, Fee{}, err
	}
	// Check 6: the nonce.
	if a.Nonce != slot.ActionNonce {
		return nil, Fee{}, fmt.Errorf("%w: have %d, slot %d", ErrActionNonce, a.Nonce, slot.ActionNonce)
	}
	// Check 7: the expected remaining.
	if !a.ExpectedRemaining.Eq(slot.Remaining) {
		return nil, Fee{}, fmt.Errorf("%w: have %v, slot %v", ErrActionRemaining, a.ExpectedRemaining, slot.Remaining)
	}
	// Check 8: the debit pays G_ACTION at the block's base fee and fits the
	// slot.
	if env.Header.BaseFee == nil || env.Header.BaseFee.Sign() < 0 {
		return nil, Fee{}, fmt.Errorf("%w: %w: including block has no base fee", ErrActionDebit, ErrRevealChainInfo)
	}
	baseFee, overflow := uint256.FromBig(env.Header.BaseFee)
	if overflow {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrActionDebit, ErrBaseFee)
	}
	burn, err := ActionBurn(baseFee)
	if err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrActionDebit, err)
	}
	if a.Debit.Lt(burn) {
		return nil, Fee{}, fmt.Errorf("%w: debit %v, G_ACTION times the base fee %v", ErrActionDebit, a.Debit, burn)
	}
	if a.Debit.Gt(slot.Remaining) {
		return nil, Fee{}, fmt.Errorf("%w: debit %v, remaining %v", ErrActionDebit, a.Debit, slot.Remaining)
	}
	// Check 9: the node's own binding digest, in the verifier's inputs.
	in := a.VerifyInputs(chainID, env.Genesis, slot)
	// Check 10: the proof, for the inputs the node computed.
	if verifier == nil {
		verifier = DefaultVerifier()
	}
	if err := verifier.VerifyReveal(in, common.CopyBytes(a.Proof)); err != nil {
		return nil, Fee{}, fmt.Errorf("%w: %w", ErrActionProof, err)
	}
	return a, Fee{
		Price:    baseFee,
		BasePart: new(uint256.Int).Set(burn),
		Burn:     burn,
		Tip:      new(uint256.Int).Sub(a.Debit, burn),
		Total:    new(uint256.Int).Set(a.Debit),
	}, nil
}

// SettleAction makes the first, kept part of a checked policy action's
// change, before its policy call: it takes exactly the debit from the slot
// and spends its action nonce (DebitEscrowSlot), so that action_debits rises
// and total_escrow falls by the debit and the slot closes when its remaining
// reaches zero; the burn, G_ACTION times the base fee, is credited to
// nobody, and the tip is paid to the coinbase. It returns the slot as it was
// before. The policy call that follows runs under its own snapshot, so its
// failure never undoes this. On an error nothing is changed.
func SettleAction(st StateDB, env *BlockEnv, a *Action, fee Fee) (*EscrowSlot, error) {
	slot, ok := ReadEscrowSlot(st, a.Marker)
	if !ok {
		return nil, fmt.Errorf("%w: no slot of marker %x", ErrActionSlot, a.Marker)
	}
	if fee.Total == nil || fee.Burn == nil || fee.Tip == nil || !new(uint256.Int).Add(fee.Burn, fee.Tip).Eq(fee.Total) || !fee.Total.Eq(a.Debit) {
		return nil, fmt.Errorf("%w: debit %v not split into burn and tip", ErrActionDebit, a.Debit)
	}
	height := env.Header.Number.Uint64()
	snap := st.Snapshot()
	if err := DebitEscrowSlot(st, height, slot.Policy, a.Marker, a.Debit); err != nil {
		st.RevertToSnapshot(snap)
		return nil, fmt.Errorf("%w: %w", ErrActionDebit, err)
	}
	st.AddBalance(env.Header.Coinbase, fee.Tip)
	return slot, nil
}

// WriteActionResult writes the action-result log of a policy action from
// the escrow account, whether its policy call succeeded or not: topic 0 is
// K("ghost/action-result/v1"), topic 1 the marker, and the data the nonce
// the action spent, the debit, the call's status (1 for success, 0 for
// failure), the gas the call used and ActionReturnHash of its return data,
// 32 bytes each.
func WriteActionResult(st StateDB, height uint64, a *Action, success bool, gasUsed uint64, ret []byte) {
	var status uint64
	if success {
		status = 1
	}
	retHash := ActionReturnHash(ret)
	data := make([]byte, 0, actionResultLogSize)
	data = append(data, common.LeftPadBytes(binary.BigEndian.AppendUint64(nil, a.Nonce), 32)...)
	data = append(data, amountWord(amountOrZero(a.Debit))...)
	data = append(data, common.LeftPadBytes(binary.BigEndian.AppendUint64(nil, status), 32)...)
	data = append(data, common.LeftPadBytes(binary.BigEndian.AppendUint64(nil, gasUsed), 32)...)
	data = append(data, retHash[:]...)
	st.AddLog(&types.Log{
		Address:     ghost.EscrowAccount,
		Topics:      []common.Hash{ghosttree.K(TagActionResult), a.Marker},
		Data:        data,
		BlockNumber: height,
	})
}
