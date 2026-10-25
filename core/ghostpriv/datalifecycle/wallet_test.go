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

package datalifecycle

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/ghostpriv"
	"github.com/ethereum/go-ethereum/core/ghostpriv/ghostprivtest"
	"github.com/ethereum/go-ethereum/core/ghosttree"
)

// The wallet here is a stand-in for the real one, whose key derivation is
// not reimplemented. One Phantom Key, a string of digits, controls one data
// commitment (spec 04, section 3), and every secret is derived from the
// digits with a hash tag of its own: the secret parts s, r and b, the note
// key k_note, the data key k_data, the two nonces and the host locator.
//
//	cf  = K(content fingerprint tag, len(plaintext), plaintext)
//	F_d = K(data fingerprint tag, s, r, b, DATA, cf, rule)
//	C   = K("ghost/data-commitment/v1", DATA, F_d), computed by the node
//	m   = K("ghost/data-marker/v1", s, r, b)
//
// The note holds only what the wallet cannot derive from the digits, the
// version, the plaintext length and cf, encrypted under k_note. The file is
// encrypted under k_data and kept off chain by the host; neither key, nor a
// part of one, nor the host locator is ever written on chain.
const (
	tagDigits             = "ghost/test-data-wallet/digits/v1"
	tagSecretS            = "ghost/test-data-wallet/secret-s/v1"
	tagSecretR            = "ghost/test-data-wallet/secret-r/v1"
	tagSecretB            = "ghost/test-data-wallet/secret-b/v1"
	tagNoteKey            = "ghost/test-data-wallet/note-key/v1"
	tagDataKey            = "ghost/test-data-wallet/data-key/v1"
	tagNoteNonce          = "ghost/test-data-wallet/note-nonce/v1"
	tagDataNonce          = "ghost/test-data-wallet/data-nonce/v1"
	tagHostLocator        = "ghost/test-data-wallet/host-locator/v1"
	tagContentFingerprint = "ghost/test-data-wallet/content-fingerprint/v1"
	tagDataFingerprint    = "ghost/test-data-wallet/data-fingerprint/v1"

	// digitCount is the length of a Phantom Key in this stand-in.
	digitCount = 24

	// notePlainSize is the plaintext of a note: AES-GCM adds the 12-byte
	// nonce in front and the 16-byte tag behind, filling the note exactly.
	notePlainSize = ghostpriv.NoteSize - 12 - 16

	// noteVersion is the version of the data note's plaintext.
	noteVersion uint16 = 1
)

var (
	errDecrypt         = errors.New("authenticated decryption failed")
	errFingerprint     = errors.New("content fingerprint does not match the commitment")
	errDataUnavailable = errors.New("data unavailable: the host has no ciphertext")
	errNoteNotFound    = errors.New("no note opens under the note key")
	errRestoreMismatch = errors.New("recomputed commitment differs from the stored leaf")
)

// phantomKey is the Phantom Key: the digits, the only thing a holder keeps.
type phantomKey string

// newPhantomKey makes the digits of a label, standing in for a fresh draw.
func newPhantomKey(label string) phantomKey {
	h := ghosttree.K(tagDigits, []byte(label))
	digits := make([]byte, digitCount)
	for i := range digits {
		digits[i] = '0' + h[i]%10
	}
	return phantomKey(digits)
}

// wallet is what a device derives from the digits and the chain id. It keeps
// nothing else: everything about the commitment comes from the chain.
type wallet struct {
	key     phantomKey
	chainID uint64
}

func openWallet(key phantomKey, chainID uint64) *wallet {
	return &wallet{key: key, chainID: chainID}
}

func (w *wallet) secret(tag string) common.Hash { return ghosttree.K(tag, []byte(w.key)) }

func (w *wallet) noteKey() common.Hash { return w.secret(tagNoteKey) }
func (w *wallet) dataKey() common.Hash { return w.secret(tagDataKey) }
func (w *wallet) locator() common.Hash { return w.secret(tagHostLocator) }

// contentFingerprint is cf of a plaintext.
func contentFingerprint(plaintext []byte) common.Hash {
	return ghosttree.K(tagContentFingerprint, binary.BigEndian.AppendUint64(nil, uint64(len(plaintext))), plaintext)
}

// fingerprint is F_d for the content fingerprint cf, with the empty rule.
func (w *wallet) fingerprint(cf common.Hash) common.Hash {
	s, r, b := w.secret(tagSecretS), w.secret(tagSecretR), w.secret(tagSecretB)
	return ghosttree.K(tagDataFingerprint, s[:], r[:], b[:], ghostpriv.Data[:], cf[:], make([]byte, 32))
}

// commitment is C for cf, the leaf the node appends.
func (w *wallet) commitment(cf common.Hash) common.Hash {
	return ghostpriv.DataCommitmentVersion(ghostpriv.SaltedCommitVersion, w.fingerprint(cf))
}

// marker is the commitment's one marker.
func (w *wallet) marker() common.Hash {
	s, r, b := w.secret(tagSecretS), w.secret(tagSecretR), w.secret(tagSecretB)
	return ghosttree.K(ghostpriv.TagDataMarker, s[:], r[:], b[:])
}

// associatedData binds a ciphertext to the chain id, the version and DATA,
// so a ciphertext made for one chain or type fails to decrypt as another.
func (w *wallet) associatedData() []byte {
	ad := binary.BigEndian.AppendUint64(nil, w.chainID)
	ad = binary.BigEndian.AppendUint16(ad, ghostpriv.Version)
	return append(ad, ghostpriv.Data[:]...)
}

func newAEAD(key common.Hash) cipher.AEAD {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// seal encrypts under key with the nonce derived under nonceTag: nonce, then
// the ciphertext and tag. One key encrypts one plaintext, so the derived
// nonce is never reused under it.
func (w *wallet) seal(key common.Hash, nonceTag string, plaintext []byte) []byte {
	aead := newAEAD(key)
	nonce := w.secret(nonceTag).Bytes()[:aead.NonceSize()]
	return aead.Seal(common.CopyBytes(nonce), nonce, plaintext, w.associatedData())
}

// open is the authenticated decryption of seal under key.
func (w *wallet) open(key common.Hash, sealed []byte) ([]byte, error) {
	return openSealed(key, sealed, w.associatedData())
}

func openSealed(key common.Hash, sealed, ad []byte) ([]byte, error) {
	aead := newAEAD(key)
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, errDecrypt
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], ad)
	if err != nil {
		return nil, errDecrypt
	}
	return plain, nil
}

// note is the commitment's note for a plaintext: version, length and cf,
// zero padded and encrypted under k_note to exactly the note length.
func (w *wallet) note(plaintext []byte) [ghostpriv.NoteSize]byte {
	return w.noteFor(uint64(len(plaintext)), contentFingerprint(plaintext))
}

func (w *wallet) noteFor(length uint64, cf common.Hash) [ghostpriv.NoteSize]byte {
	plain := make([]byte, notePlainSize)
	binary.BigEndian.PutUint16(plain[0:2], noteVersion)
	binary.BigEndian.PutUint64(plain[2:10], length)
	copy(plain[10:42], cf[:])
	var note [ghostpriv.NoteSize]byte
	if sealed := w.seal(w.noteKey(), tagNoteNonce, plain); copy(note[:], sealed) != ghostpriv.NoteSize {
		panic("note does not fill the note length")
	}
	return note
}

// noteContent is the plaintext of a data note.
type noteContent struct {
	length uint64
	cf     common.Hash
}

// openNote decrypts a note under k_note, if it is this wallet's.
func (w *wallet) openNote(note [ghostpriv.NoteSize]byte) (noteContent, bool) {
	plain, err := w.open(w.noteKey(), note[:])
	if err != nil || len(plain) != notePlainSize || binary.BigEndian.Uint16(plain[0:2]) != noteVersion {
		return noteContent{}, false
	}
	return noteContent{length: binary.BigEndian.Uint64(plain[2:10]), cf: common.BytesToHash(plain[10:42])}, true
}

// encryptFile is the ciphertext the host keeps: the file under k_data.
func (w *wallet) encryptFile(plaintext []byte) []byte {
	return w.seal(w.dataKey(), tagDataNonce, plaintext)
}

// decryptFile opens a ciphertext under k_data and checks the plaintext
// against the content fingerprint the commitment holds. A ciphertext that is
// not the wallet's fails authenticated decryption; one that decrypts to
// other bytes fails the fingerprint check. Either way nothing is shown.
func (w *wallet) decryptFile(ciphertext []byte, want noteContent) ([]byte, error) {
	plain, err := w.open(w.dataKey(), ciphertext)
	if err != nil {
		return nil, err
	}
	if uint64(len(plain)) != want.length || contentFingerprint(plain) != want.cf {
		return nil, errFingerprint
	}
	return plain, nil
}

// read fetches the file from the host and opens it. A host without the
// ciphertext is reported as unavailable, never as other bytes.
func (w *wallet) read(h *host, want noteContent) ([]byte, error) {
	ciphertext, ok := h.get(w.locator())
	if !ok {
		return nil, errDataUnavailable
	}
	return w.decryptFile(ciphertext, want)
}

// dataReveal is a data reveal of the commitment for purpose, made for
// verifier, against a data tree root, with the stub proof of its binding
// digest on the network's chain.
func (w *wallet) dataReveal(n *node, root common.Hash, purpose byte, verifier common.Address) *ghostpriv.DataReveal {
	r := &ghostpriv.DataReveal{
		Version:  ghostpriv.Version,
		ChainID:  n.chain.Config().GetChainID().Uint64(),
		Marker:   w.marker(),
		Root:     root,
		Purpose:  ghostpriv.PurposeField(purpose),
		Verifier: verifier,
	}
	stubProve(n, r)
	return r
}

// stubProve sets the stub proof of the data reveal's binding digest.
func stubProve(n *node, r *ghostpriv.DataReveal) {
	r.Proof = ghostprivtest.Proof(r.BindingDigest(r.ChainID, n.chain.Genesis().Hash()))
}

// restored is what a wallet learns about its commitment from the digits and
// the endpoint's bulk answers alone.
type restored struct {
	content  noteContent
	leaf     common.Hash
	position uint32
	block    uint64
	spent    bool
	notes    []noteRecord // the bulk answer, kept for the membership witness
}

// restore runs spec 04, section 8: derive the secrets from the digits, find
// the note by trying k_note against every data note fetched in bulk,
// recompute C from the note's cf and check it is the leaf stored with the
// note, failing closed if not, then compute the marker locally and check it
// against the marker set fetched in bulk.
func (w *wallet) restore(ep *endpoint) (*restored, error) {
	notes := ep.notes()
	var found *restored
	for _, rec := range notes {
		content, ok := w.openNote(rec.note)
		if !ok {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: notes at positions %d and %d both open", errRestoreMismatch, found.position, rec.position)
		}
		found = &restored{content: content, leaf: rec.leaf, position: rec.position, block: rec.block}
	}
	if found == nil {
		return nil, errNoteNotFound
	}
	if c := w.commitment(found.content.cf); c != found.leaf {
		return nil, fmt.Errorf("%w: %x recomputed, %x stored at position %d", errRestoreMismatch, c, found.leaf, found.position)
	}
	found.spent = ep.markers()[w.marker()]
	found.notes = notes
	return found, nil
}
