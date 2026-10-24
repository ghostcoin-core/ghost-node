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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// BitcoinHeaderSize is the length of a raw Bitcoin block header.
const BitcoinHeaderSize = 80

var (
	// ErrBits is returned for a header whose compact target is negative,
	// zero, above 2^256 - 1 or above the network's proof-of-work limit.
	ErrBits = errors.New("header bits are not a valid target")

	// ErrProofOfWork is returned for a header whose hash is above the target
	// of its own bits.
	ErrProofOfWork = errors.New("header hash is above the target of its bits")
)

// bitcoinHeader is a decoded Bitcoin block header. Hashes are kept in
// Bitcoin's internal byte order, the order in which they are hashed and
// linked; Display gives the reversed order block explorers print.
type bitcoinHeader struct {
	Raw        [BitcoinHeaderSize]byte
	Version    int32
	PrevBlock  [32]byte
	MerkleRoot [32]byte
	Time       uint32
	Bits       uint32
	Nonce      uint32
}

func decodeBitcoinHeader(raw []byte) (*bitcoinHeader, error) {
	if len(raw) != BitcoinHeaderSize {
		return nil, fmt.Errorf("header of %d bytes, want %d", len(raw), BitcoinHeaderSize)
	}
	h := new(bitcoinHeader)
	copy(h.Raw[:], raw)
	h.Version = int32(binary.LittleEndian.Uint32(raw[0:4]))
	copy(h.PrevBlock[:], raw[4:36])
	copy(h.MerkleRoot[:], raw[36:68])
	h.Time = binary.LittleEndian.Uint32(raw[68:72])
	h.Bits = binary.LittleEndian.Uint32(raw[72:76])
	h.Nonce = binary.LittleEndian.Uint32(raw[76:80])
	return h, nil
}

// encodeBitcoinHeader is the raw header of the fields.
func encodeBitcoinHeader(version int32, prev, merkle [32]byte, time, bits, nonce uint32) [BitcoinHeaderSize]byte {
	var raw [BitcoinHeaderSize]byte
	binary.LittleEndian.PutUint32(raw[0:4], uint32(version))
	copy(raw[4:36], prev[:])
	copy(raw[36:68], merkle[:])
	binary.LittleEndian.PutUint32(raw[68:72], time)
	binary.LittleEndian.PutUint32(raw[72:76], bits)
	binary.LittleEndian.PutUint32(raw[76:80], nonce)
	return raw
}

// Hash is the double SHA-256 of the raw header, in internal byte order.
func (h *bitcoinHeader) Hash() [32]byte {
	return doubleSHA256(h.Raw[:])
}

func doubleSHA256(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// Display reverses a hash from internal byte order to the order Bitcoin
// prints it.
func Display(hash [32]byte) [32]byte {
	var out [32]byte
	for i := range hash {
		out[i] = hash[31-i]
	}
	return out
}

// compactTarget expands the compact target of a header's bits: a mantissa of
// 23 bits with a sign bit, times 256^(exponent-3). A negative, zero or too
// large target is ErrBits.
func compactTarget(bits uint32) (*big.Int, error) {
	exponent := uint(bits >> 24)
	mantissa := int64(bits & 0x007fffff)
	if bits&0x00800000 != 0 && mantissa != 0 {
		return nil, fmt.Errorf("%w: %#08x is negative", ErrBits, bits)
	}
	target := big.NewInt(mantissa)
	if exponent <= 3 {
		target.Rsh(target, 8*(3-exponent))
	} else {
		target.Lsh(target, 8*(exponent-3))
	}
	if target.Sign() == 0 {
		return nil, fmt.Errorf("%w: %#08x is zero", ErrBits, bits)
	}
	if target.BitLen() > 256 {
		return nil, fmt.Errorf("%w: %#08x overflows 256 bits", ErrBits, bits)
	}
	return target, nil
}

// compactBits encodes a non-negative target as compact bits, as Bitcoin
// Core's GetCompact does: the target's three most significant bytes, moved
// down a byte when the top one would set the sign bit, and its length in
// bytes. The bytes below the three are dropped.
func compactBits(target *big.Int) uint32 {
	size := uint((target.BitLen() + 7) / 8)
	var mantissa uint64
	if size <= 3 {
		mantissa = target.Uint64() << (8 * (3 - size))
	} else {
		mantissa = new(big.Int).Rsh(target, 8*(size-3)).Uint64()
	}
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		size++
	}
	return uint32(mantissa) | uint32(size)<<24
}

// checkProofOfWork checks that the target of the header's own bits is not
// above the network's proof-of-work limit and the header's hash, read as a
// little-endian number, not above that target, and returns the header's
// work, 2^256 / (target + 1).
func (h *bitcoinHeader) checkProofOfWork(powLimit *big.Int) (*big.Int, error) {
	target, err := compactTarget(h.Bits)
	if err != nil {
		return nil, err
	}
	if target.Cmp(powLimit) > 0 {
		return nil, fmt.Errorf("%w: %#08x is above the network's proof-of-work limit", ErrBits, h.Bits)
	}
	display := Display(h.Hash())
	if new(big.Int).SetBytes(display[:]).Cmp(target) > 0 {
		return nil, fmt.Errorf("%w: block %x, bits %#08x", ErrProofOfWork, display, h.Bits)
	}
	work := new(big.Int).Lsh(big.NewInt(1), 256)
	return work.Div(work, target.Add(target, big.NewInt(1))), nil
}
