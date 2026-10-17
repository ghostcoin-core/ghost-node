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

package ghostrules

import "errors"

// maxTimestamp is the first timestamp the rule rejects, 2^63, so timestamps
// stay safe in signed 64-bit arithmetic.
const maxTimestamp = 1 << 63

var (
	// ErrTimestampNotAfterParent is returned for a timestamp at or before
	// its parent's.
	ErrTimestampNotAfterParent = errors.New("ghostrules: timestamp not after parent")

	// ErrTimestampTooFarAhead is returned for a timestamp beyond the local
	// clock plus the allowed drift. It is the only one of these errors that
	// can clear with time: a caller may hold the block and retry once its
	// clock advances, and skips this check when revalidating history.
	ErrTimestampTooFarAhead = errors.New("ghostrules: timestamp too far in the future")

	// ErrTimestampOverflow is returned for a timestamp of 2^63 or more.
	ErrTimestampOverflow = errors.New("ghostrules: timestamp not below 2^63")
)

// CheckTimestamp applies the timestamp rule to a block at height 1 or more:
// the timestamp must be strictly after the parent's, at most now plus the
// future drift, and below 2^63. now is the caller's local clock in seconds.
// The future-drift error is returned only when the other checks pass.
func (p Params) CheckTimestamp(parentTime, time, now uint64) error {
	if time >= maxTimestamp {
		return ErrTimestampOverflow
	}
	if time <= parentTime {
		return ErrTimestampNotAfterParent
	}
	// time > now + drift, written so that now + drift cannot overflow.
	if time > p.FutureDrift && time-p.FutureDrift > now {
		return ErrTimestampTooFarAhead
	}
	return nil
}
