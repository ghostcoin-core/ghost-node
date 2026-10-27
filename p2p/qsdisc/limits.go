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

package qsdisc

import "time"

// The limits on everything a remote peer can make a node hold or do. They
// are written, with their measurement, in docs/account-transactions.md.
const (
	// MaxPacketSize is the largest UDP packet, in bytes. A larger packet is
	// dropped undecoded.
	MaxPacketSize = 1280

	// MaxNeighbors is the most entries in one neighbors packet, the bucket
	// size.
	MaxNeighbors = BucketSize

	// MaxAmplification is the most times the bytes of a findnode that its
	// neighbors answer may take; the answer holds fewer nodes when a full
	// one would be larger. FindnodeSize is the size Encode pads a findnode
	// to, so that a full answer fits.
	MaxAmplification = 2
	FindnodeSize     = MaxPacketSize / MaxAmplification

	// NumBuckets is the number of distance buckets of the table, one for
	// each of the upper 1/15 of the log distances; closer nodes share the
	// first bucket.
	NumBuckets = 17

	// BucketSize is the number of nodes in a bucket.
	BucketSize = 16

	// MaxReplacements is the number of replacement candidates of a bucket.
	MaxReplacements = 10

	// BucketIPLimit is the most addresses from one /24 (BucketSubnet) in a
	// bucket, TableIPLimit the most in the table. Addresses on a LAN are not
	// counted, as in the old table.
	BucketIPLimit, BucketSubnet = 2, 24
	TableIPLimit, TableSubnet   = 10, 24

	// ProvenTime is how long an endpoint stays proven after it answered one
	// of our pings with our token.
	ProvenTime = 12 * time.Hour

	// PingTimeout is how long a ping waits for its pong.
	PingTimeout = 5 * time.Second

	// MaxPendingPings is the most pings waiting for a pong at once.
	MaxPendingPings = 512

	// MaxRemotePings is the most of the pending pings that a remote peer can
	// make a node send (a ping back to an unproven endpoint, or the ping of
	// a verification it triggered). The other pings stay for the node's own
	// live checks and lookups, which a remote peer cannot use up.
	MaxRemotePings = 448

	// MaxChallengePings is the most of the pending pings that prove again
	// the endpoint of a table node whose proof was pushed out of the
	// endpoints a node keeps, sent when the node pings us without it. They
	// are apart from MaxRemotePings, so that a flood of pings from new
	// sources cannot stop a table node from proving itself again, and leave
	// MaxPendingPings-MaxRemotePings-MaxChallengePings for the node's own
	// live checks and lookups.
	MaxChallengePings = 32

	// MaxVerifications is the most record verifications running at once.
	MaxVerifications = 8

	// VerifyInterval is the least time between two verifications started
	// for one node ID at one endpoint. It is kept per endpoint so that a
	// peer claiming an ID at its own endpoint cannot hold up the
	// verification of that ID at the honest one.
	VerifyInterval = time.Minute

	// MaxVerifyStarts is the most verification starts remembered to
	// enforce VerifyInterval, and so the most that start in one
	// VerifyInterval over all IDs and endpoints.
	MaxVerifyStarts = 1024

	// MaxVerifyRetries is the most verifications a remote peer triggered
	// that are queued to start later because all MaxVerifications were
	// running; the oldest is dropped first. A retry is held to the same
	// budgets as a first attempt.
	MaxVerifyRetries = 64

	// MaxFailed is the size of the memory of failed verifications; the
	// oldest is dropped first.
	MaxFailed = 1024

	// SourceRate and SourceBurst are the token bucket of each source
	// address: packets a second, and the most at once. A packet over it is
	// dropped without an answer. Every ping and findnode of the address is
	// charged to its one bucket, whatever its port and cookie. A findnode
	// always needs the cookie our pongs gave its endpoint and ID; without
	// it, it is dropped and charges nothing.
	SourceRate  = 10
	SourceBurst = 20

	// CookieReserve is the packets of a source's bucket that only a request
	// carrying that cookie may take, so that packets forged from the
	// address cannot spend the whole bucket and stop the peer's own live
	// checks of us.
	CookieReserve = SourceBurst / 2

	// MaxSources is the number of source addresses whose token bucket is
	// tracked and the number of endpoints whose proof is kept; the least
	// recently seen is dropped first.
	MaxSources = 1024

	// LookupAlpha is the number of nodes a lookup asks at a time,
	// LookupTimeout how long it waits for each, and LookupResults the most
	// nodes it returns.
	LookupAlpha   = 3
	LookupTimeout = 5 * time.Second
	LookupResults = 16

	// RevalidateInterval is the time between two live checks of a table
	// node.
	RevalidateInterval = 10 * time.Second

	// BootnodeRetryInterval is the least time between the end of one
	// bootstrap and the start of the next while the table holds no
	// bootnode. A node that reached none on its first start, or lost them
	// all, tries them again this often.
	BootnodeRetryInterval = 10 * time.Second

	// MaxRevalidateFails is the number of live checks in a row a table node
	// may leave unanswered before it is removed. One lost pong, or one a
	// flood crowded out, does not evict a live node.
	MaxRevalidateFails = 3
)
