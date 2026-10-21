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

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/ethereum/go-ethereum/p2p/qsconn"
	"github.com/ethereum/go-ethereum/rlp"
)

// Packet types. A packet is one type byte followed by the RLP of its body.
// Packets carry node IDs and endpoints only, never a record or a signature:
// nothing in them is trusted until the node's record is fetched and
// verified.
const (
	PingPacket byte = iota + 1
	PongPacket
	FindnodePacket
	NeighborsPacket
)

// TokenSize is the size of the random token of a ping and its pong.
const TokenSize = 16

// CookieSize is the size of a cookie. A node gives every endpoint that
// pings it a cookie in its pong, a keyed hash of that endpoint, the pinging
// node's ID and the time period under a secret of the node, which expires
// at most ProvenTime after it was given; the endpoint puts it in its later
// pings and findnodes to the node. Only an endpoint that receives the
// node's pongs can know its cookie, so a ping carrying it is charged to an
// allowance of its own that packets forged from the endpoint's address
// cannot use up, and a findnode without it is never answered.
const CookieSize = 16

var (
	errPacketTooLarge = errors.New("qsdisc: packet too large")
	errPacketEmpty    = errors.New("qsdisc: empty packet")
	errPacketType     = errors.New("qsdisc: unknown packet type")
	errTooManyNodes   = errors.New("qsdisc: too many neighbors")
	errEndpointIP     = errors.New("qsdisc: neighbor IP is neither 4 nor 16 bytes")
)

// Ping asks a node to answer with a pong carrying the same token. Cookie is
// the cookie the receiver gave the sender's endpoint, or zero when it has
// none.
type Ping struct {
	From   qsconn.NodeID
	Token  [TokenSize]byte
	Cookie [CookieSize]byte
	Rest   []rlp.RawValue `rlp:"tail"`
}

// Pong answers a ping. Cookie is the cookie the sender gives the endpoint
// the ping came from; a pong is the same size as the ping it answers.
type Pong struct {
	From   qsconn.NodeID
	Token  [TokenSize]byte
	Cookie [CookieSize]byte
	Rest   []rlp.RawValue `rlp:"tail"`
}

// Findnode asks for the nodes closest to Target. Token is random, and the
// answer must echo it. Cookie is the cookie the receiver gave the sender's
// endpoint and ID; a findnode without it is dropped. The answer is at most
// MaxAmplification times the size of the findnode, so Encode pads a
// findnode with no Rest to FindnodeSize.
type Findnode struct {
	From   qsconn.NodeID
	Target qsconn.NodeID
	Token  [TokenSize]byte
	Cookie [CookieSize]byte
	Rest   []rlp.RawValue `rlp:"tail"`
}

// Neighbors answers a findnode with at most MaxNeighbors nodes and the
// findnode's token.
type Neighbors struct {
	From  qsconn.NodeID
	Token [TokenSize]byte
	Nodes []Neighbor
	Rest  []rlp.RawValue `rlp:"tail"`
}

// Neighbor is a node ID and the UDP endpoint it is said to be at.
type Neighbor struct {
	ID  qsconn.NodeID
	IP  net.IP
	UDP uint16
}

// Addr returns the endpoint of the neighbor.
func (n *Neighbor) Addr() netip.AddrPort {
	ip, _ := netip.AddrFromSlice(n.IP)
	return netip.AddrPortFrom(ip.Unmap(), n.UDP)
}

func neighborOf(id qsconn.NodeID, addr netip.AddrPort) Neighbor {
	ip := addr.Addr().Unmap()
	return Neighbor{ID: id, IP: ip.AsSlice(), UDP: addr.Port()}
}

// Encode returns the packet of a Ping, Pong, Findnode or Neighbors.
func Encode(p any) ([]byte, error) {
	var typ byte
	switch p := p.(type) {
	case *Ping:
		typ = PingPacket
	case *Pong:
		typ = PongPacket
	case *Findnode:
		typ = FindnodePacket
		if len(p.Rest) == 0 {
			padded, err := padFindnode(p)
			if err != nil {
				return nil, err
			}
			return encodePacket(typ, padded)
		}
	case *Neighbors:
		if len(p.Nodes) > MaxNeighbors {
			return nil, errTooManyNodes
		}
		typ = NeighborsPacket
	default:
		return nil, fmt.Errorf("qsdisc: can't encode %T", p)
	}
	return encodePacket(typ, p)
}

func encodePacket(typ byte, p any) ([]byte, error) {
	body, err := rlp.EncodeToBytes(p)
	if err != nil {
		return nil, err
	}
	b := append([]byte{typ}, body...)
	if len(b) > MaxPacketSize {
		return nil, errPacketTooLarge
	}
	return b, nil
}

// padFindnode returns a copy of p whose packet is at least FindnodeSize
// bytes, padded with a string of zeros in Rest.
func padFindnode(p *Findnode) (*Findnode, error) {
	body, err := rlp.EncodeToBytes(p)
	if err != nil {
		return nil, err
	}
	q := *p
	// The pad string's header and the growth of the list header take at
	// most a few bytes; start below and grow the pad until it is enough.
	for n := max(FindnodeSize-1-len(body)-8, 0); ; n++ {
		pad, err := rlp.EncodeToBytes(make([]byte, n))
		if err != nil {
			return nil, err
		}
		q.Rest = []rlp.RawValue{pad}
		body, err = rlp.EncodeToBytes(&q)
		if err != nil {
			return nil, err
		}
		if 1+len(body) >= FindnodeSize {
			return &q, nil
		}
	}
}

// Decode decodes a packet. A packet over MaxPacketSize is dropped before it
// is decoded.
func Decode(b []byte) (any, error) {
	if len(b) > MaxPacketSize {
		return nil, errPacketTooLarge
	}
	if len(b) == 0 {
		return nil, errPacketEmpty
	}
	var p any
	switch b[0] {
	case PingPacket:
		p = new(Ping)
	case PongPacket:
		p = new(Pong)
	case FindnodePacket:
		p = new(Findnode)
	case NeighborsPacket:
		p = new(Neighbors)
	default:
		return nil, errPacketType
	}
	if err := rlp.DecodeBytes(b[1:], p); err != nil {
		return nil, err
	}
	if n, ok := p.(*Neighbors); ok {
		if len(n.Nodes) > MaxNeighbors {
			return nil, errTooManyNodes
		}
		for i := range n.Nodes {
			if l := len(n.Nodes[i].IP); l != net.IPv4len && l != net.IPv6len {
				return nil, errEndpointIP
			}
		}
	}
	return p, nil
}
