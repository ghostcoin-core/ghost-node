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

package enode

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ethereum/go-ethereum/p2p/enr"
)

// quantumSafeIDHexLen is the length of the user part of a quantum-safe node
// URL: the 32-byte node ID in hex.
const quantumSafeIDHexLen = 2 * len(ID{})

// NewQuantumSafe makes a node known only by its quantum-safe node ID (the
// hash of its ML-DSA-44 public key, see package p2p/qsconn), its IP and its
// TCP port. The record uses the null identity scheme: it is not signed, and
// the public key only travels in the handshake, where the dialling side checks
// that it hashes to id.
func NewQuantumSafe(id ID, ip net.IP, tcp int) *Node {
	var r enr.Record
	if len(ip) > 0 {
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		r.Set(enr.IP(ip))
	}
	if tcp != 0 {
		r.Set(enr.TCP(tcp))
	}
	return SignNull(&r, id)
}

// ParseQuantumSafe parses a quantum-safe node URL,
// enode://<64 hex chars of the node ID>@host:port. The host is an IP address
// or a DNS name; the port is the TCP port. Nothing else is accepted.
func ParseQuantumSafe(rawurl string) (*Node, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "enode" {
		return nil, errors.New("invalid URL scheme, want \"enode\"")
	}
	if u.User == nil {
		return nil, errors.New("quantum-safe node URL needs <node ID>@host:port")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return nil, errors.New("invalid node ID")
	}
	id, err := parseQuantumSafeID(u.User.Username())
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("quantum-safe node URL takes no path or query")
	}
	if u.Hostname() == "" {
		return nil, errors.New("quantum-safe node URL needs a host")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		ips, err := lookupIPFunc(u.Hostname())
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no address for host %s", u.Hostname())
		}
		ip = ips[0]
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid port")
	}
	return NewQuantumSafe(id, ip, int(port)), nil
}

// parseQuantumSafeID decodes the 64 hex chars of a node ID.
func parseQuantumSafeID(in string) (ID, error) {
	var id ID
	if len(in) != quantumSafeIDHexLen {
		return id, fmt.Errorf("invalid node ID (wrong length, want %d hex chars)", quantumSafeIDHexLen)
	}
	if _, err := hex.Decode(id[:], []byte(in)); err != nil {
		return id, fmt.Errorf("invalid node ID (%v)", err)
	}
	return id, nil
}

// isQuantumSafeURL reports whether the user part of an enode URL is a
// quantum-safe node ID rather than a secp256k1 public key.
func isQuantumSafeURL(rawurl string) bool {
	u, err := url.Parse(rawurl)
	return err == nil && u.User != nil && len(u.User.Username()) == quantumSafeIDHexLen
}

// isQuantumSafe reports whether n is known only by its node ID, as made by
// NewQuantumSafe.
func (n *Node) isQuantumSafe() bool {
	return n.r.IdentityScheme() == "null"
}

// URLQuantumSafe returns enode://<64 hex chars of the node ID>@host:port, or
// enode://<64 hex chars> when the node has no IP address.
func (n *Node) URLQuantumSafe() string {
	u := url.URL{Scheme: "enode"}
	nodeid := hex.EncodeToString(n.id[:])
	if !n.ip.IsValid() {
		u.Host = nodeid
	} else {
		addr := net.TCPAddr{IP: n.IP(), Port: n.TCP()}
		u.User = url.User(nodeid)
		u.Host = addr.String()
	}
	return u.String()
}
