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
	"net"
	"strings"
	"testing"
)

const qsTestID = "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"

// TestEnodeURLQuantumSafe covers enode://<64 hex chars of the node ID>@host:port.
func TestEnodeURLQuantumSafe(t *testing.T) {
	url := "enode://" + qsTestID + "@10.3.58.6:30303"
	for name, parse := range map[string]func(string) (*Node, error){
		"ParseQuantumSafe": ParseQuantumSafe,
		"ParseV4":          ParseV4,
		"Parse":            func(s string) (*Node, error) { return Parse(ValidSchemes, s) },
	} {
		n, err := parse(url)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n.ID() != HexID(qsTestID) {
			t.Errorf("%s: ID %v, want %s", name, n.ID(), qsTestID)
		}
		if !n.IP().Equal(net.IP{10, 3, 58, 6}) || n.TCP() != 30303 || n.UDP() != 0 {
			t.Errorf("%s: endpoint %v tcp %d udp %d", name, n.IP(), n.TCP(), n.UDP())
		}
		if n.Pubkey() != nil {
			t.Errorf("%s: node has a secp256k1 key", name)
		}
		if n.Record().IdentityScheme() != "null" {
			t.Errorf("%s: scheme %q, want null", name, n.Record().IdentityScheme())
		}
		if got := n.URLv4(); got != url {
			t.Errorf("%s: URLv4 %s, want %s", name, got, url)
		}
		if got := n.String(); got != url {
			t.Errorf("%s: String %s, want %s", name, got, url)
		}
	}

	// The text form, used by the static and trusted node lists, round-trips.
	n := NewQuantumSafe(HexID(qsTestID), net.ParseIP("127.0.0.1"), 30303)
	text, err := n.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != "enode://"+qsTestID+"@127.0.0.1:30303" {
		t.Fatalf("text %s", text)
	}
	var back Node
	if err := back.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if back.ID() != n.ID() || back.TCP() != 30303 || !back.IP().Equal(net.IP{127, 0, 0, 1}) {
		t.Fatalf("round trip gave %v", back.String())
	}

	// IPv6.
	n6, err := ParseQuantumSafe("enode://" + qsTestID + "@[2001:db8::1]:30303")
	if err != nil {
		t.Fatal(err)
	}
	if n6.URLv4() != "enode://"+qsTestID+"@[2001:db8::1]:30303" {
		t.Fatalf("IPv6 URL %s", n6.URLv4())
	}

	// A host name is resolved.
	defer func(f func(string) ([]net.IP, error)) { lookupIPFunc = f }(lookupIPFunc)
	lookupIPFunc = func(host string) ([]net.IP, error) {
		if host == "node.example" {
			return []net.IP{{10, 0, 0, 7}}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	nh, err := ParseV4("enode://" + qsTestID + "@node.example:30303")
	if err != nil {
		t.Fatal(err)
	}
	if !nh.IP().Equal(net.IP{10, 0, 0, 7}) {
		t.Fatalf("resolved IP %v", nh.IP())
	}
}

func TestEnodeURLQuantumSafeInvalid(t *testing.T) {
	for _, test := range []struct{ input, wantError string }{
		{"enode://" + qsTestID[:62] + "@10.3.58.6:30303", "invalid public key"}, // 62 hex chars go to the secp256k1 parser
		{"enode://" + qsTestID[:63] + "x@10.3.58.6:30303", "invalid node ID"},
		{"enode://" + qsTestID + "@10.3.58.6", "invalid port"},
		{"enode://" + qsTestID + "@10.3.58.6:0", "invalid port"},
		{"enode://" + qsTestID + "@10.3.58.6:70000", "invalid port"},
		{"enode://" + qsTestID + "@10.3.58.6:30303?discport=30301", "no path or query"},
		{"enode://" + qsTestID + "@10.3.58.6:30303/x", "no path or query"},
		{"enode://" + qsTestID + ":pw@10.3.58.6:30303", "invalid node ID"},
		{"enode://" + qsTestID + "@:30303", "needs a host"},
		{"http://" + qsTestID + "@10.3.58.6:30303", "invalid URL scheme"},
	} {
		var err error
		if strings.HasPrefix(test.input, "enode://") {
			_, err = ParseV4(test.input)
		} else {
			_, err = ParseQuantumSafe(test.input)
		}
		if err == nil || !strings.Contains(err.Error(), test.wantError) {
			t.Errorf("%s: got error %v, want %q", test.input, err, test.wantError)
		}
	}
}

// TestLocalNodeQuantumSafe checks that a quantum-safe local node has the
// given ID and publishes it in the 64 hex chars form.
func TestLocalNodeQuantumSafe(t *testing.T) {
	db, _ := OpenDB("")
	defer db.Close()
	ln := NewLocalNodeQuantumSafe(db, HexID(qsTestID))
	ln.SetStaticIP(net.IP{127, 0, 0, 1})
	n := ln.Node()
	if n.ID() != HexID(qsTestID) || ln.ID() != HexID(qsTestID) {
		t.Fatalf("local node ID %v", n.ID())
	}
	if n.Pubkey() != nil || n.Record().IdentityScheme() != "null" {
		t.Fatal("local node is not a null-scheme node without a secp256k1 key")
	}
	if got, want := n.URLv4(), "enode://"+qsTestID+"@127.0.0.1:0"; got != want {
		t.Fatalf("local node URL %s, want %s", got, want)
	}
}
