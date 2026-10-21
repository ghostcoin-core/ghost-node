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

package ethconfig

import (
	"reflect"
	"strings"
	"testing"
)

// TestEthConfigHasNoDiscoveryURLs checks that the eth configuration and its
// TOML form carry no DNS discovery URLs: the node finds peers with the
// quantum-safe discovery of the p2p server only.
func TestEthConfigHasNoDiscoveryURLs(t *testing.T) {
	check := func(what string, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		for i := 0; i < typ.NumField(); i++ {
			if name := typ.Field(i).Name; strings.Contains(name, "DiscoveryURLs") {
				t.Errorf("%s has field %s", what, name)
			}
		}
	}
	check("ethconfig.Config", reflect.TypeOf(Config{}))

	enc, err := Defaults.MarshalTOML()
	if err != nil {
		t.Fatal(err)
	}
	check("the TOML form of ethconfig.Config", reflect.TypeOf(enc))

	// Nor does the TOML decoding read them from a configuration file.
	var dec struct{ fields []string }
	cfg := Defaults
	err = cfg.UnmarshalTOML(func(v interface{}) error {
		typ := reflect.TypeOf(v).Elem()
		for i := 0; i < typ.NumField(); i++ {
			dec.fields = append(dec.fields, typ.Field(i).Name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range dec.fields {
		if strings.Contains(f, "DiscoveryURLs") {
			t.Errorf("TOML decoding reads field %s", f)
		}
	}
	if len(dec.fields) == 0 {
		t.Fatal("TOML decoding read no fields")
	}
}
