// Copyright 2026 The go-ethereum Authors
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

package rpc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type selfDecoding struct{ Text string }

func (s *selfDecoding) UnmarshalJSON(input []byte) error {
	return json.Unmarshal(input, &s.Text)
}

// TestRPCNullArguments checks that a JSON null passed for a required (non-pointer)
// argument is rejected, while null for an optional (pointer) argument stays nil.
func TestRPCNullArguments(t *testing.T) {
	var (
		tInt   = reflect.TypeOf(0)
		tPtr   = reflect.TypeOf((*int)(nil))
		tSelf  = reflect.TypeOf(selfDecoding{})
		tSlice = reflect.TypeOf([]float64(nil))
	)
	tests := []struct {
		name  string
		input string
		types []reflect.Type
		want  []any
		err   string
	}{
		{"null into a pointer", `[null]`, []reflect.Type{tPtr}, []any{(*int)(nil)}, ""},
		{"spaced null into a pointer", `[ null ]`, []reflect.Type{tPtr}, []any{(*int)(nil)}, ""},
		{"missing optional argument", `[1]`, []reflect.Type{tInt, tPtr}, []any{1, (*int)(nil)}, ""},
		{"null params", `null`, []reflect.Type{tPtr}, []any{(*int)(nil)}, ""},
		{"null into a slice", `[1, null]`, []reflect.Type{tInt, tSlice}, []any{1, []float64(nil)}, ""},
		{"self decoding", `["0x1234"]`, []reflect.Type{tSelf}, []any{selfDecoding{Text: "0x1234"}}, ""},

		{"null into a value", `[null]`, []reflect.Type{tInt}, nil, "missing value for required argument 0"},
		{"null into a second value", `[1, null]`, []reflect.Type{tInt, tInt}, nil, "missing value for required argument 1"},
		{"self decoding null", `[null]`, []reflect.Type{tSelf}, nil, "missing value for required argument 0"},
		{"wrong type", `["not an int"]`, []reflect.Type{tInt}, nil, "invalid argument 0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := parsePositionalArguments(json.RawMessage(tc.input), tc.types)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("expected error containing %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(args) != len(tc.want) {
				t.Fatalf("got %d args, want %d", len(args), len(tc.want))
			}
			for i, arg := range args {
				if !reflect.DeepEqual(arg.Interface(), tc.want[i]) {
					t.Errorf("arg %d: got %#v, want %#v", i, arg.Interface(), tc.want[i])
				}
			}
		})
	}
}

// TestRPCKeyUnescape checks that unicode escapes in the keys of a JSON-RPC
// message are unescaped before the keys are matched to message fields.
// Messages are decoded by encoding/json, which unescapes keys.
func TestRPCKeyUnescape(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		version string
		method  string
		id      string
	}{
		{"plain keys", `{"jsonrpc":"2.0","method":"m","id":7}`, "2.0", "m", "7"},
		{"unicode-escaped keys", "{\"jsonrp\\u0063\":\"2.0\",\"metho\\u0064\":\"m\",\"i\\u0064\":7}", "2.0", "m", "7"},
		{"double-escaped key is not method", `{"metho\\u0064":"not the method key"}`, "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, batch := range []bool{false, true} {
				input := tc.input
				if batch {
					input = "[" + input + "]"
				}
				msgs, isBatch := parseMessage(json.RawMessage(input))
				if isBatch != batch || len(msgs) != 1 {
					t.Fatalf("batch=%v: got %d messages, batch %v", batch, len(msgs), isBatch)
				}
				msg := msgs[0]
				if msg.Version != tc.version || msg.Method != tc.method || string(msg.ID) != tc.id {
					t.Errorf("batch=%v: got version %q method %q id %q, want %q %q %q",
						batch, msg.Version, msg.Method, msg.ID, tc.version, tc.method, tc.id)
				}
			}
		})
	}
}
