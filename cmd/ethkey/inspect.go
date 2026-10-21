// Copyright 2017 The go-ethereum Authors
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
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/urfave/cli/v2"
)

type outputInspect struct {
	Address   string
	Scheme    string
	PublicKey string
	Seed      string `json:",omitempty"`
}

var (
	privateFlag = &cli.BoolFlag{
		Name:  "private",
		Usage: "include the key seed in the output",
	}
)

var commandInspect = &cli.Command{
	Name:      "inspect",
	Usage:     "inspect a keyfile",
	ArgsUsage: "<keyfile>",
	Description: `
Print various information about the keyfile of an ML-DSA-44 account key.

The key seed can be printed by using the --private flag;
make sure to use this feature with great caution!`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		privateFlag,
	},
	Action: func(ctx *cli.Context) error {
		keyfilepath := ctx.Args().First()

		// Read key from file.
		keyjson, err := os.ReadFile(keyfilepath)
		if err != nil {
			utils.Fatalf("Failed to read the keyfile at '%s': %v", keyfilepath, err)
		}

		// Decrypt key with passphrase.
		passphrase := getPassphrase(ctx, false)
		key, err := keystore.DecryptKey(keyjson, passphrase)
		if err != nil {
			utils.Fatalf("Error decrypting key: %v", err)
		}

		// Output all relevant information we can retrieve.
		showPrivate := ctx.Bool(privateFlag.Name)
		out := outputInspect{
			Address:   key.Address.Hex(),
			Scheme:    fmt.Sprintf("%#04x", keystore.KeyScheme),
			PublicKey: hex.EncodeToString(key.PublicKey()),
		}
		if showPrivate {
			out.Seed = hex.EncodeToString(key.Seed[:])
		}
		clear(key.Seed[:])

		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:       ", out.Address)
			fmt.Println("Scheme:        ", out.Scheme)
			fmt.Println("Public key:    ", out.PublicKey)
			if showPrivate {
				fmt.Println("Key seed:      ", out.Seed)
			}
		}
		return nil
	},
}
