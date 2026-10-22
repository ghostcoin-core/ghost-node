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
	Scheme    uint16
	PublicKey string
	Seed      string `json:",omitempty"`
}

var (
	privateFlag = &cli.BoolFlag{
		Name:  "private",
		Usage: "include the secret seed of the key in the output",
	}
)

var commandInspect = &cli.Command{
	Name:      "inspect",
	Usage:     "inspect an ML-DSA-44 keyfile",
	ArgsUsage: "<keyfile>",
	Description: `
Print the address, scheme and public key of an ML-DSA-44 keyfile.

The secret seed of the key can be printed by using the --private flag;
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
		defer clear(key.Seed)
		pub, err := key.MLDSAPublicKey()
		if err != nil {
			utils.Fatalf("Failed to derive the public key: %v", err)
		}

		// Output all relevant information we can retrieve.
		showPrivate := ctx.Bool(privateFlag.Name)
		out := outputInspect{
			Address:   key.Address.Hex(),
			Scheme:    keystore.MLDSAScheme,
			PublicKey: hex.EncodeToString(pub),
		}
		if showPrivate {
			out.Seed = hex.EncodeToString(key.Seed)
		}

		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:       ", out.Address)
			fmt.Println("Scheme:        ", schemeName(out.Scheme))
			fmt.Println("Public key:    ", out.PublicKey)
			if showPrivate {
				fmt.Println("Seed:          ", out.Seed)
			}
		}
		return nil
	},
}
