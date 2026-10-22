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
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/urfave/cli/v2"
)

type outputGenerate struct {
	Address   string
	Scheme    uint16
	PublicKey string
}

var (
	seedFlag = &cli.StringFlag{
		Name:  "seed",
		Usage: "file containing the 32-byte seed (64 hex digits) of the ML-DSA-44 key to encrypt",
	}
	lightKDFFlag = &cli.BoolFlag{
		Name:  "lightkdf",
		Usage: "use less secure scrypt parameters",
	}
)

var commandGenerate = &cli.Command{
	Name:      "generate",
	Usage:     "generate new ML-DSA-44 keyfile",
	ArgsUsage: "[ <keyfile> ]",
	Description: `
Generate a new keyfile holding an ML-DSA-44 account key.

If you want to encrypt an existing key, its 32-byte seed can be specified by
setting --seed with the location of a file containing the seed in hex.
`,
	Flags: []cli.Flag{
		passphraseFlag,
		jsonFlag,
		seedFlag,
		lightKDFFlag,
	},
	Action: func(ctx *cli.Context) error {
		// Check if keyfile path given and make sure it doesn't already exist.
		keyfilepath := ctx.Args().First()
		if keyfilepath == "" {
			keyfilepath = defaultKeyfileName
		}
		if _, err := os.Stat(keyfilepath); err == nil {
			utils.Fatalf("Keyfile already exists at %s.", keyfilepath)
		} else if !os.IsNotExist(err) {
			utils.Fatalf("Error checking if keyfile exists: %v", err)
		}

		var (
			key *keystore.Key
			err error
		)
		if file := ctx.String(seedFlag.Name); file != "" {
			// Load the seed from file.
			seed, err := keystore.LoadSeed(file)
			if err != nil {
				utils.Fatalf("Can't load seed: %v", err)
			}
			key, err = keystore.NewMLDSAKeyFromSeed(seed)
			clear(seed)
			if err != nil {
				utils.Fatalf("Can't derive the key: %v", err)
			}
		} else {
			// If not loaded, generate random.
			key, err = keystore.NewRandomMLDSAKey()
			if err != nil {
				utils.Fatalf("Failed to generate random key: %v", err)
			}
		}
		defer clear(key.Seed)

		// Encrypt key with passphrase.
		passphrase := getPassphrase(ctx, true)
		scryptN, scryptP := keystore.StandardScryptN, keystore.StandardScryptP
		if ctx.Bool(lightKDFFlag.Name) {
			scryptN, scryptP = keystore.LightScryptN, keystore.LightScryptP
		}
		keyjson, err := keystore.EncryptKey(key, passphrase, scryptN, scryptP)
		if err != nil {
			utils.Fatalf("Error encrypting key: %v", err)
		}

		// Store the file to disk.
		if err := os.MkdirAll(filepath.Dir(keyfilepath), 0700); err != nil {
			utils.Fatalf("Could not create directory %s", filepath.Dir(keyfilepath))
		}
		if err := os.WriteFile(keyfilepath, keyjson, 0600); err != nil {
			utils.Fatalf("Failed to write keyfile to %s: %v", keyfilepath, err)
		}

		// Output some information.
		pub, err := key.MLDSAPublicKey()
		if err != nil {
			utils.Fatalf("Failed to derive the public key: %v", err)
		}
		out := outputGenerate{
			Address:   key.Address.Hex(),
			Scheme:    keystore.MLDSAScheme,
			PublicKey: hex.EncodeToString(pub),
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:", out.Address)
			fmt.Println("Scheme:", schemeName(out.Scheme))
			fmt.Println("Public key:", out.PublicKey)
		}
		return nil
	},
}

// schemeName returns the printed name of a key file scheme.
func schemeName(scheme uint16) string {
	if scheme == keystore.MLDSAScheme {
		return fmt.Sprintf("%d (ML-DSA-44)", scheme)
	}
	return fmt.Sprintf("%d", scheme)
}
