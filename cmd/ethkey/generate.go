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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
)

type outputGenerate struct {
	Address      string
	AddressEIP55 string
}

var (
	seedFlag = &cli.StringFlag{
		Name:  "seed",
		Usage: "file containing a hex encoded 32-byte ML-DSA-44 key seed to encrypt",
	}
	lightKDFFlag = &cli.BoolFlag{
		Name:  "lightkdf",
		Usage: "use less secure scrypt parameters",
	}
)

var commandGenerate = &cli.Command{
	Name:      "generate",
	Usage:     "generate new keyfile",
	ArgsUsage: "[ <keyfile> ]",
	Description: `
Generate a new keyfile of an ML-DSA-44 account key (scheme 0x0001).

If you want to encrypt an existing key seed, it can be specified by setting
--seed with the location of the file containing the 32-byte seed in hex.
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

		var seed [keystore.SeedSize]byte
		defer clear(seed[:])
		if file := ctx.String(seedFlag.Name); file != "" {
			// Load the seed from file.
			content, err := os.ReadFile(file)
			if err != nil {
				utils.Fatalf("Can't load key seed: %v", err)
			}
			loaded, err := hex.DecodeString(strings.TrimSpace(string(content)))
			if err != nil {
				utils.Fatalf("Can't load key seed: %v", err)
			}
			if len(loaded) != keystore.SeedSize {
				utils.Fatalf("Can't load key seed: a key seed is %d bytes, have %d", keystore.SeedSize, len(loaded))
			}
			copy(seed[:], loaded)
			clear(loaded)
		} else if _, err := rand.Read(seed[:]); err != nil {
			// If not loaded, generate random.
			utils.Fatalf("Failed to generate random key seed: %v", err)
		}
		seedCopy := seed
		pub, _ := mldsa44.NewKeyFromSeed(&seedCopy)
		clear(seedCopy[:])

		// Create the keyfile object with a random UUID.
		UUID, err := uuid.NewRandom()
		if err != nil {
			utils.Fatalf("Failed to generate random uuid: %v", err)
		}
		key := &keystore.Key{
			Id:      UUID,
			Address: types.GhostAccountAddressOf(keystore.KeyScheme, pub.Bytes()),
			Seed:    seed,
		}
		defer clear(key.Seed[:])

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
		out := outputGenerate{
			Address: key.Address.Hex(),
		}
		if ctx.Bool(jsonFlag.Name) {
			mustPrintJSON(out)
		} else {
			fmt.Println("Address:", out.Address)
		}
		return nil
	},
}
