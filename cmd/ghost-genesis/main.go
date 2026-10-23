// Copyright 2026 The Ghost Authors
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

// Command ghost-genesis derives the Ghost genesis block from the genesis
// Bitcoin-block rule (spec 06, section 8).
//
//	ghost-genesis derive -tl <unix seconds> -headers <file>
//
// The header file holds raw 80-byte Bitcoin block headers, each linked to an
// earlier one except the first, possibly on competing branches. The command
// checks the header chain (links, proof of work against each header's bits,
// timestamps above the median time past), reads the branch with the most
// work, selects the first block whose median time past is at or above T_L,
// requires it to be Confirmations deep, and prints the selected block, the
// genesis hash and the genesis block's RLP bytes. When the headers do not
// settle the choice it refuses and prints why. It reads only the file.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

var errUsage = errors.New("usage: ghost-genesis derive -tl <unix seconds> -headers <file>")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ghost-genesis:", err)
		os.Exit(1)
	}
}

// run runs the command with its arguments, without the program name.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "derive" {
		return errUsage
	}
	fs := flag.NewFlagSet("derive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tl := fs.Uint64("tl", 0, "T_L, in Unix seconds")
	path := fs.String("headers", "", "file of raw 80-byte Bitcoin block headers, in order")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *tl == 0 || *path == "" {
		return errUsage
	}
	headers, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	d, err := Derive(*tl, headers)
	if err != nil {
		return err
	}
	enc, err := d.Encoded()
	if err != nil {
		return err
	}
	bitcoin := Display(d.BitcoinHash)
	_, err = fmt.Fprintf(stdout, "bitcoin-block %x\nbitcoin-height %d\nconfirmations %d\nmedian-time-past %d\ngenesis-hash %x\ngenesis-block %x\n",
		bitcoin, d.BitcoinHeight, d.Confirmations, d.MedianTime, d.Block.Hash(), enc)
	return err
}
