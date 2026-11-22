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

//go:build !ghostrelease

package ghost

// SetTestNetMinDifficultyForTests lowers the public test network's difficulty
// floor, so a test can mine a long test-network chain with real RandomX seals
// in seconds. The genesis is unchanged: its difficulty is the start
// difficulty, and ASERT is at the floor on a chain started long after the
// genesis time. Release builds do not have this function.
func SetTestNetMinDifficultyForTests(d int64) {
	if d < 1 {
		panic("test network difficulty floor below 1")
	}
	testNetMinDifficulty = d
}
