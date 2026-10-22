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

//go:build ghosttreetest14

package ghosttree

// releaseDepth is the tree depth of the test build made with the
// ghosttreetest14 build tag: 2^14 = 16,384 leaves per tree, four pages, so a
// test chain can fill a tree and roll over (spec 05, RT-1 Part B). Only the
// build tag selects it; a release build refuses the tag (depth_refuse.go).
const releaseDepth = 14
