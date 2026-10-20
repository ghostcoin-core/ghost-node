"""Checks the sender vectors of the account transaction (type 0x52).

The expected values in TestGhostAccountTxSenderVectors
(core/types/tx_ghost_account_test.go) must come from an implementation
independent of the node (spec 09, property QS-5). This file is that
implementation: Keccak-256 with the original padding, written here from the
Keccak reference, and the tagged hash K of spec 01 section 2. It recomputes
every vector and compares it with the constant in the Go test.

Run: python3 -m unittest scripts/test_ghost_account_vectors.py
"""

import os
import re
import unittest

_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

_MASK = (1 << 64) - 1


def _rotl(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(a):
    """Keccak-f[1600] on a 5x5 state of 64-bit lanes, a[x][y]."""
    for rc in _ROUND_CONSTANTS:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROTATIONS[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    """Keccak-256 with the original padding (0x01 ... 0x80), not SHA3-256."""
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0x00)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            a[i % 5][i // 5] ^= lane
        a = _keccak_f(a)
    out = bytearray()
    for i in range(4):
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


def tagged(tag, *parts):
    """K of spec 01: one length byte, the ASCII tag, then the parts."""
    raw = tag.encode("ascii")
    return keccak256(bytes([len(raw)]) + raw + b"".join(parts))


def sender(scheme, public_key):
    return tagged("ghost/account-address/v1", scheme.to_bytes(2, "big"), public_key)[:20]


def sighash(genesis, unsigned_hash):
    return tagged("ghost/account-tx/v1", bytes([0x52]), genesis, unsigned_hash)


# The inputs of the vectors, the same as in the Go test.
SENDER_INPUTS = {
    "mldsa44-counting": (0x0001, bytes(i % 256 for i in range(1312))),
    "mldsa44-zero": (0x0001, bytes(1312)),
    "mldsa44-ones": (0x0001, bytes([0xFF]) * 1312),
    "scheme2-counting": (0x0002, bytes(range(32))),
}
SIGHASH_INPUTS = {
    "sighash-11-22": (bytes([0x11]) * 32, bytes([0x22]) * 32),
}

GO_TEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core", "types",
                       "tx_ghost_account_test.go")


def go_vectors():
    """The name and expected hex of every vector in the Go test."""
    with open(GO_TEST, encoding="utf-8") as f:
        text = f.read()
    return dict(re.findall(r'\{"([a-z0-9-]+)",[^\n]*"(0x[0-9a-f]+)"\}', text))


class KeccakTest(unittest.TestCase):
    def test_known_answers(self):
        # The Keccak-256 of the empty string and of "abc", as published.
        self.assertEqual(keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")


class VectorTest(unittest.TestCase):
    def test_go_constants_match(self):
        computed = {}
        for name, (scheme, pk) in SENDER_INPUTS.items():
            computed[name] = "0x" + sender(scheme, pk).hex()
        for name, (genesis, unsigned) in SIGHASH_INPUTS.items():
            computed[name] = "0x" + sighash(genesis, unsigned).hex()
        self.assertEqual(go_vectors(), computed)


if __name__ == "__main__":
    unittest.main()
