# Quantum-safe peer transport

Package `p2p/qsconn` is the node's quantum-safe peer transport: the node
identity, the hybrid handshake and the encrypted frames of spec 09 of the
Ghost repository, section 10 (`docs/spec/09-quantum-safe-accounts.md`). This
document describes the package as built; the spec is the authority on the
format. The package stands on its own here: the peer-to-peer layer of the
node does not use it yet.

There is one identity scheme, one key exchange and one frame cipher. Nothing
is negotiated, and the package has no other handshake to fall back to. Any
input that does not parse exactly, any unknown scheme, any wrong length and
any failed check closes the connection.

## Hashes

| Name | Definition |
|---|---|
| `K(tag, parts...)` | Keccak-256 over one byte holding the tag's length, the ASCII tag and the parts in order |
| `S(tag, parts...)` | SHA3-256 over one byte holding the tag's length, the ASCII tag and the parts in order |
| `SHAKE256(x, n)` | the first `n` bytes of SHAKE256 over `x` |

## Node identity

| | |
|---|---|
| Scheme | `0x0001`, ML-DSA-44 (FIPS 204, pure mode), `github.com/cloudflare/circl` v1.6.1, package `sign/mldsa/mldsa44` |
| Public key | 1,312 bytes |
| Signature | 2,420 bytes, hedged |
| Node ID | `K("ghost/node-id/v1", scheme, public_key)`, 32 bytes, the scheme as 2 bytes big-endian |

`GenerateIdentity` makes a key pair from the system's random source.
`Identity.Save` writes the 2,560-byte private key, hex encoded and with no
line ending, to a temporary file of mode `0600` in the same directory and
renames it over the target, so a replaced file never keeps a wider mode.
`LoadIdentity` refuses a file that is not a regular file, that its group or
others may read or write (on systems other than Windows), that is not
exactly 5,120 hex characters, or whose key does not encode back to the same
bytes.

## Handshake

The dialling side is the initiator and knows the node ID it dialled. The
whole handshake runs under `Config.HandshakeTimeout` (default 5 seconds);
when it passes, the connection is closed.

Each key exchange message is a 4-byte big-endian length followed by the
body. The length must equal the body size below exactly, and it is checked
before the body is read.

| # | From | Body | Body size |
|---|---|---|---|
| 1 | initiator | ephemeral X25519 public key (32) `xi`, ML-KEM-768 encapsulation key (1,184) `ek` | 1,216 |
| 2 | responder | ephemeral X25519 public key (32) `xr`, ML-KEM-768 ciphertext (1,088) `ct` | 1,120 |

The responder refuses an encapsulation key that the standard library's
`crypto/mlkem` does not accept. Either side refuses an X25519 exchange whose
shared secret is all zeros. X25519 is `crypto/ecdh`.

Both sides then compute:

```
transcript_hash = S("ghost/p2p-transcript/v1", xi, ek, xr, ct)
k               = S("ghost/p2p-kex/v1", ss_mlkem, ss_x25519, transcript_hash)
keys            = SHAKE256(k, 64)
key_i2r         = keys[0:32]    initiator to responder
key_r2i         = keys[32:64]   responder to initiator
```

Changing either shared secret changes both keys
(`TestHybridKeysNeedBothSharedSecrets`).

Under those keys, each side sends one authentication record (the record
format is that of a frame below, without the message code):

| Field | Size |
|---|---|
| scheme | 2, big-endian, must be `0x0001` |
| public key | 1,312 |
| ML-DSA-44 signature over `transcript_hash`, context `ghost/p2p-handshake/v1` | 2,420 |

The plaintext is 3,734 bytes, the record on the wire 3,754 bytes, and any
other announced length is refused. The initiator sends its record first. The
responder checks it before it sends its own, so it shows its identity only
to an authenticated peer. The initiator checks that the responder's public
key hashes to the node ID it dialled before it verifies the signature.

| Step | Wire bytes |
|---|---|
| message 1 | 1,220 |
| message 2 | 1,124 |
| initiator authentication | 3,754 |
| responder authentication | 3,754 |

## Frames

```
frame      = length (4 bytes, big-endian) || ciphertext
ciphertext = ChaCha20-Poly1305(key, nonce, plaintext, associated data = length)
plaintext  = message code (8 bytes, big-endian) || data
nonce      = 4 zero bytes || counter (8 bytes, big-endian)
```

The length counts the ciphertext, the 16-byte tag included. It must lie in
`[24, 24 + Config.MaxMessageSize]` (default maximum 16 MiB of data) and is
checked before the ciphertext is read. ChaCha20-Poly1305 is
`golang.org/x/crypto/chacha20poly1305`.

Each direction has its own key and counter. The counter starts at zero with
the authentication record and goes up by one with every record, so a
modified, replayed, reordered or dropped frame fails to authenticate. After
2^20 records in a direction (`rekeyInterval`), that direction's key becomes
`SHAKE256(old_key, 32)` and its counter starts again at zero.

`Conn.Read` returns the message code, the data and the size on the wire;
`Conn.Write` takes a code and data and returns the size on the wire, and
refuses data above the maximum without writing. `Close`, `SetDeadline`,
`SetReadDeadline` and `SetWriteDeadline` act on the underlying connection.
A frame that fails any check, and any read or write error, closes the
connection; every later `Read` after a failed read, and every later `Write`
after a failed write, returns the same error. A failed handshake fails both.

## Limits

| Limit | Value |
|---|---|
| Handshake timeout | `Config.HandshakeTimeout`, default 5 s |
| Frame data | `Config.MaxMessageSize`, default 16,777,216 bytes |
| Key exchange messages | exactly 1,216 and 1,120 bytes of body |
| Authentication record | exactly 3,750 bytes of ciphertext |
| Rekey | every 2^20 records per direction |
