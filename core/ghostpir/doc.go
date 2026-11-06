// Package ghostpir is the single-server lattice PIR scheme that serves wallet
// restore reads: a wallet fetches one record of a public database (a note, a
// coin-tree witness record, a lookup or marker leaf with its witness) and the
// server, which holds the whole database, learns nothing about which record.
//
// # The scheme: GhostPIR-RLWE-2048
//
// The scheme is a ring-LWE form of the one-hot matrix-vector PIR. Its ring is
// R_q = Z_q[X]/(X^2048 + 1) with q = 2^50 - 16383, the largest prime below
// 2^50 with q = 1 mod 4096, so that products are computed with the negacyclic
// number-theoretic transform. The plaintext modulus is p = 2^16: every ring
// element of the database carries 2,048 coefficients of 16 bits, 4,096 bytes
// (one cell).
//
// The database is a grid of cells with Rows rows and Cols columns, laid out
// column by column. Record i sits at a fixed cell (or, for a record larger
// than a cell, at a fixed run of cells inside one column), so its column is a
// public function of i.
//
// Every snapshot has a public 32-byte seed (the snapshot's identity). From
// the seed alone anyone expands one uniform ring element a_j per column,
// AES-256-CTR keyed with SHA-256 of a domain label and the seed. No key or
// permission is needed to build or serve a database: any full node holding
// the same public data derives the same database and the same a_j.
//
// A query for record i in column c is, for every column j,
//
//	b_j = a_j * s + e_j + Delta * [j == c]
//
// with a fresh secret s per query, uniform ternary (coefficients in
// {-1, 0, 1}), errors e_j with centred binomial coefficients (eta = 21,
// standard deviation 3.24) and Delta = floor(q / p). The client sends the
// b_j only, in NTT form; the a_j are public. The query is a set of Cols
// ring-LWE samples under one secret and is indistinguishable from uniform,
// so the server's view (the query bytes, the answer it computes, the size
// of both and its logs) is the same for every index.
//
// The server answers every row r with the ring-LWE ciphertext
//
//	(H_r, A_r) = sum_j D[r][j] * (a_j, b_j)
//
// The hint H_r = sum_j D[r][j] * a_j does not depend on the query; it is
// computed once per snapshot (the preprocessing of a rebuild). Per query the
// server computes A_r only: Rows * Cols pointwise products in NTT form and
// Rows inverse transforms. Both parts are switched from q down to
// q' = 2^28 before they are sent. The client computes A_r - H_r * s for the
// rows of its record, which is Delta' * D[r][c] plus a small error, and
// rounds to recover the record.
//
// # Security level
//
// The lattice parameters are those of the HomomorphicEncryption.org security
// standard (Albrecht et al., 2018, table for a uniform ternary secret and
// error of standard deviation about 3.2): ring dimension 2,048 is rated at 128
// bits against classical attacks up to log2 q = 54 and at 128 bits against
// quantum attacks up to log2 q = 51. Our q is below 2^50, under both bounds,
// so the query meets 128 classical bits and NIST post-quantum security
// Category 1 (as hard to break as a search for an AES-128 key). The answer is
// computed from the query and public data only and carries no further secret.
//
// # Correctness
//
// With centred plaintext coefficients the error of a decrypted coefficient
// has standard deviation about 2^16 * 3.24 * sqrt(2048 * Cols / 12) before the
// modulus switch. The grid is shaped with at most MaxCols columns, which
// keeps that error, after the switch and its rounding, under a quarter of
// Delta' = 2^12 at about twelve standard deviations, against the half of
// Delta' that decoding tolerates: a coefficient decodes wrong with
// probability far below 2^-60.
package ghostpir
