package ghostpir

// SchemeName names the PIR scheme and its parameter set. A server publishes
// it with every snapshot shape, and a client refuses a shape that names
// another scheme.
const SchemeName = "GhostPIR-RLWE-2048"

const (
	// LogN is log2 of the ring dimension.
	LogN = 11
	// N is the ring dimension: R_q = Z_q[X]/(X^N + 1).
	N = 1 << LogN

	// Q is the ciphertext modulus of queries, 2^50 - 16383: the largest
	// prime below 2^50 with Q = 1 mod 2N.
	Q uint64 = 1<<50 - 16383
	// QBits is the bit width of a coefficient mod Q on the wire.
	QBits = 50

	// PBits is log2 of the plaintext modulus p.
	PBits = 16
	// Delta scales a plaintext into a query: floor(Q / p).
	Delta uint64 = Q >> PBits

	// AnswerBits is log2 of the modulus q' an answer is switched down to.
	AnswerBits = 28
	// answerMask reduces mod q'.
	answerMask = 1<<AnswerBits - 1

	// CellBytes is the plaintext one ring element carries: N coefficients
	// of PBits bits.
	CellBytes = N * PBits / 8

	// MaxCols bounds the columns of a grid, so that the summed error of an
	// answer stays inside the decoding margin (see the package comment).
	MaxCols = 1 << 14
	// MaxRows bounds the rows of a grid, so that a database's answer stays
	// bounded (at most 2 * MaxRows ring elements).
	MaxRows = 1 << 14

	// errorEta is the parameter of the centred binomial error distribution:
	// a coefficient is the difference of the popcounts of two eta-bit
	// strings, variance eta / 2.
	errorEta = 21
)
