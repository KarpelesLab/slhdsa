// Package slhdsa implements the SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
// as specified in FIPS 205.
//
// SLH-DSA is a post-quantum digital signature scheme based on hash functions.
// It provides strong security guarantees against both classical and quantum attacks.
package slhdsa

import "io"

// Internal constants for maximum buffer sizes
const (
	maxN       = 32 // Maximum security parameter (hash output size in bytes)
	maxM       = 49 // Maximum message digest size
	maxK       = 35 // Maximum number of FORS trees
	maxA       = 14 // Maximum height of FORS tree
	maxWotsLen = 67 // Maximum WOTS+ chain length (2*maxN + 3)

	maxContextLen = 255 // Maximum context length for signing
)

// Params defines the parameters for an SLH-DSA instance.
// Use the predefined parameter sets like SHA2_128s, SHA2_128f, etc.
type Params struct {
	name    string
	isShake bool
	n       uint32 // Security parameter (hash output size in bytes): 16, 24, or 32
	h       uint32 // Total tree height: 63, 64, 66, or 68
	d       uint32 // Number of hypertree layers: 7, 8, 17, or 22
	hPrime  uint32 // Height of each XMSS tree (h = hPrime * d)
	a       uint32 // Height of FORS trees
	k       uint32 // Number of FORS trees
	m       uint32 // Message digest size
	w       uint32 // Winternitz parameter (always 16)
	len     uint32 // WOTS+ chain count (2*n + 3)
	sigSize int    // Total signature size in bytes
	pkSize  int    // Public key size in bytes
	skSize  int    // Private key size in bytes
}

// Predefined parameter sets following FIPS 205.
// The naming convention is: HashFunction_SecurityLevel[s|f]
// - s = small signatures (slower signing)
// - f = fast signing (larger signatures)
var (
	// SHA2-based parameter sets
	SHA2_128s = &Params{
		name: "SLH-DSA-SHA2-128s", isShake: false,
		n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, w: 16, len: 35,
		sigSize: 7856, pkSize: 32, skSize: 64,
	}
	SHA2_128f = &Params{
		name: "SLH-DSA-SHA2-128f", isShake: false,
		n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, w: 16, len: 35,
		sigSize: 17088, pkSize: 32, skSize: 64,
	}
	SHA2_192s = &Params{
		name: "SLH-DSA-SHA2-192s", isShake: false,
		n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, w: 16, len: 51,
		sigSize: 16224, pkSize: 48, skSize: 96,
	}
	SHA2_192f = &Params{
		name: "SLH-DSA-SHA2-192f", isShake: false,
		n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, w: 16, len: 51,
		sigSize: 35664, pkSize: 48, skSize: 96,
	}
	SHA2_256s = &Params{
		name: "SLH-DSA-SHA2-256s", isShake: false,
		n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, w: 16, len: 67,
		sigSize: 29792, pkSize: 64, skSize: 128,
	}
	SHA2_256f = &Params{
		name: "SLH-DSA-SHA2-256f", isShake: false,
		n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, w: 16, len: 67,
		sigSize: 49856, pkSize: 64, skSize: 128,
	}

	// SHAKE-based parameter sets
	SHAKE_128s = &Params{
		name: "SLH-DSA-SHAKE-128s", isShake: true,
		n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, w: 16, len: 35,
		sigSize: 7856, pkSize: 32, skSize: 64,
	}
	SHAKE_128f = &Params{
		name: "SLH-DSA-SHAKE-128f", isShake: true,
		n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, w: 16, len: 35,
		sigSize: 17088, pkSize: 32, skSize: 64,
	}
	SHAKE_192s = &Params{
		name: "SLH-DSA-SHAKE-192s", isShake: true,
		n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, w: 16, len: 51,
		sigSize: 16224, pkSize: 48, skSize: 96,
	}
	SHAKE_192f = &Params{
		name: "SLH-DSA-SHAKE-192f", isShake: true,
		n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, w: 16, len: 51,
		sigSize: 35664, pkSize: 48, skSize: 96,
	}
	SHAKE_256s = &Params{
		name: "SLH-DSA-SHAKE-256s", isShake: true,
		n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, w: 16, len: 67,
		sigSize: 29792, pkSize: 64, skSize: 128,
	}
	SHAKE_256f = &Params{
		name: "SLH-DSA-SHAKE-256f", isShake: true,
		n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, w: 16, len: 67,
		sigSize: 49856, pkSize: 64, skSize: 128,
	}
)

// paramsByName maps algorithm names to parameter sets
var paramsByName = map[string]*Params{
	"SLH-DSA-SHA2-128s":  SHA2_128s,
	"SLH-DSA-SHA2-128f":  SHA2_128f,
	"SLH-DSA-SHA2-192s":  SHA2_192s,
	"SLH-DSA-SHA2-192f":  SHA2_192f,
	"SLH-DSA-SHA2-256s":  SHA2_256s,
	"SLH-DSA-SHA2-256f":  SHA2_256f,
	"SLH-DSA-SHAKE-128s": SHAKE_128s,
	"SLH-DSA-SHAKE-128f": SHAKE_128f,
	"SLH-DSA-SHAKE-192s": SHAKE_192s,
	"SLH-DSA-SHAKE-192f": SHAKE_192f,
	"SLH-DSA-SHAKE-256s": SHAKE_256s,
	"SLH-DSA-SHAKE-256f": SHAKE_256f,
}

// ParamsByName returns the parameter set for the given algorithm name.
// Returns nil if the name is not recognized.
func ParamsByName(name string) *Params {
	return paramsByName[name]
}

// String returns the algorithm name.
func (p *Params) String() string {
	return p.name
}

// SignatureSize returns the size of signatures in bytes.
func (p *Params) SignatureSize() int {
	return p.sigSize
}

// PublicKeySize returns the size of public keys in bytes.
func (p *Params) PublicKeySize() int {
	return p.pkSize
}

// PrivateKeySize returns the size of private keys in bytes.
func (p *Params) PrivateKeySize() int {
	return p.skSize
}

// GenerateKey generates a new key pair using the provided random source.
func (p *Params) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	return GenerateKey(rand, p)
}

// mdLen returns the message digest length for FORS
func (p *Params) mdLen() int {
	return int(p.k*p.a+7) >> 3
}

// treeIdxLen returns the byte length needed for tree index
func (p *Params) treeIdxLen() int {
	return int(p.h-p.hPrime+7) >> 3
}

// treeIdxMask returns the bitmask for tree index
func (p *Params) treeIdxMask() uint64 {
	return (1 << (p.h - p.hPrime)) - 1
}

// leafIdxLen returns the byte length needed for leaf index
func (p *Params) leafIdxLen() int {
	return int(p.hPrime+7) >> 3
}

// leafIdxMask returns the bitmask for leaf index
func (p *Params) leafIdxMask() uint64 {
	return (1 << p.hPrime) - 1
}
