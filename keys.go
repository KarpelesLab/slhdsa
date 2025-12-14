package slhdsa

import (
	"crypto"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
)

// Compile-time interface check
var _ crypto.Signer = (*PrivateKey)(nil)

// PublicKey represents an SLH-DSA public key.
type PublicKey struct {
	params *Params
	seed   [maxN]byte // PK.seed
	root   [maxN]byte // PK.root

	// Hash function state (internal, not serialized)
	md        hash.Hash
	mdBig     hash.Hash
	mdBigFunc func() hash.Hash
	shake     *sha3.SHAKE
	h         hashFunc
	newAddr   func() address
}

// PrivateKey represents an SLH-DSA private key.
type PrivateKey struct {
	PublicKey
	seed [maxN]byte // SK.seed
	prf  [maxN]byte // SK.prf
}

// Params returns the parameter set used by this key.
func (pk *PublicKey) Params() *Params {
	return pk.params
}

// Bytes returns the serialized public key (PK.seed || PK.root).
func (pk *PublicKey) Bytes() []byte {
	out := make([]byte, 2*pk.params.n)
	copy(out, pk.seed[:pk.params.n])
	copy(out[pk.params.n:], pk.root[:pk.params.n])
	return out
}

// Equal reports whether pk and other have the same value.
// It implements the crypto.PublicKey interface.
func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok || pk.params != other.params {
		return false
	}
	return subtle.ConstantTimeCompare(pk.seed[:pk.params.n], other.seed[:pk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(pk.root[:pk.params.n], other.root[:pk.params.n]) == 1
}

// Params returns the parameter set used by this key.
func (sk *PrivateKey) Params() *Params {
	return sk.params
}

// Bytes returns the serialized private key (SK.seed || SK.prf || PK.seed || PK.root).
func (sk *PrivateKey) Bytes() []byte {
	out := make([]byte, 4*sk.params.n)
	copy(out, sk.seed[:sk.params.n])
	copy(out[sk.params.n:], sk.prf[:sk.params.n])
	copy(out[2*sk.params.n:], sk.PublicKey.seed[:sk.params.n])
	copy(out[3*sk.params.n:], sk.root[:sk.params.n])
	return out
}

// Public returns the public key corresponding to this private key.
// It implements the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return &sk.PublicKey
}

// Equal reports whether sk and other have the same value.
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk.params != other.params {
		return false
	}
	return subtle.ConstantTimeCompare(sk.seed[:sk.params.n], other.seed[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.prf[:sk.params.n], other.prf[:sk.params.n]) == 1 &&
		sk.PublicKey.Equal(&other.PublicKey)
}

// GenerateKey generates a new SLH-DSA key pair.
func GenerateKey(rand io.Reader, params *Params) (*PrivateKey, error) {
	if params == nil {
		return nil, errors.New("slhdsa: nil params")
	}

	sk := &PrivateKey{}
	sk.params = params
	initKeyHash(params, &sk.PublicKey)

	// Read random seeds
	if _, err := io.ReadFull(rand, sk.seed[:params.n]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, sk.prf[:params.n]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, sk.PublicKey.seed[:params.n]); err != nil {
		return nil, err
	}

	// Compute root
	computeRoot(sk)
	return sk, nil
}

// NewPrivateKey parses a serialized private key.
// The key bytes must be: SK.seed || SK.prf || PK.seed || PK.root
func NewPrivateKey(params *Params, keyBytes []byte) (*PrivateKey, error) {
	if params == nil {
		return nil, errors.New("slhdsa: nil params")
	}
	if len(keyBytes) != int(4*params.n) {
		return nil, errors.New("slhdsa: invalid private key length")
	}

	sk := &PrivateKey{}
	sk.params = params
	initKeyHash(params, &sk.PublicKey)

	copy(sk.seed[:], keyBytes[:params.n])
	copy(sk.prf[:], keyBytes[params.n:2*params.n])
	copy(sk.PublicKey.seed[:], keyBytes[2*params.n:3*params.n])

	// Compute and verify root
	computeRoot(sk)

	if subtle.ConstantTimeCompare(sk.root[:params.n], keyBytes[3*params.n:]) != 1 {
		return nil, errors.New("slhdsa: invalid private key (root mismatch)")
	}

	return sk, nil
}

// NewPublicKey parses a serialized public key.
// The key bytes must be: PK.seed || PK.root
func NewPublicKey(params *Params, keyBytes []byte) (*PublicKey, error) {
	if params == nil {
		return nil, errors.New("slhdsa: nil params")
	}
	if len(keyBytes) != int(2*params.n) {
		return nil, errors.New("slhdsa: invalid public key length")
	}

	pk := &PublicKey{}
	pk.params = params
	initKeyHash(params, pk)

	copy(pk.seed[:], keyBytes[:params.n])
	copy(pk.root[:], keyBytes[params.n:])

	return pk, nil
}

// computeRoot computes the root of the top XMSS tree
func computeRoot(sk *PrivateKey) {
	addr := sk.newAddr()
	addr.setLayerAddress(sk.params.d - 1)
	tmpBuf := make([]byte, sk.params.n*sk.params.len)
	sk.xmssNode(sk.root[:], tmpBuf, 0, sk.params.hPrime, addr)
}
