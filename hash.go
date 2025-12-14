package slhdsa

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"hash"
)

// hashFunc defines the hash function interface used in SLH-DSA.
// Different implementations exist for SHAKE and SHA2 variants.
type hashFunc interface {
	// f is the tweakable hash function F
	f(pk *PublicKey, addr address, m1, out []byte)
	// h is the tweakable hash function H (takes two n-byte inputs)
	h(pk *PublicKey, addr address, m1, m2, out []byte)
	// t is the tweakable hash function T_l (takes arbitrary length input)
	t(pk *PublicKey, addr address, ml, out []byte)
	// hMsg computes the message hash H_msg
	hMsg(pk *PublicKey, R, mPrefix, M, out []byte)
	// prf is the PRF for key generation
	prf(sk *PrivateKey, addr address, out []byte)
	// prfMsg is the PRF for randomizer generation
	prfMsg(sk *PrivateKey, optRand, mPrefix, m, out []byte)
}

// shakeHash implements hashFunc using SHAKE256
type shakeHash struct{}

func (shakeHash) f(pk *PublicKey, addr address, m1, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(addr.bytes())
	pk.shake.Write(m1[:pk.params.n])
	pk.shake.Read(out[:pk.params.n])
}

func (shakeHash) h(pk *PublicKey, addr address, m1, m2, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(addr.bytes())
	pk.shake.Write(m1[:pk.params.n])
	pk.shake.Write(m2[:pk.params.n])
	pk.shake.Read(out[:pk.params.n])
}

func (shakeHash) t(pk *PublicKey, addr address, ml, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(addr.bytes())
	pk.shake.Write(ml)
	pk.shake.Read(out[:pk.params.n])
}

func (shakeHash) hMsg(pk *PublicKey, R, mPrefix, M, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(R[:pk.params.n])
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(pk.root[:pk.params.n])
	pk.shake.Write(mPrefix)
	pk.shake.Write(M)
	pk.shake.Read(out[:pk.params.m])
}

func (shakeHash) prf(sk *PrivateKey, addr address, out []byte) {
	sk.shake.Reset()
	sk.shake.Write(sk.PublicKey.seed[:sk.params.n])
	sk.shake.Write(addr.bytes())
	sk.shake.Write(sk.seed[:sk.params.n])
	sk.shake.Read(out[:sk.params.n])
}

func (shakeHash) prfMsg(sk *PrivateKey, optRand, mPrefix, m, out []byte) {
	sk.shake.Reset()
	sk.shake.Write(sk.prf[:sk.params.n])
	sk.shake.Write(optRand)
	sk.shake.Write(mPrefix)
	sk.shake.Write(m)
	sk.shake.Read(out[:sk.params.n])
}

// sha2Hash implements hashFunc using SHA-256/SHA-512
type sha2Hash struct{}

func (sha2Hash) f(pk *PublicKey, addr address, m1, out []byte) {
	var zeros [64]byte
	pk.md.Reset()
	pk.md.Write(pk.seed[:pk.params.n])
	pk.md.Write(zeros[:64-pk.params.n])
	pk.md.Write(addr.bytes())
	pk.md.Write(m1[:pk.params.n])
	pk.md.Sum(zeros[:0])
	copy(out, zeros[:pk.params.n])
}

func (sha2Hash) h(pk *PublicKey, addr address, m1, m2, out []byte) {
	var zeros [128]byte
	pk.mdBig.Reset()
	pk.mdBig.Write(pk.seed[:pk.params.n])
	pk.mdBig.Write(zeros[:uint32(pk.mdBig.BlockSize())-pk.params.n])
	pk.mdBig.Write(addr.bytes())
	pk.mdBig.Write(m1[:pk.params.n])
	pk.mdBig.Write(m2[:pk.params.n])
	pk.mdBig.Sum(zeros[:0])
	copy(out, zeros[:pk.params.n])
}

func (sha2Hash) t(pk *PublicKey, addr address, ml, out []byte) {
	var zeros [128]byte
	pk.mdBig.Reset()
	pk.mdBig.Write(pk.seed[:pk.params.n])
	pk.mdBig.Write(zeros[:uint32(pk.mdBig.BlockSize())-pk.params.n])
	pk.mdBig.Write(addr.bytes())
	pk.mdBig.Write(ml)
	pk.mdBig.Sum(zeros[:0])
	copy(out, zeros[:pk.params.n])
}

func (sha2Hash) hMsg(pk *PublicKey, R, mPrefix, M, out []byte) {
	var buf [128]byte
	pk.mdBig.Reset()
	pk.mdBig.Write(R[:pk.params.n])
	pk.mdBig.Write(pk.seed[:pk.params.n])
	pk.mdBig.Write(pk.root[:pk.params.n])
	pk.mdBig.Write(mPrefix)
	pk.mdBig.Write(M)
	pk.mdBig.Sum(buf[:0])
	mgf1([][]byte{R[:pk.params.n], pk.seed[:pk.params.n], buf[:pk.mdBig.Size()]}, pk.mdBig, out[:pk.params.m])
}

func (sha2Hash) prf(sk *PrivateKey, addr address, out []byte) {
	var zeros [128]byte
	sk.md.Reset()
	sk.md.Write(sk.PublicKey.seed[:sk.params.n])
	sk.md.Write(zeros[:64-sk.params.n])
	sk.md.Write(addr.bytes())
	sk.md.Write(sk.seed[:sk.params.n])
	sk.md.Sum(zeros[:0])
	copy(out, zeros[:sk.params.n])
}

func (sha2Hash) prfMsg(sk *PrivateKey, optRand, mPrefix, m, out []byte) {
	var buf [128]byte
	mac := hmac.New(sk.mdBigFunc, sk.prf[:sk.params.n])
	mac.Write(optRand)
	mac.Write(mPrefix)
	mac.Write(m)
	mac.Sum(buf[:0])
	copy(out, buf[:sk.params.n])
}

// mgf1 implements MGF1 (Mask Generation Function 1) from PKCS#1
func mgf1(seeds [][]byte, h hash.Hash, out []byte) {
	var counter uint32
	var buf [128]byte
	size := h.Size()
	maskLen := len(out)
	for i := 0; i < maskLen; i += size {
		h.Reset()
		for _, seed := range seeds {
			h.Write(seed)
		}
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		h.Sum(buf[:0])
		copy(out[i:], buf[:size])
		counter++
	}
}

// initKeyHash initializes the hash functions for a key based on parameter set
func initKeyHash(params *Params, pk *PublicKey) {
	if params.isShake {
		pk.shake = sha3.NewSHAKE256()
		pk.h = shakeHash{}
		pk.newAddr = func() address { return &adrs32{} }
	} else {
		pk.md = sha256.New()
		if params.n == 16 {
			pk.mdBig = pk.md
			pk.mdBigFunc = sha256.New
		} else {
			pk.mdBig = sha512.New()
			pk.mdBigFunc = sha512.New
		}
		pk.h = sha2Hash{}
		pk.newAddr = func() address { return &adrs22{} }
	}
}
