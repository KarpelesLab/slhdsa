package slhdsa

import (
	"crypto"
	"errors"
	"io"
)

// Options contains signing options for SLH-DSA.
// It implements crypto.SignerOpts.
type Options struct {
	// Context is an optional domain separation string (max 255 bytes).
	Context []byte
}

// HashFunc returns 0 to indicate that SLH-DSA operates on raw messages.
func (o *Options) HashFunc() crypto.Hash {
	return 0
}

// Sign implements crypto.Signer. It signs the message with the private key.
//
// SLH-DSA does not support pre-hashing, so opts.HashFunc() must be 0.
// Pass nil or &Options{} for default options, or &Options{Context: ctx}
// for domain separation.
//
// If rand is nil, signing is deterministic. If rand is provided, it supplies
// entropy for hedged signing which may help against side-channel attacks.
func (sk *PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("slhdsa: pre-hashed messages not supported")
	}

	var context []byte
	if o, ok := opts.(*Options); ok && o != nil {
		context = o.Context
	}

	var optRand []byte
	if rand != nil {
		optRand = make([]byte, sk.params.n)
		if _, err := io.ReadFull(rand, optRand); err != nil {
			return nil, err
		}
	}

	return sk.sign(message, context, optRand)
}

// SignMessage implements crypto.MessageSigner. It signs the message with the private key.
//
// SLH-DSA does not support pre-hashing, so opts.HashFunc() must be 0.
// Pass nil or &Options{} for default options, or &Options{Context: ctx}
// for domain separation.
//
// If rand is nil, signing is deterministic. If rand is provided, it supplies
// entropy for hedged signing which may help against side-channel attacks.
func (sk *PrivateKey) SignMessage(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return sk.Sign(rand, message, opts)
}

// sign is the internal signing function.
// FIPS 205 Algorithm 22: slh_sign
func (sk *PrivateKey) sign(message, context, rand []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("slhdsa: empty message")
	}
	if len(rand) > 0 && len(rand) != int(sk.params.n) {
		return nil, errors.New("slhdsa: random bytes must be nil or n bytes")
	}
	if len(context) > maxContextLen {
		return nil, errors.New("slhdsa: context too long (max 255 bytes)")
	}

	// Build message prefix: 0x00 || len(ctx) || ctx
	var mPrefix [maxContextLen + 2]byte
	mPrefix[0] = 0x00 // Pure SLH-DSA
	mPrefix[1] = byte(len(context))
	copy(mPrefix[2:], context)

	return sk.signInternal(mPrefix[:2+len(context)], message, rand)
}

// signInternal implements the internal signing algorithm.
// FIPS 205 Algorithm 19: slh_sign_internal
func (sk *PrivateKey) signInternal(mPrefix, message, optRand []byte) ([]byte, error) {
	sig := make([]byte, sk.params.sigSize)

	// Generate randomizer R
	if len(optRand) == 0 {
		// Deterministic: use PK.seed as randomizer
		optRand = sk.PublicKey.seed[:sk.params.n]
	}
	sk.h.prfMsg(sk, optRand, mPrefix, message, sig)

	R := sig[:sk.params.n]
	sigRest := sig[sk.params.n:]

	// Compute message digest
	var digest [maxM]byte
	sk.h.hMsg(&sk.PublicKey, R, mPrefix, message, digest[:])

	// Extract indices from digest
	mdLen := sk.params.mdLen()
	md := digest[:mdLen]

	remaining := digest[mdLen:]
	treeIdxLen := sk.params.treeIdxLen()
	leafIdxLen := sk.params.leafIdxLen()

	treeIdx := toInt(remaining[:treeIdxLen]) & sk.params.treeIdxMask()
	remaining = remaining[treeIdxLen:]
	leafIdx := uint32(toInt(remaining[:leafIdxLen]) & sk.params.leafIdxMask())

	// Sign with FORS
	addr := sk.newAddr()
	addr.setTreeAddress(treeIdx)
	addr.setTypeAndClear(adrsFORSTree)
	addr.setKeyPairAddress(leafIdx)

	sk.forsSign(md, addr, sigRest)

	// Compute FORS public key
	var pkFors [maxN]byte
	sigRest = sk.forsPkFromSig(md, sigRest, addr, pkFors[:])

	// Sign with hypertree
	sk.htSign(pkFors[:sk.params.n], treeIdx, leafIdx, sigRest)

	return sig, nil
}

// Verify verifies an SLH-DSA signature.
//
// The context parameter must match what was used during signing.
//
// FIPS 205 Algorithm 24: slh_verify
func (pk *PublicKey) Verify(signature, message, context []byte) bool {
	if len(message) == 0 {
		return false
	}
	if len(context) > maxContextLen {
		return false
	}
	if len(signature) != pk.params.sigSize {
		return false
	}

	// Build message prefix: 0x00 || len(ctx) || ctx
	var mPrefix [maxContextLen + 2]byte
	mPrefix[0] = 0x00 // Pure SLH-DSA
	mPrefix[1] = byte(len(context))
	copy(mPrefix[2:], context)

	return pk.verifyInternal(signature, mPrefix[:2+len(context)], message)
}

// verifyInternal implements the internal verification algorithm.
// FIPS 205 Algorithm 20: slh_verify_internal
func (pk *PublicKey) verifyInternal(sig, mPrefix, message []byte) bool {
	R := sig[:pk.params.n]
	sigRest := sig[pk.params.n:]

	// Compute message digest
	var digest [maxM]byte
	pk.h.hMsg(pk, R, mPrefix, message, digest[:])

	// Extract indices from digest
	mdLen := pk.params.mdLen()
	md := digest[:mdLen]

	remaining := digest[mdLen:]
	treeIdxLen := pk.params.treeIdxLen()
	leafIdxLen := pk.params.leafIdxLen()

	treeIdx := toInt(remaining[:treeIdxLen]) & pk.params.treeIdxMask()
	remaining = remaining[treeIdxLen:]
	leafIdx := uint32(toInt(remaining[:leafIdxLen]) & pk.params.leafIdxMask())

	// Verify FORS signature
	addr := pk.newAddr()
	addr.setTreeAddress(treeIdx)
	addr.setTypeAndClear(adrsFORSTree)
	addr.setKeyPairAddress(leafIdx)

	var pkFors [maxN]byte
	sigRest = pk.forsPkFromSig(md, sigRest, addr, pkFors[:])

	// Verify hypertree signature
	return pk.htVerify(pkFors[:pk.params.n], sigRest, treeIdx, leafIdx)
}

// toInt converts a big-endian byte slice to uint64
func toInt(b []byte) uint64 {
	var ret uint64
	for _, v := range b {
		ret = ret<<8 | uint64(v)
	}
	return ret
}
