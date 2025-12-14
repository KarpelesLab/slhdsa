package slhdsa

import "crypto/subtle"

// Hypertree implementation as specified in FIPS 205.
// A hypertree is a tree of XMSS trees used to sign FORS public keys.

// htSign generates a hypertree signature.
// FIPS 205 Algorithm 12: ht_sign
func (sk *PrivateKey) htSign(pkFors []byte, treeIdx uint64, leafIdx uint32, sig []byte) {
	addr := sk.newAddr()

	sigLenPerLayer := (sk.params.hPrime + sk.params.len) * sk.params.n
	mask := sk.params.leafIdxMask()

	var rootBuf [maxN]byte
	root := rootBuf[:sk.params.n]
	copy(root, pkFors)

	tmpBuf := make([]byte, sk.params.n*sk.params.len)

	for j := range sk.params.d {
		addr.setLayerAddress(j)
		addr.setTreeAddress(treeIdx)
		sk.xmssSign(root, tmpBuf, leafIdx, addr, sig)

		if j < sk.params.d-1 {
			sk.xmssPkFromSig(leafIdx, sig, root, tmpBuf, addr, root)
			leafIdx = uint32(treeIdx & mask)
			treeIdx >>= sk.params.hPrime
			sig = sig[sigLenPerLayer:]
		}
	}
}

// htVerify verifies a hypertree signature.
// FIPS 205 Algorithm 13: ht_verify
func (pk *PublicKey) htVerify(pkFors []byte, sig []byte, treeIdx uint64, leafIdx uint32) bool {
	addr := pk.newAddr()

	sigLenPerLayer := (pk.params.hPrime + pk.params.len) * pk.params.n
	mask := pk.params.leafIdxMask()

	var rootBuf [maxN]byte
	root := rootBuf[:pk.params.n]
	copy(root, pkFors)

	tmpBuf := make([]byte, pk.params.n*pk.params.len)

	for j := range pk.params.d {
		addr.setLayerAddress(j)
		addr.setTreeAddress(treeIdx)
		pk.xmssPkFromSig(leafIdx, sig, root, tmpBuf, addr, root)

		leafIdx = uint32(treeIdx & mask)
		treeIdx >>= pk.params.hPrime
		sig = sig[sigLenPerLayer:]
	}

	return subtle.ConstantTimeCompare(pk.root[:pk.params.n], root) == 1
}
