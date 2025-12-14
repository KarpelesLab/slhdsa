package slhdsa

// XMSS (eXtended Merkle Signature Scheme) implementation
// as specified in FIPS 205.

// xmssNode computes a node in the XMSS tree.
// FIPS 205 Algorithm 9: xmss_node
func (sk *PrivateKey) xmssNode(out, tmpBuf []byte, i, z uint32, addr address) {
	if z == 0 {
		// Leaf node: compute WOTS+ public key
		addr.setTypeAndClear(adrsWOTSHash)
		addr.setKeyPairAddress(i)
		sk.wotsPkGen(out, tmpBuf, addr)
	} else {
		// Internal node: hash children
		var lnode, rnode [maxN]byte
		sk.xmssNode(lnode[:], tmpBuf, 2*i, z-1, addr)
		sk.xmssNode(rnode[:], tmpBuf, 2*i+1, z-1, addr)

		addr.setTypeAndClear(adrsTree)
		addr.setTreeHeight(z)
		addr.setTreeIndex(i)
		sk.h.h(&sk.PublicKey, addr, lnode[:], rnode[:], out)
	}
}

// xmssSign generates an XMSS signature.
// FIPS 205 Algorithm 10: xmss_sign
func (sk *PrivateKey) xmssSign(msg, tmpBuf []byte, leafIdx uint32, addr address, sig []byte) {
	// Build authentication path
	authStart := sk.params.n * sk.params.len
	authPath := sig[authStart:]
	idx := leafIdx

	for j := range sk.params.hPrime {
		sk.xmssNode(authPath, tmpBuf, idx^1, j, addr)
		authPath = authPath[sk.params.n:]
		idx >>= 1
	}

	// Generate WOTS+ signature
	addr.setTypeAndClear(adrsWOTSHash)
	addr.setKeyPairAddress(leafIdx)
	sk.wotsSign(msg, addr, sig)
}

// xmssPkFromSig computes an XMSS public key from a signature.
// FIPS 205 Algorithm 11: xmss_pkFromSig
func (pk *PublicKey) xmssPkFromSig(leafIdx uint32, sig, msg, tmpBuf []byte, addr address, out []byte) {
	// Compute WOTS+ public key from signature
	addr.setTypeAndClear(adrsWOTSHash)
	addr.setKeyPairAddress(leafIdx)
	pk.wotsPkFromSig(sig, msg, tmpBuf, addr, out)

	// Compute root from authentication path
	addr.setTypeAndClear(adrsTree)
	sig = sig[pk.params.len*pk.params.n:] // Skip to auth path

	for k := range pk.params.hPrime {
		addr.setTreeHeight(k + 1)
		if leafIdx&1 == 0 {
			leafIdx >>= 1
			addr.setTreeIndex(leafIdx)
			pk.h.h(pk, addr, out, sig, out)
		} else {
			leafIdx = (leafIdx - 1) >> 1
			addr.setTreeIndex(leafIdx)
			pk.h.h(pk, addr, sig, out, out)
		}
		sig = sig[pk.params.n:]
	}
}
