package slhdsa

// WOTS+ (Winternitz One-Time Signature Plus) implementation
// as specified in FIPS 205.

// wotsChain applies the chaining function F iteratively.
// It hashes the input 'steps' times starting from position 'start'.
// FIPS 205 Algorithm 5: chain
func (pk *PublicKey) wotsChain(inout []byte, start, steps byte, addr address) {
	for i := start; i < start+steps; i++ {
		addr.setHashAddress(uint32(i))
		pk.h.f(pk, addr, inout, inout)
	}
}

// wotsPkGen generates a WOTS+ public key.
// FIPS 205 Algorithm 6: wots_pkGen
func (sk *PrivateKey) wotsPkGen(out, tmpBuf []byte, addr address) {
	// Create PRF address
	skAddr := sk.newAddr()
	skAddr.clone(addr)
	skAddr.setTypeAndClear(adrsWOTSPRF)
	skAddr.copyKeyPairAddress(addr)

	tmp := tmpBuf
	// Compute all chain endpoints
	for i := range sk.params.len {
		// Generate secret key for chain i
		skAddr.setChainAddress(i)
		sk.h.prf(sk, skAddr, tmp)

		// Compute public value (chain to end)
		addr.setChainAddress(i)
		sk.wotsChain(tmp, 0, 15, addr) // w=16, so chain 15 steps
		tmp = tmp[sk.params.n:]
	}

	// Compress to get public key
	pkAddr := sk.newAddr()
	pkAddr.clone(addr)
	pkAddr.setTypeAndClear(adrsWOTSPK)
	pkAddr.copyKeyPairAddress(addr)
	sk.h.t(&sk.PublicKey, pkAddr, tmpBuf, out)
}

// wotsSign generates a WOTS+ signature on an n-byte message.
// FIPS 205 Algorithm 7: wots_sign
func (sk *PrivateKey) wotsSign(msg []byte, addr address, sig []byte) {
	var msgAndCsum [maxWotsLen]byte

	// Convert message to base w=16 (nibbles)
	bytes2nibbles(msg, msgAndCsum[:])

	// Compute checksum
	len1 := sk.params.n * 2
	var csum uint16
	for i := range len1 {
		csum += uint16(msgAndCsum[i])
	}
	csum = uint16(15*len1) - csum

	// Append checksum in base 16
	msgAndCsum[len1] = byte(csum>>8) & 0x0F
	msgAndCsum[len1+1] = byte(csum>>4) & 0x0F
	msgAndCsum[len1+2] = byte(csum) & 0x0F

	// Create PRF address
	skAddr := sk.newAddr()
	skAddr.clone(addr)
	skAddr.setTypeAndClear(adrsWOTSPRF)
	skAddr.copyKeyPairAddress(addr)

	// Generate signature chains
	for i := range sk.params.len {
		skAddr.setChainAddress(i)
		sk.h.prf(sk, skAddr, sig)
		addr.setChainAddress(i)
		sk.wotsChain(sig, 0, msgAndCsum[i], addr)
		sig = sig[sk.params.n:]
	}
}

// wotsPkFromSig computes a WOTS+ public key from a signature.
// FIPS 205 Algorithm 8: wots_pkFromSig
func (pk *PublicKey) wotsPkFromSig(sig, msg, tmpBuf []byte, addr address, out []byte) {
	var msgAndCsum [maxWotsLen]byte

	// Convert message to base w=16 (nibbles)
	bytes2nibbles(msg, msgAndCsum[:])

	// Compute checksum
	len1 := pk.params.n * 2
	var csum uint16
	for i := range len1 {
		csum += uint16(msgAndCsum[i])
	}
	csum = uint16(15*len1) - csum

	// Append checksum in base 16
	msgAndCsum[len1] = byte(csum>>8) & 0x0F
	msgAndCsum[len1+1] = byte(csum>>4) & 0x0F
	msgAndCsum[len1+2] = byte(csum) & 0x0F

	// Complete the chains from signature values
	copy(tmpBuf, sig)
	tmp := tmpBuf
	for i := range pk.params.len {
		addr.setChainAddress(i)
		pk.wotsChain(tmp, msgAndCsum[i], 15-msgAndCsum[i], addr)
		tmp = tmp[pk.params.n:]
	}

	// Compress to get public key
	pkAddr := pk.newAddr()
	pkAddr.clone(addr)
	pkAddr.setTypeAndClear(adrsWOTSPK)
	pkAddr.copyKeyPairAddress(addr)
	pk.h.t(pk, pkAddr, tmpBuf, out)
}

// bytes2nibbles converts bytes to nibbles (base 16)
func bytes2nibbles(in, out []byte) {
	for i := range in {
		out[i*2] = in[i] >> 4
		out[i*2+1] = in[i] & 0x0F
	}
}
