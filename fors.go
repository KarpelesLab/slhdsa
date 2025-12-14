package slhdsa

// FORS (Forest of Random Subsets) implementation
// as specified in FIPS 205.

// forsSign generates a FORS signature on a k*a-bit message digest.
// FIPS 205 Algorithm 16: fors_sign
func (sk *PrivateKey) forsSign(md []byte, addr address, sig []byte) {
	var indices [maxK]uint32
	base2b(md, sk.params.a, indices[:sk.params.k])

	twoPowerA := uint32(1 << sk.params.a)
	var treeIDTimesTwoPowerA uint32

	for treeID := range sk.params.k {
		nodeID := indices[treeID]
		sk.forsGenPrivateKey(nodeID+treeIDTimesTwoPowerA, addr, sig)
		sig = sig[sk.params.n:]

		// Compute authentication path
		treeOffset := treeIDTimesTwoPowerA
		for j := range sk.params.a {
			s := nodeID ^ 1
			sk.forsNode(s+treeOffset, j, addr, sig)
			nodeID >>= 1
			treeOffset >>= 1
			sig = sig[sk.params.n:]
		}
		treeIDTimesTwoPowerA += twoPowerA
	}
}

// forsPkFromSig computes a FORS public key from a signature.
// FIPS 205 Algorithm 17: fors_pkFromSig
func (pk *PublicKey) forsPkFromSig(md, sig []byte, addr address, out []byte) []byte {
	var indices [maxK]uint32
	base2b(md, pk.params.a, indices[:pk.params.k])

	twoPowerA := uint32(1 << pk.params.a)

	var treeIDTimesTwoPowerA uint32
	root := make([]byte, pk.params.n*pk.params.k)
	rootPtr := root

	for treeID := range pk.params.k {
		// Compute leaf from signature
		nodeID := indices[treeID]
		treeIdx := nodeID + treeIDTimesTwoPowerA
		addr.setTreeHeight(0)
		addr.setTreeIndex(treeIdx)
		pk.h.f(pk, addr, sig, rootPtr)
		sig = sig[pk.params.n:]

		// Compute root from leaf and authentication path
		for layer := range pk.params.a {
			addr.setTreeHeight(layer + 1)
			if nodeID&1 == 0 {
				treeIdx >>= 1
				addr.setTreeIndex(treeIdx)
				pk.h.h(pk, addr, rootPtr, sig, rootPtr)
			} else {
				treeIdx = (treeIdx - 1) >> 1
				addr.setTreeIndex(treeIdx)
				pk.h.h(pk, addr, sig, rootPtr, rootPtr)
			}
			sig = sig[pk.params.n:]
			nodeID >>= 1
		}
		treeIDTimesTwoPowerA += twoPowerA
		rootPtr = rootPtr[pk.params.n:]
	}

	// Compress roots to get FORS public key
	forsPkAddr := pk.newAddr()
	forsPkAddr.clone(addr)
	forsPkAddr.setTypeAndClear(adrsFORSRoots)
	forsPkAddr.copyKeyPairAddress(addr)
	pk.h.t(pk, forsPkAddr, root, out)

	return sig
}

// forsNode computes a node in a FORS tree.
// FIPS 205 Algorithm 15: fors_node
func (sk *PrivateKey) forsNode(nodeID, layer uint32, addr address, out []byte) {
	if layer == 0 {
		// Leaf: hash private key value
		sk.forsGenPrivateKey(nodeID, addr, out)
		addr.setTreeHeight(0)
		addr.setTreeIndex(nodeID)
		sk.h.f(&sk.PublicKey, addr, out, out)
	} else {
		// Internal node: hash children
		var lnode, rnode [maxN]byte
		sk.forsNode(nodeID*2, layer-1, addr, lnode[:])
		sk.forsNode(nodeID*2+1, layer-1, addr, rnode[:])

		addr.setTreeHeight(layer)
		addr.setTreeIndex(nodeID)
		sk.h.h(&sk.PublicKey, addr, lnode[:], rnode[:], out)
	}
}

// forsGenPrivateKey generates a FORS private key value.
// FIPS 205 Algorithm 14: fors_skGen
func (sk *PrivateKey) forsGenPrivateKey(idx uint32, addr address, out []byte) {
	skAddr := sk.newAddr()
	skAddr.clone(addr)
	skAddr.setTypeAndClear(adrsFORSPRF)
	skAddr.copyKeyPairAddress(addr)
	skAddr.setTreeIndex(idx)
	sk.h.prf(sk, skAddr, out)
}

// base2b converts a byte array to base 2^b representation.
// FIPS 205 Algorithm 4: base_2^b
func base2b(in []byte, b uint32, out []uint32) {
	var bits, total uint32
	mask := uint32(1<<b - 1)
	idx := 0

	for i := range out {
		for bits < b {
			total = (total << 8) | uint32(in[idx])
			idx++
			bits += 8
		}
		bits -= b
		out[i] = (total >> bits) & mask
	}
}
