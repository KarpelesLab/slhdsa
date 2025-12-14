package slhdsa

// addressType identifies the type of hash address
type addressType byte

const (
	adrsWOTSHash  addressType = iota // WOTS+ hash address
	adrsWOTSPK                       // WOTS+ public key compression
	adrsTree                         // Tree node hashing
	adrsFORSTree                     // FORS tree address
	adrsFORSRoots                    // FORS roots compression
	adrsWOTSPRF                      // WOTS+ PRF key generation
	adrsFORSPRF                      // FORS PRF key generation
)

// address is an interface for hash address operations.
// SLH-DSA uses two address formats:
// - 32-byte format for SHAKE
// - 22-byte compressed format for SHA2
type address interface {
	setLayerAddress(l uint32)
	setTreeAddress(t uint64)
	setTypeAndClear(y addressType)
	setKeyPairAddress(i uint32)
	setChainAddress(i uint32)
	setHashAddress(i uint32)
	setTreeHeight(i uint32)
	setTreeIndex(i uint32)
	getKeyPairAddress() uint32
	getTreeIndex() uint32
	bytes() []byte
	clone(source address)
	copyKeyPairAddress(source address)
}

// adrs32 is the 32-byte address format used with SHAKE
type adrs32 [32]byte

func (a *adrs32) setLayerAddress(l uint32) {
	a[0] = byte(l >> 24)
	a[1] = byte(l >> 16)
	a[2] = byte(l >> 8)
	a[3] = byte(l)
}

func (a *adrs32) setTreeAddress(t uint64) {
	a[8] = byte(t >> 56)
	a[9] = byte(t >> 48)
	a[10] = byte(t >> 40)
	a[11] = byte(t >> 32)
	a[12] = byte(t >> 24)
	a[13] = byte(t >> 16)
	a[14] = byte(t >> 8)
	a[15] = byte(t)
}

func (a *adrs32) setTypeAndClear(y addressType) {
	a[19] = byte(y)
	clear(a[20:])
}

func (a *adrs32) setKeyPairAddress(i uint32) {
	a[20] = byte(i >> 24)
	a[21] = byte(i >> 16)
	a[22] = byte(i >> 8)
	a[23] = byte(i)
}

func (a *adrs32) setChainAddress(i uint32) {
	a[24] = byte(i >> 24)
	a[25] = byte(i >> 16)
	a[26] = byte(i >> 8)
	a[27] = byte(i)
}

func (a *adrs32) setHashAddress(i uint32) {
	a[28] = byte(i >> 24)
	a[29] = byte(i >> 16)
	a[30] = byte(i >> 8)
	a[31] = byte(i)
}

func (a *adrs32) setTreeHeight(i uint32) {
	a.setChainAddress(i)
}

func (a *adrs32) setTreeIndex(i uint32) {
	a.setHashAddress(i)
}

func (a *adrs32) getKeyPairAddress() uint32 {
	return uint32(a[20])<<24 | uint32(a[21])<<16 | uint32(a[22])<<8 | uint32(a[23])
}

func (a *adrs32) getTreeIndex() uint32 {
	return uint32(a[28])<<24 | uint32(a[29])<<16 | uint32(a[30])<<8 | uint32(a[31])
}

func (a *adrs32) bytes() []byte {
	return a[:]
}

func (a *adrs32) clone(b address) {
	copy(a[:], b.bytes())
}

func (a *adrs32) copyKeyPairAddress(b address) {
	copy(a[20:24], b.bytes()[20:24])
}

// adrs22 is the 22-byte compressed address format used with SHA2
type adrs22 [22]byte

func (a *adrs22) setLayerAddress(l uint32) {
	a[0] = byte(l)
}

func (a *adrs22) setTreeAddress(t uint64) {
	a[1] = byte(t >> 56)
	a[2] = byte(t >> 48)
	a[3] = byte(t >> 40)
	a[4] = byte(t >> 32)
	a[5] = byte(t >> 24)
	a[6] = byte(t >> 16)
	a[7] = byte(t >> 8)
	a[8] = byte(t)
}

func (a *adrs22) setTypeAndClear(y addressType) {
	a[9] = byte(y)
	clear(a[10:])
}

func (a *adrs22) setKeyPairAddress(i uint32) {
	a[10] = byte(i >> 24)
	a[11] = byte(i >> 16)
	a[12] = byte(i >> 8)
	a[13] = byte(i)
}

func (a *adrs22) setChainAddress(i uint32) {
	a[14] = byte(i >> 24)
	a[15] = byte(i >> 16)
	a[16] = byte(i >> 8)
	a[17] = byte(i)
}

func (a *adrs22) setHashAddress(i uint32) {
	a[18] = byte(i >> 24)
	a[19] = byte(i >> 16)
	a[20] = byte(i >> 8)
	a[21] = byte(i)
}

func (a *adrs22) setTreeHeight(i uint32) {
	a.setChainAddress(i)
}

func (a *adrs22) setTreeIndex(i uint32) {
	a.setHashAddress(i)
}

func (a *adrs22) getKeyPairAddress() uint32 {
	return uint32(a[10])<<24 | uint32(a[11])<<16 | uint32(a[12])<<8 | uint32(a[13])
}

func (a *adrs22) getTreeIndex() uint32 {
	return uint32(a[18])<<24 | uint32(a[19])<<16 | uint32(a[20])<<8 | uint32(a[21])
}

func (a *adrs22) bytes() []byte {
	return a[:]
}

func (a *adrs22) clone(b address) {
	copy(a[:], b.bytes())
}

func (a *adrs22) copyKeyPairAddress(b address) {
	copy(a[10:14], b.bytes()[10:14])
}
