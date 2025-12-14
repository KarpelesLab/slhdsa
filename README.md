# slhdsa

A simple, dependency-free Go implementation of **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm) as specified in [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

SLH-DSA is a post-quantum digital signature scheme, designed to be secure against attacks by quantum computers.

## Goals

- **Zero external dependencies** - Uses only Go 1.24+ standard library
- **Simple API** - Just `GenerateKey`, `Sign`, and `Verify`
- **Easy to read** - Clean, straightforward implementation
- **FIPS 205 compliant** - Validated against official NIST test vectors

## Installation

```bash
go get github.com/KarpelesLab/slhdsa
```

Requires Go 1.24 or later.

## Usage

```go
package main

import (
	"crypto/rand"
	"fmt"

	"github.com/KarpelesLab/slhdsa"
)

func main() {
	// Generate a key pair
	sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		panic(err)
	}

	// Sign a message (implements crypto.Signer)
	message := []byte("Hello, post-quantum world!")
	signature, err := sk.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}

	// Verify the signature
	pk := sk.Public().(*slhdsa.PublicKey)
	valid := pk.Verify(signature, message, nil)
	fmt.Println("Signature valid:", valid)
}
```

## Parameter Sets

All 12 FIPS 205 parameter sets are supported:

| Parameter Set | Security | Signature Size | Public Key | Private Key |
|---------------|----------|----------------|------------|-------------|
| `SHA2_128s`   | 128-bit  | 7,856 bytes    | 32 bytes   | 64 bytes    |
| `SHA2_128f`   | 128-bit  | 17,088 bytes   | 32 bytes   | 64 bytes    |
| `SHA2_192s`   | 192-bit  | 16,224 bytes   | 48 bytes   | 96 bytes    |
| `SHA2_192f`   | 192-bit  | 35,664 bytes   | 48 bytes   | 96 bytes    |
| `SHA2_256s`   | 256-bit  | 29,792 bytes   | 64 bytes   | 128 bytes   |
| `SHA2_256f`   | 256-bit  | 49,856 bytes   | 64 bytes   | 128 bytes   |
| `SHAKE_128s`  | 128-bit  | 7,856 bytes    | 32 bytes   | 64 bytes    |
| `SHAKE_128f`  | 128-bit  | 17,088 bytes   | 32 bytes   | 64 bytes    |
| `SHAKE_192s`  | 192-bit  | 16,224 bytes   | 48 bytes   | 96 bytes    |
| `SHAKE_192f`  | 192-bit  | 35,664 bytes   | 48 bytes   | 96 bytes    |
| `SHAKE_256s`  | 256-bit  | 29,792 bytes   | 64 bytes   | 128 bytes   |
| `SHAKE_256f`  | 256-bit  | 49,856 bytes   | 64 bytes   | 128 bytes   |

The `s` variants are slower but produce smaller signatures. The `f` variants are faster but produce larger signatures.

## API

The `PrivateKey` type implements `crypto.Signer` and `crypto.MessageSigner` (Go 1.25+).

### Key Generation

```go
sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
```

### Signing

```go
// Basic signing (deterministic) - implements crypto.Signer
sig, err := sk.Sign(nil, message, nil)

// With context (for domain separation)
sig, err := sk.Sign(nil, message, &slhdsa.Options{Context: []byte("my-context")})

// With randomness (hedged signing, may help against side-channel attacks)
sig, err := sk.Sign(rand.Reader, message, nil)
```

### Verification

```go
pk := sk.Public().(*slhdsa.PublicKey)
valid := pk.Verify(signature, message, nil)

// With context (must match what was used during signing)
valid := pk.Verify(signature, message, []byte("my-context"))
```

### Key Serialization

```go
// Export keys
skBytes := sk.Bytes()
pkBytes := sk.Public().Bytes()

// Import keys
sk, err := slhdsa.NewPrivateKey(slhdsa.SHA2_128f, skBytes)
pk, err := slhdsa.NewPublicKey(slhdsa.SHA2_128f, pkBytes)
```

## License

MIT License - see [LICENSE](LICENSE) file.
