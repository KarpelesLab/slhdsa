//go:build go1.25

package slhdsa

import "crypto"

// Compile-time interface check for Go 1.25+
var _ crypto.MessageSigner = (*PrivateKey)(nil)
