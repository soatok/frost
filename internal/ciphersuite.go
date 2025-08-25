// Go implementation of FROST (RFC 9591)
package internal

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

const (
	// ContextString is the context string for FROST(Ed25519, SHA-512).
	ContextString = "FROST-ED25519-SHA512-v1"
)

// Ciphersuite defines the cryptographic hash functions used within FROST.
//
// H1, H2, and H3 map arbitrary byte strings to Scalar elements associated with the
// prime-order group.
//
// H4 and H5 are aliases for H with distinct domain separators.
//
// The other component you need is a Prime-Order Group. See: Ed25519.
//
// See https://www.rfc-editor.org/rfc/rfc9591.html#name-cryptographic-hash-function
type Ciphersuite interface {
	H1([]byte) *Scalar
	H2([]byte) *Scalar
	H3([]byte) *Scalar
	H4([]byte) []byte
	H5([]byte) []byte
}

// Ed25519Sha512 is the ciphersuite for FROST using Ed25519 and SHA-512.
type Ed25519Sha512 struct{}

// H1() is used for calculating binding factors (based on the participant commitment
// list, message to be signed, and group public key).
func (c *Ed25519Sha512) H1(m []byte) *Scalar {
	h := sha512.New()
	h.Write([]byte(ContextString))
	h.Write([]byte("rho"))
	h.Write(m)
	return c.hashToScalar(h.Sum(nil))
}

// Ed25519 is the exception in that H2() doesn't have domain separation.
// This is intended for compatibility with Ed25519, which we are using.
//
// H2() is used for signature challenge generation.
func (c *Ed25519Sha512) H2(m []byte) *Scalar {
	h := sha512.New()
	h.Write(m)
	return c.hashToScalar(h.Sum(nil))
}

// H3() is used for nonce generation. It's used with 32 random bytes to hedge
// against a weak random number generator.
func (c *Ed25519Sha512) H3(m []byte) *Scalar {
	h := sha512.New()
	h.Write([]byte(ContextString))
	h.Write([]byte("nonce"))
	h.Write(m)
	return c.hashToScalar(h.Sum(nil))
}

// H4() is used for hashing the message to a fixed length.
func (c *Ed25519Sha512) H4(m []byte) []byte {
	h := sha512.New()
	h.Write([]byte(ContextString))
	h.Write([]byte("msg"))
	h.Write(m)
	return h.Sum(nil)
}

// H5() is used for group commitment.
func (c *Ed25519Sha512) H5(m []byte) []byte {
	h := sha512.New()
	h.Write([]byte(ContextString))
	h.Write([]byte("com"))
	h.Write(m)
	return h.Sum(nil)
}

// Reducing a hash to a scalar. Only for internal usage.
func (c *Ed25519Sha512) hashToScalar(m []byte) *Scalar {
	s, err := edwards25519.NewScalar().SetUniformBytes(m)
	if err != nil {
		// This should not happen
		panic(err)
	}
	return &Scalar{s: s}
}
