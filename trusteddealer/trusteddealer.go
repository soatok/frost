package trusteddealer

// Package trusteddealer implements the "Trusted Dealer" key generation strategy from
// Appendix C of RFC 9591.
//
// https://www.rfc-editor.org/rfc/rfc9591.html#name-trusted-dealer-key-generati

import (
	"crypto/rand"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/soatok/frost"
	"github.com/soatok/frost/internal"
)

type KeygenOutput = frost.KeygenOutput

type TrustedDealer struct {
	c internal.Ciphersuite
}

func NewTrustedDealer(c internal.Ciphersuite) *TrustedDealer {
	return &TrustedDealer{c: c}
}

// Implement the interface defined in ,,/keygen.go
func (td *TrustedDealer) Keygen(maxParticipants, minParticipants uint32) (*KeygenOutput, error) {
	// Generate a random secret key
	secretKeyBytes := make([]byte, 64)
	_, err := rand.Read(secretKeyBytes)
	if err != nil {
		return nil, err
	}
	secretKey, err := edwards25519.NewScalar().SetUniformBytes(secretKeyBytes)
	if err != nil {
		return nil, err
	}

	// Generate random coefficients for the polynomial
	coefficients := make([]*edwards25519.Scalar, minParticipants-1)
	for i := range coefficients {
		randomBytes := make([]byte, 64)
		_, err := rand.Read(randomBytes)
		if err != nil {
			return nil, err
		}
		coefficients[i], err = edwards25519.NewScalar().SetUniformBytes(randomBytes)
		if err != nil {
			return nil, err
		}
	}

	// Create secret shares
	participantPrivateKeys, fullCoefficients, err := td.secretShareShard(secretKey, coefficients, maxParticipants)
	if err != nil {
		return nil, err
	}

	// Create VSS commitment
	vssCommitment := vssCommit(fullCoefficients)

	// Derive group info
	groupPublicKey, participants, err := DeriveGroupInfo(td.c, maxParticipants, minParticipants, vssCommitment)
	if err != nil {
		return nil, err
	}

	return &KeygenOutput{
		ParticipantPrivateKeys: participantPrivateKeys,
		Participants:           participants,
		GroupPublicKey:         groupPublicKey,
		VssCommitment:          vssCommitment,
	}, nil
}

// This is where the trusted party actually performs the deal.
// This function split the secret scalar, s, into miultiple shares.
//
// https://www.rfc-editor.org/rfc/rfc9591.html#name-shamir-secret-sharing
func (td *TrustedDealer) secretShareShard(s *edwards25519.Scalar, coefficients []*edwards25519.Scalar, maxParticipants uint32) ([]*internal.SecretShare, []*edwards25519.Scalar, error) {
	// Prepend the secret to the coefficients
	fullCoefficients := append([]*edwards25519.Scalar{s}, coefficients...)

	// Evaluate the polynomial for each point x=1,...,n
	secretKeyShares := make([]*internal.SecretShare, maxParticipants)
	for i := uint32(1); i <= maxParticipants; i++ {
		x, err := internal.NewScalarFromBigInt(big.NewInt(int64(i)))
		if err != nil {
			return nil, nil, err
		}
		y := polynomialEvaluate(x.ToEd25519(), fullCoefficients)
		yScalar, err := internal.NewScalar().SetBytes(y.Bytes())
		if err != nil {
			return nil, nil, err
		}

		secretKeyShares[i-1] = &internal.SecretShare{
			Identifier: x,
			Scalar:     yScalar,
		}
	}
	return secretKeyShares, fullCoefficients, nil
}

// Evaluate a polynomial using Horner's method.
//
// Because edwards25519 is constant-time, we aren't worried about leaks here:
//
// https://www.rfc-editor.org/rfc/rfc9591.html#name-additional-polynomial-opera
func polynomialEvaluate(x *edwards25519.Scalar, coeffs []*edwards25519.Scalar) *edwards25519.Scalar {
	value := edwards25519.NewScalar()
	for i := len(coeffs) - 1; i >= 0; i-- {
		value.Multiply(value, x)
		value.Add(value, coeffs[i])
	}
	return value
}

// Security: This needs to be constant-time with respect to the coefficients.
//
// https://www.rfc-editor.org/rfc/rfc9591.html#name-verifiable-secret-sharing
func vssCommit(coeffs []*edwards25519.Scalar) []*internal.Element {
	vssCommitment := make([]*internal.Element, len(coeffs))
	for i, coeff := range coeffs {
		point := edwards25519.NewIdentityPoint().ScalarBaseMult(coeff)
		vssCommitment[i] = internal.NewElementFromPoint(point)
	}
	return vssCommitment
}

// Every input to this method is public, so the timing leaks caused by math/big are moot.
//
// https://www.rfc-editor.org/rfc/rfc9591.html#name-verifiable-secret-sharing
func VssVerify(c internal.Ciphersuite, share *internal.SecretShare, vssCommitment []*internal.Element, minParticipants uint32) (bool, error) {
	sk_i := share.Scalar.ToEd25519()
	s_i := edwards25519.NewIdentityPoint().ScalarBaseMult(sk_i)
	s_i_prime := edwards25519.NewIdentityPoint()
	iScalar := share.Identifier

	for j := uint32(0); j < minParticipants; j++ {
		pow_i_j_big := new(big.Int).Exp(iScalar.BigInt(), big.NewInt(int64(j)), c.Order())
		pow_i_j, err := internal.NewScalarFromBigInt(pow_i_j_big)
		if err != nil {
			return false, err
		}
		term := edwards25519.NewIdentityPoint().ScalarMult(pow_i_j.ToEd25519(), vssCommitment[j].ToEd25519())
		s_i_prime.Add(s_i_prime, term)
	}

	// Comparison of two edwards25519.Point structs uses a constant-time method under the hood:
	return s_i.Equal(s_i_prime) == 1, nil
}

// Every input to this method is public, so the timing leaks caused by math/big are moot.
//
// https://www.rfc-editor.org/rfc/rfc9591.html#name-verifiable-secret-sharing
func DeriveGroupInfo(c internal.Ciphersuite, maxParticipants, minParticipants uint32, vssCommitment []*internal.Element) (*internal.GroupKey, []*internal.Participant, error) {
	groupPublicKey := &internal.GroupKey{Element: vssCommitment[0]}
	participants := make([]*internal.Participant, maxParticipants)

	for i := uint32(1); i <= maxParticipants; i++ {
		pk_i := edwards25519.NewIdentityPoint()
		iScalar, err := internal.NewScalarFromBigInt(big.NewInt(int64(i)))
		if err != nil {
			return nil, nil, err
		}

		for j := uint32(0); j < minParticipants; j++ {
			pow_i_j_big := new(big.Int).Exp(iScalar.BigInt(), big.NewInt(int64(j)), c.Order())
			pow_i_j, err := internal.NewScalarFromBigInt(pow_i_j_big)
			if err != nil {
				return nil, nil, err
			}
			term := edwards25519.NewIdentityPoint().ScalarMult(pow_i_j.ToEd25519(), vssCommitment[j].ToEd25519())
			pk_i.Add(pk_i, term)
		}
		pk, err := internal.NewElement().SetBytes(pk_i.Bytes())
		if err != nil {
			return nil, nil, err
		}
		participants[i-1] = &internal.Participant{
			Identifier:     iScalar,
			PublicKeyShare: pk,
		}
	}
	return groupPublicKey, participants, nil
}
