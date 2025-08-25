package internal

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"
)

// BindingFactor is a tuple of a participant identifier and a binding factor.
type BindingFactor struct {
	Identifier *Scalar
	Factor     *Scalar
}

// NonceGenerate generates a nonce for a participant.
func NonceGenerate(c Ciphersuite, secret *Scalar) (*Scalar, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	secretEnc := secret.Bytes()
	return c.H3(append(randomBytes, secretEnc...)), nil
}

// DeriveInterpolatingValue derives the interpolating value for a participant.
func DeriveInterpolatingValue(L []*Scalar, xi *Scalar) (*Scalar, error) {
	// Ensure xi is in L
	found := false
	for _, xj := range L {
		if xj.Equal(xi) {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("xi not in L")
	}

	// Ensure no duplicates in L
	for i, xj := range L {
		for j, xk := range L {
			if i != j && xj.Equal(xk) {
				return nil, fmt.Errorf("duplicate value in L")
			}
		}
	}

	one, err := NewScalar().SetBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		// This should not happen
		panic(err)
	}
	numerator := NewScalar()
	numerator.s.Set(one.s)
	denominator := NewScalar()
	denominator.s.Set(one.s)

	for _, xj := range L {
		if xj.Equal(xi) {
			continue
		}
		numerator.Mul(numerator, xj)
		tmp := NewScalar().Sub(xj, xi)
		denominator.Mul(denominator, tmp)
	}

	inv := NewScalar().Invert(denominator)
	value := NewScalar().Mul(numerator, inv)
	return value, nil
}

// EncodeGroupCommitmentList encodes a list of commitments into a byte string.
func EncodeGroupCommitmentList(commitments []*Commitment) []byte {
	var encoded []byte
	// Sort by identifier
	sort.Slice(commitments, func(i, j int) bool {
		// This is not a constant time comparison, but the identifiers are public.
		return bytes.Compare(commitments[i].Identifier.Bytes(), commitments[j].Identifier.Bytes()) < 0
	})
	for _, c := range commitments {
		encoded = append(encoded, c.Identifier.Bytes()...)
		encoded = append(encoded, c.Hiding.Bytes()...)
		encoded = append(encoded, c.Binding.Bytes()...)
	}
	return encoded
}

// ParticipantsFromCommitmentList extracts the participant identifiers from a
// list of commitments.
func ParticipantsFromCommitmentList(commitments []*Commitment) []*Scalar {
	// Sort by identifier first
	sort.Slice(commitments, func(i, j int) bool {
		return bytes.Compare(commitments[i].Identifier.Bytes(), commitments[j].Identifier.Bytes()) < 0
	})
	var identifiers []*Scalar
	for _, c := range commitments {
		identifiers = append(identifiers, c.Identifier)
	}
	return identifiers
}

// BindingFactorForParticipant returns the binding factor for a given participant.
func BindingFactorForParticipant(bindingFactors []*BindingFactor, identifier *Scalar) (*Scalar, error) {
	for _, bf := range bindingFactors {
		if bf.Identifier.Equal(identifier) {
			return bf.Factor, nil
		}
	}
	return nil, fmt.Errorf("participant not found")
}

// ComputeBindingFactors computes the binding factors for all participants.
func ComputeBindingFactors(c Ciphersuite, groupPublicKey *Element, commitments []*Commitment, msg []byte) []*BindingFactor {
	groupPublicKeyEnc := groupPublicKey.Bytes()
	msgHash := c.H4(msg)
	encodedCommitmentHash := c.H5(EncodeGroupCommitmentList(commitments))

	rhoInputPrefix := append(groupPublicKeyEnc, msgHash...)
	rhoInputPrefix = append(rhoInputPrefix, encodedCommitmentHash...)

	var bindingFactors []*BindingFactor
	for _, commitment := range commitments {
		rhoInput := append(rhoInputPrefix, commitment.Identifier.Bytes()...)
		bindingFactor := c.H1(rhoInput)
		bindingFactors = append(bindingFactors, &BindingFactor{
			Identifier: commitment.Identifier,
			Factor:     bindingFactor,
		})
	}
	return bindingFactors
}

// ComputeGroupCommitment computes the group commitment.
func ComputeGroupCommitment(commitments []*Commitment, bindingFactors []*BindingFactor) (*Element, error) {
	groupCommitment := NewElement()

	for _, commitment := range commitments {
		bindingFactor, err := BindingFactorForParticipant(bindingFactors, commitment.Identifier)
		if err != nil {
			return nil, err
		}
		bindingNonce := NewElement().Mul(bindingFactor, commitment.Binding)
		groupCommitment.Add(groupCommitment, commitment.Hiding)
		groupCommitment.Add(groupCommitment, bindingNonce)
	}
	return groupCommitment, nil
}

// ComputeChallenge computes the signature challenge.
func ComputeChallenge(c Ciphersuite, groupCommitment, groupPublicKey *Element, msg []byte) *Scalar {
	groupCommEnc := groupCommitment.Bytes()
	groupPublicKeyEnc := groupPublicKey.Bytes()
	challengeInput := append(groupCommEnc, groupPublicKeyEnc...)
	challengeInput = append(challengeInput, msg...)
	return c.H2(challengeInput)
}
