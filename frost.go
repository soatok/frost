package frost

import (
	"github.com/soatok/frost/internal"
)

type Ciphersuite = internal.Ciphersuite
type Commitment = internal.Commitment
type Element = internal.Element
type GroupKey = internal.GroupKey
type Nonce = internal.Nonce
type Participant = internal.Participant
type Scalar = internal.Scalar
type SignatureShare = internal.SignatureShare
type SecretShare = internal.SecretShare
type State = internal.State

// FROST(Ed25519, SHA-512) from RFC 9591, section 6.1
type Ed25519Sha512 = internal.Ed25519Sha512

// Initialize the default ciphersuite
func DefaultCiphersuite() Ciphersuite {
	return new(Ed25519Sha512)
}

// Initialize a Participant based on serialized (scalar, element) values
func NewParticipant(id, publicShare []byte) (*Participant, error) {
	identifier, err := internal.NewScalar().SetBytes(id)
	if err != nil {
		return nil, err
	}
	share, err := internal.NewElement().SetBytes(publicShare)
	if err != nil {
		return nil, err
	}

	party := new(Participant)
	party.Identifier = identifier
	party.PublicKeyShare = share
	return party, nil
}

// Load a Group Key from a sequence of bytes
func GroupKeyFromBytes(b []byte) (*GroupKey, error) {
	el, err := internal.NewElement().SetBytes(b)
	if err != nil {
		return nil, err
	}
	gk := new(GroupKey)
	gk.Element = el
	return gk, nil
}

// Load an element from a sequence of bytes
func ElementFromBytes(b []byte) (*Element, error) {
	s, err := internal.NewElement().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Load a scalar from a sequence of bytes
func ScalarFromBytes(b []byte) (*Scalar, error) {
	s, err := internal.NewScalar().SetBytes(b)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Deserialize a secret share from two sequences of bytes
func SecretShareFromBytes(id, sec []byte) (*SecretShare, error) {
	identifier, err := internal.NewScalar().SetBytes(id)
	if err != nil {
		return nil, err
	}
	share, err := internal.NewScalar().SetBytes(sec)
	if err != nil {
		return nil, err
	}

	ss := new(SecretShare)
	ss.Identifier = identifier
	ss.Scalar = share
	return ss, nil
}

// Initialize a new FROST State
func NewState(c Ciphersuite, participants []*Participant, groupKey *GroupKey, msg []byte, mySecretShare *SecretShare) *State {
	var myIdentifier *Scalar
	if mySecretShare != nil {
		myIdentifier = mySecretShare.Identifier
	}
	return internal.NewState(c, participants, groupKey, msg, myIdentifier, mySecretShare)
}

// Deserialize commitments from JSON
func CommitmentFromJSON(j []byte) (*internal.Commitment, error) {
	return internal.CommitmentFromJSON(j)
}

// Deserialize a signature share from a JSON sequence
func SignatureShareFromJSON(j []byte) (*internal.SignatureShare, error) {
	return internal.SignatureShareFromJSON(j)
}

// Internalize a new scalar
func NewScalar() *Scalar {
	return internal.NewScalar()
}

// Initialzie a new element
func NewElement() *Element {
	return internal.NewElement()
}

// derives the interpolating value for a participant
func DeriveInterpolatingValueTestingOnly(L []*Scalar, xi *Scalar) (*Scalar, error) {
	return internal.DeriveInterpolatingValue(L, xi)
}

// ComputeBindingFactors computes the binding factors for a signing ceremony.
func ComputeBindingFactors(c Ciphersuite, groupPublicKey *GroupKey, commitments []*Commitment, msg []byte) []*internal.BindingFactor {
	return internal.ComputeBindingFactors(c, groupPublicKey.Element, commitments, msg)
}

// ComputeGroupCommitment computes the group commitment for a signing ceremony.
func ComputeGroupCommitment(commitments []*Commitment, bindingFactors []*internal.BindingFactor) (*Element, error) {
	return internal.ComputeGroupCommitment(commitments, bindingFactors)
}
