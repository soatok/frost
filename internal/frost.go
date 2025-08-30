package internal

import (
	"crypto/subtle"
	"fmt"
)

// State holds the state of a FROST signing ceremony.
type State struct {
	Ciphersuite     Ciphersuite
	Participants    []*Participant
	GroupKey        *GroupKey
	Message         []byte
	Commitments     []*Commitment
	SignatureShares []*SignatureShare
	MyIdentifier    *Scalar
	MySecretShare   *SecretShare
	MyNonce         *Nonce
	MyCommitment    *Commitment
	bindingFactors  []*BindingFactor
	groupCommitment *Element
	challenge       *Scalar
}

// NewState creates a new state for a signing ceremony.
func NewState(c Ciphersuite, participants []*Participant, groupKey *GroupKey, msg []byte, myIdentifier *Scalar, mySecretShare *SecretShare) *State {
	return &State{
		Ciphersuite:   c,
		Participants:  participants,
		GroupKey:      groupKey,
		Message:       msg,
		MyIdentifier:  myIdentifier,
		MySecretShare: mySecretShare,
	}
}

// Commit performs the first round of the FROST protocol.
func (s *State) Commit() (*Commitment, error) {
	hidingNonce, err := NonceGenerate(s.Ciphersuite, s.MySecretShare.Scalar)
	if err != nil {
		return nil, err
	}
	bindingNonce, err := NonceGenerate(s.Ciphersuite, s.MySecretShare.Scalar)
	if err != nil {
		return nil, err
	}
	s.MyNonce = &Nonce{
		Hiding:  hidingNonce,
		Binding: bindingNonce,
	}

	hidingCommitment := NewElement().Mul(hidingNonce, nil)
	bindingCommitment := NewElement().Mul(bindingNonce, nil)

	s.MyCommitment = &Commitment{
		Identifier: s.MyIdentifier,
		Hiding:     hidingCommitment,
		Binding:    bindingCommitment,
	}
	return s.MyCommitment, nil
}

// Sign performs the second round of the FROST protocol.
func (s *State) Sign(commitments []*Commitment) (*SignatureShare, error) {
	s.Commitments = commitments
	s.bindingFactors = ComputeBindingFactors(s.Ciphersuite, s.GroupKey.Element, s.Commitments, s.Message)

	var err error
	s.groupCommitment, err = ComputeGroupCommitment(s.Commitments, s.bindingFactors)
	if err != nil {
		return nil, err
	}

	s.challenge = ComputeChallenge(s.Ciphersuite, s.groupCommitment, s.GroupKey.Element, s.Message)
	if s.MySecretShare == nil {
		// An aggregation-only state allows the coordinator to compute the signature without holding a share
		return nil, nil
	}

	participantList := ParticipantsFromCommitmentList(s.Commitments)
	lambda_i, err := DeriveInterpolatingValue(participantList, s.MyIdentifier)
	if err != nil {
		return nil, err
	}

	bindingFactor, err := BindingFactorForParticipant(s.bindingFactors, s.MyIdentifier)
	if err != nil {
		return nil, err
	}

	sigShare := NewScalar()
	sigShare.Add(s.MyNonce.Hiding, NewScalar().Mul(s.MyNonce.Binding, bindingFactor))
	tmp := NewScalar().Mul(lambda_i, s.MySecretShare.Scalar)
	tmp.Mul(tmp, s.challenge)
	sigShare.Add(sigShare, tmp)

	return &SignatureShare{
		Identifier: s.MyIdentifier,
		Share:      sigShare,
	}, nil
}

// Aggregate aggregates the signature shares to produce the final signature.
func (s *State) Aggregate(shares []*SignatureShare) (*Signature, error) {
	if s.groupCommitment == nil {
		return nil, fmt.Errorf("group commitment not computed")
	}

	z := NewScalar()
	for _, share := range shares {
		z.Add(z, share.Share)
	}

	return &Signature{
		R: s.groupCommitment,
		Z: z,
	}, nil
}

func (s *State) SetGroupCommitment(e *Element) {
	s.groupCommitment = e
}

// VerifySignatureShare verifies a single signature share.
func (s *State) VerifySignatureShare(share *SignatureShare) (bool, error) {
	// Find the participant's public key share
	var p *Participant
	for _, participant := range s.Participants {
		if participant.Identifier.Equal(share.Identifier) {
			p = participant
			break
		}
	}
	if p == nil {
		return false, fmt.Errorf("participant not found")
	}

	// Find the participant's commitment
	var comm *Commitment
	for _, c := range s.Commitments {
		if c.Identifier.Equal(share.Identifier) {
			comm = c
			break
		}
	}
	if comm == nil {
		return false, fmt.Errorf("commitment not found")
	}

	bindingFactor, err := BindingFactorForParticipant(s.bindingFactors, share.Identifier)
	if err != nil {
		return false, err
	}

	commShare := NewElement().Mul(bindingFactor, comm.Binding)
	commShare.Add(commShare, comm.Hiding)

	participantList := ParticipantsFromCommitmentList(s.Commitments)
	lambda_i, err := DeriveInterpolatingValue(participantList, share.Identifier)
	if err != nil {
		return false, err
	}

	l := NewElement().Mul(share.Share, nil)

	tmp := NewScalar().Mul(s.challenge, lambda_i)
	r := NewElement().Mul(tmp, p.PublicKeyShare)
	r.Add(r, commShare)
	return subtle.ConstantTimeCompare(l.Bytes(), r.Bytes()) == 1, nil
}
