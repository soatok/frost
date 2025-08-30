package frost

import (
	"github.com/soatok/frost/internal"
)

type KeygenOutput struct {
	ParticipantPrivateKeys []*internal.SecretShare
	Participants           []*internal.Participant
	GroupPublicKey         *internal.GroupKey
	VssCommitment          []*internal.Element
}

// Key generators should implement this interface!
type KeyGenerator interface {
	Keygen(maxParticipants, minParticipants uint32) (*KeygenOutput, error)
}

// How many outputs do we hold?
func (ko KeygenOutput) Count() int {
	return len(ko.Participants)
}

// Get the Verifiable Secret Sharing commitments for each participant
func (ko *KeygenOutput) Commitments(index int) [][]byte {
	out := [][]byte{}
	for _, c := range ko.VssCommitment {
		out = append(out, c.Bytes())
	}
	return out
}
