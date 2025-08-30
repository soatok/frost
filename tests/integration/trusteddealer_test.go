package integration

import (
	"crypto/ed25519"
	"testing"

	"github.com/soatok/frost"
	"github.com/soatok/frost/internal"
	"github.com/soatok/frost/trusteddealer"
	"github.com/stretchr/testify/require"
)

func TestTrustedDealer(t *testing.T) {
	c := frost.DefaultCiphersuite()
	td := trusteddealer.NewTrustedDealer(c)

	maxSigners := uint32(4)
	minSigners := uint32(3)

	// 1. KeyGen
	keygen, err := td.Keygen(maxSigners, minSigners)
	require.NoError(t, err)
	require.Len(t, keygen.ParticipantPrivateKeys, 4)
	require.Len(t, keygen.Participants, 4)

	// Test VSSVerify
	for _, p := range keygen.ParticipantPrivateKeys {
		ok, err := trusteddealer.VssVerify(c, p, keygen.VssCommitment, minSigners)
		require.NoError(t, err)
		require.True(t, ok)
	}

	// 2. Round 1
	message := []byte("it's a lovely day to save lives")
	participants := keygen.Participants[:3]
	secretShares := make([]*internal.SecretShare, 3)
	for i := 0; i < 3; i++ {
		for _, s := range keygen.ParticipantPrivateKeys {
			if s.Identifier.Equal(participants[i].Identifier) {
				secretShares[i] = s
				break
			}
		}
	}

	states := make([]*frost.State, 3)
	commitments := make([]*frost.Commitment, 3)

	for i := range participants {
		states[i] = frost.NewState(
			c,
			keygen.Participants,
			keygen.GroupPublicKey,
			message,
			secretShares[i],
		)
		var err error
		commitments[i], err = states[i].Commit()
		require.NoError(t, err)
	}

	// 3. Round 2
	shares := make([]*frost.SignatureShare, 3)
	for i := range states {
		var err error
		shares[i], err = states[i].Sign(commitments)
		require.NoError(t, err)
	}

	// 4. Aggregate
	aggState := frost.NewState(c, keygen.Participants, keygen.GroupPublicKey, message, nil)
	_, err = aggState.Sign(commitments)
	require.NoError(t, err)

	sig, err := aggState.Aggregate(shares)
	require.NoError(t, err)

	// 5. Verify
	pubKeyBytes := keygen.GroupPublicKey.Element.Bytes()
	sigBytes := sig.Bytes()

	ok := ed25519.Verify(pubKeyBytes, message, sigBytes)
	require.True(t, ok)
}
