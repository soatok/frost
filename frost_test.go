package frost_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/soatok/frost"
	"github.com/stretchr/testify/assert"
)

// Default ciphersuite
var csuite = frost.DefaultCiphersuite()

// Test helper
func NewScalar64(i uint64) (*frost.Scalar, error) {
	s := make([]byte, 8)
	binary.LittleEndian.PutUint64(s, i)
	// 24 additional zero bytes
	x := make([]byte, 24)
	s = append(s, x...)
	return frost.ScalarFromBytes(s)
}

func TestFrostEd25519(t *testing.T) {
	// Test vectors from RFC 9591, Appendix E.1
	// https://www.rfc-editor.org/rfc/rfc9591.html#appendix-E.1
	var (
		msgHex                      = "74657374"
		groupSecretKeyHex           = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"
		groupPublicKeyHex           = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"
		p1ParticipantShareHex       = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"
		p3ParticipantShareHex       = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"
		p1HidingNonceHex            = "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407"
		p1BindingNonceHex           = "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301"
		p3HidingNonceHex            = "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e"
		p3BindingNonceHex           = "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d"
		p1HidingNonceCommitmentHex  = "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3"
		p1BindingNonceCommitmentHex = "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932"
		p3HidingNonceCommitmentHex  = "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91"
		p3BindingNonceCommitmentHex = "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552"
		p1SigShareHex               = "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603"
		p3SigShareHex               = "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007"
		finalSignatureHex           = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"
	)

	// Decode hex values
	msg, _ := hex.DecodeString(msgHex)
	groupSecretKeyBytes, _ := hex.DecodeString(groupSecretKeyHex)
	groupPublicKeyBytes, _ := hex.DecodeString(groupPublicKeyHex)
	p1ParticipantShareBytes, _ := hex.DecodeString(p1ParticipantShareHex)
	p3ParticipantShareBytes, _ := hex.DecodeString(p3ParticipantShareHex)
	p1HidingNonceBytes, _ := hex.DecodeString(p1HidingNonceHex)
	p1BindingNonceBytes, _ := hex.DecodeString(p1BindingNonceHex)
	p3HidingNonceBytes, _ := hex.DecodeString(p3HidingNonceHex)
	p3BindingNonceBytes, _ := hex.DecodeString(p3BindingNonceHex)
	p1HidingNonceCommitmentBytes, _ := hex.DecodeString(p1HidingNonceCommitmentHex)
	p1BindingNonceCommitmentBytes, _ := hex.DecodeString(p1BindingNonceCommitmentHex)
	p3HidingNonceCommitmentBytes, _ := hex.DecodeString(p3HidingNonceCommitmentHex)
	p3BindingNonceCommitmentBytes, _ := hex.DecodeString(p3BindingNonceCommitmentHex)
	p1SigShareBytes, _ := hex.DecodeString(p1SigShareHex)
	p3SigShareBytes, _ := hex.DecodeString(p3SigShareHex)
	finalSignatureBytes, _ := hex.DecodeString(finalSignatureHex)

	// Create objects from bytes
	groupSecretKey, _ := frost.ScalarFromBytes(groupSecretKeyBytes)
	groupPublicKey, _ := frost.ElementFromBytes(groupPublicKeyBytes)
	p1ID, err := NewScalar64(1)
	if err != nil {
		assert.Fail(t, err.Error())
	}
	p3ID, err := NewScalar64(3)
	if err != nil {
		assert.Fail(t, err.Error())
	}

	p1SecretShare, _ := frost.ScalarFromBytes(p1ParticipantShareBytes)
	p3SecretShare, _ := frost.ScalarFromBytes(p3ParticipantShareBytes)

	p1HidingNonce, _ := frost.ScalarFromBytes(p1HidingNonceBytes)
	p1BindingNonce, _ := frost.ScalarFromBytes(p1BindingNonceBytes)
	p3HidingNonce, _ := frost.ScalarFromBytes(p3HidingNonceBytes)
	p3BindingNonce, _ := frost.ScalarFromBytes(p3BindingNonceBytes)

	p1HidingCommitment, _ := frost.ElementFromBytes(p1HidingNonceCommitmentBytes)
	p1BindingCommitment, _ := frost.ElementFromBytes(p1BindingNonceCommitmentBytes)
	p3HidingCommitment, _ := frost.ElementFromBytes(p3HidingNonceCommitmentBytes)
	p3BindingCommitment, _ := frost.ElementFromBytes(p3BindingNonceCommitmentBytes)

	p1SigShare, _ := frost.ScalarFromBytes(p1SigShareBytes)
	p3SigShare, _ := frost.ScalarFromBytes(p3SigShareBytes)

	// Create participants
	p1PublicKey := frost.NewElement().Mul(p1SecretShare, nil)
	p3PublicKey := frost.NewElement().Mul(p3SecretShare, nil)
	p1 := &frost.Participant{Identifier: p1ID, PublicKeyShare: p1PublicKey}
	p3 := &frost.Participant{Identifier: p3ID, PublicKeyShare: p3PublicKey}
	participants := []*frost.Participant{p1, p3}

	// Create state for participant 1
	state1 := frost.NewState(csuite, participants, &frost.GroupKey{Element: groupPublicKey}, msg, &frost.SecretShare{Identifier: p1ID, Scalar: p1SecretShare})
	state1.MyNonce = &frost.Nonce{Hiding: p1HidingNonce, Binding: p1BindingNonce}

	// Create state for participant 3
	state3 := frost.NewState(csuite, participants, &frost.GroupKey{Element: groupPublicKey}, msg, &frost.SecretShare{Identifier: p3ID, Scalar: p3SecretShare})
	state3.MyNonce = &frost.Nonce{Hiding: p3HidingNonce, Binding: p3BindingNonce}

	// Commitments
	commitments := []*frost.Commitment{
		{Identifier: p1ID, Hiding: p1HidingCommitment, Binding: p1BindingCommitment},
		{Identifier: p3ID, Hiding: p3HidingCommitment, Binding: p3BindingCommitment},
	}

	// Round 2 for P1
	share1, err := state1.Sign(commitments)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(share1.Share.Bytes(), p1SigShare.Bytes()) {
		t.Fatalf("p1 signature share mismatch:\ngot:  %x\nwant: %x", share1.Share.Bytes(), p1SigShare.Bytes())
	}

	// Round 2 for P3
	share3, err := state3.Sign(commitments)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(share3.Share.Bytes(), p3SigShare.Bytes()) {
		t.Fatalf("p3 signature share mismatch:\ngot:  %x\nwant: %x", share3.Share.Bytes(), p3SigShare.Bytes())
	}

	// Aggregate
	finalSig, err := state1.Aggregate([]*frost.SignatureShare{share1, share3})
	if err != nil {
		t.Fatal(err)
	}

	// Verify final signature
	sigBytes := append(finalSig.R.Bytes(), finalSig.Z.Bytes()...)
	if !bytes.Equal(sigBytes, finalSignatureBytes) {
		t.Fatalf("final signature mismatch:\ngot:  %x\nwant: %x", sigBytes, finalSignatureBytes)
	}

	// Check against the group public key
	// Verification equation: zB = R + c * PK
	// l = zB
	l := frost.NewElement().Mul(finalSig.Z, nil)

	// r = R + c * PK
	// c = H2(R || PK || msg)
	challengeInput := append(finalSig.R.Bytes(), groupPublicKey.Bytes()...)
	challengeInput = append(challengeInput, msg...)
	c_scalar := csuite.H2(challengeInput)

	r := frost.NewElement().Mul(c_scalar, groupPublicKey)
	r.Add(r, finalSig.R)

	lp := l.Point()
	rp := r.Point()
	if lp.Equal(rp) != 1 {
		t.Fatal("signature verification failed")
	}

	// Test secret key derivation
	// s = s1 * l1 + s3 * l3
	pList := []*frost.Scalar{p1ID, p3ID}
	l1, err := frost.DeriveInterpolatingValueTestingOnly(pList, p1ID)
	if err != nil {
		t.Fatal(err)
	}
	l3, err := frost.DeriveInterpolatingValueTestingOnly(pList, p3ID)
	if err != nil {
		t.Fatal(err)
	}

	s1l1 := frost.NewScalar().Mul(p1SecretShare, l1)
	s3l3 := frost.NewScalar().Mul(p3SecretShare, l3)
	s := frost.NewScalar().Add(s1l1, s3l3)
	if !bytes.Equal(s.Bytes(), groupSecretKey.Bytes()) {
		t.Fatalf("secret key derivation mismatch:\ngot:  %x\nwant: %x", s.Bytes(), groupSecretKey.Bytes())
	}
}
