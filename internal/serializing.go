package internal

import (
	"encoding/base64"
	"encoding/json"
)

// Encode the ID and public share
func (p *Participant) Bytes() ([]byte, []byte) {
	return p.Identifier.s.Bytes(), p.PublicKeyShare.Bytes()
}

// Encode the Group Key as a sequence of bytes
func (gk *GroupKey) Bytes() []byte {
	return gk.Element.Bytes()
}

// Encode SecretShare as bytes
func (ss *SecretShare) Bytes() ([]byte, []byte) {
	return ss.Identifier.Bytes(), ss.Scalar.Bytes()
}

// Deserialzie a commitment from three sequences of bytes
func CommitmentFromBytes(id, hiding, binding []byte) (*Commitment, error) {
	identifier, err := NewScalar().SetBytes(id)
	if err != nil {
		return nil, err
	}

	hide, err := NewElement().SetBytes(hiding)
	if err != nil {
		return nil, err
	}
	bind, err := NewElement().SetBytes(binding)
	if err != nil {
		return nil, err
	}

	com := new(Commitment)
	com.Identifier = identifier
	com.Hiding = hide
	com.Binding = bind
	return com, nil
}

// Serialize a commitment
func (com *Commitment) Bytes() ([]byte, []byte, []byte) {
	return com.Identifier.Bytes(), com.Hiding.Bytes(), com.Binding.Bytes()
}

// Encode a commitment as bytes
func (com *Commitment) EncodeJSON() ([]byte, error) {
	id, hide, bind := com.Bytes()
	id64 := base64.URLEncoding.EncodeToString(id)
	hide64 := base64.URLEncoding.EncodeToString(hide)
	bind64 := base64.URLEncoding.EncodeToString(bind)
	out, err := json.Marshal(struct {
		Id   string `json:"i"`
		Hide string `json:"h"`
		Bind string `json:"b"`
	}{
		Id: id64, Hide: hide64, Bind: bind64,
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Deserialize a commitment from a JSON-encoded byte slice
func CommitmentFromJSON(j []byte) (*Commitment, error) {
	var v struct {
		Id   string `json:"i"`
		Hide string `json:"h"`
		Bind string `json:"b"`
	}
	err := json.Unmarshal(j, &v)
	if err != nil {
		return nil, err
	}
	rawId, err := base64.URLEncoding.DecodeString(v.Id)
	if err != nil {
		return nil, err
	}
	rawHide, err := base64.URLEncoding.DecodeString(v.Hide)
	if err != nil {
		return nil, err
	}
	rawBind, err := base64.URLEncoding.DecodeString(v.Bind)
	if err != nil {
		return nil, err
	}
	return CommitmentFromBytes(rawId, rawHide, rawBind)
}

// Decode a signature share from a sequence of bytes
func SignatureShareFromBytes(id, share []byte) (*SignatureShare, error) {
	identifier, err := NewScalar().SetBytes(id)
	if err != nil {
		return nil, err
	}
	s, err := NewScalar().SetBytes(share)
	if err != nil {
		return nil, err
	}
	sigshare := new(SignatureShare)
	sigshare.Identifier = identifier
	sigshare.Share = s
	return sigshare, nil
}

// Deserialize a signature share from a JSON-encoded byte slice
func SignatureShareFromJSON(j []byte) (*SignatureShare, error) {
	var v struct {
		Id    string `json:"i"`
		Share string `json:"s"`
	}
	err := json.Unmarshal(j, &v)
	if err != nil {
		return nil, err
	}
	rawId, err := base64.URLEncoding.DecodeString(v.Id)
	if err != nil {
		return nil, err
	}
	rawShare, err := base64.URLEncoding.DecodeString(v.Share)
	if err != nil {
		return nil, err
	}
	return SignatureShareFromBytes(rawId, rawShare)
}

// Encode a signatue share as a sequence of bytes
func (sigshare *SignatureShare) Bytes() ([]byte, []byte) {
	return sigshare.Identifier.Bytes(), sigshare.Share.Bytes()
}

// Encode a signature share as a JSON
func (sigshare *SignatureShare) EncodeJSON() ([]byte, error) {
	id, s := sigshare.Bytes()
	id64 := base64.URLEncoding.EncodeToString(id)
	share64 := base64.URLEncoding.EncodeToString(s)
	out, err := json.Marshal(struct {
		Id    string `json:"i"`
		Share string `json:"s"`
	}{
		Id: id64, Share: share64,
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
