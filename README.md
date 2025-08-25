# Go Implementation of FROST (RFC 9591)

[![Build Status](https://github.com/soatok/frost/actions/workflows/ci.yml/badge.svg)](https://github.com/soatok/frost/actions/workflows/ci.yml)

This Go module implements [RFC 9591 (FROST)](https://www.rfc-editor.org/rfc/rfc9591.html) for threshold signing
with the Ed25519 ciphersuite.

This was developed in part to make [FREON](https://github.com/soatok/freon) possible.
[Learn more about FREON](https://soatok.blog/2025/08/09/improving-geographical-resilience-for-distributed-open-source-teams-with-freon/).

## Security Notice

> [!WARNING]
>
> This package has not been audited by a third party.

## Install

```terminal
go install github.com/soatok/frost@latest
```

## Usage

### Key Generation

This package currently does **NOT** implement key generation.

In the future, we will implement two key generation strategies in submodules:

1. Honest Dealer (simpler, but requires a trusted party)
2. An Ed25519 variant of ChillDKG

### Signing

We will explain it usage inline with an example Go program:

```go

import (
	"github.com/soatok/frost"
)

func main() {
	// We are using the default ciphersuite:
	ciphersuite := frost.DefaultCiphersuite()

	// Initialize a list of participants
	participants = []*frost.Participant{}
	for _, member := range membersDefinedElsewhere {
		id := member.Identifier
		pks := member.PublicKeyShare
		// id []byte length 32
		// pk []byte length 32
		party, err := frost.NewParticipant(id, pks)
		if err != nil {
			panic(err)
		}
		// Append to list:
		participants = append(participants, party)
	}

	// Supply the group Ed25519 public key here:
	gk, err := frost.GroupKeyFromBytes([]byte{/* ... */})
	if err != nil {
		panic(err)
	}

	// Message to sign:
	message := []byte("the message you are signing goes here")

	// Initialize secret share
	mySecretShare, err := frost.SecretShareFromBytes([]byte{/* ... */}, []byte{/* ... */})
	if err != nil {
		panic(err)
	}

	// Define a State object for the signing ceremony
	state := frost.NewState(ciphersuite, participants, message, mySecretShare)

	// First round: commit to the message
	round1, err := state.Commit()
	if err != nil {
		panic(err)
	}

	// Send your commitment from round1 to the other participants here
	send1, err := round1.EncodeJSON()
	if err != nil {
		panic(err)
	}
	// YOU MUST DEFINE THE TRANSPORT OF `send1` YOURSELF

	// networking happens here

	// Load commitments from other parties
	recv1, err := getMessagesFromAbroad() // [][]byte -- YOU MUST DEFINE THIS YOURSELF
	if err != nil {
		panic(err)
	}
	commitments := []*Commitment{}
	for _, r := range recv1 {
		c, err := CommitmentFromJSON(r)
		if err != nil {
			panic(err)
		}
		commitments = append(commitments, c)
	}

	// Perform round 2: get signature shares
	round2, err := state.Sign(commitments)
	if err != nil {
		panic(err)
	}

	// Send your commitment from round1 to the other participants here
	send2, err := round2.EncodeJSON()
	// YOU MUST DEFINE THE TRANSPORT OF `send2` YOURSELF
	
	// networking happens here

	// Load signature shares from other parties
	recv2, err := getMessagesFromAbroad() // [][]byte -- YOU MUST DEFINE THIS YOURSELF
	if err != nil {
		panic(err)
	}
	shares := []*SignatureShare{}
	for _, r := range recv2 {
		s, err := SignatureShareFromJSON(r)
		if err != nil {
			panic(err)
		}

		// Validate this share before including it:
		valid, err := state.VerifySignatureShare(s)
		if err != nil {
			panic(err)
		}
		if valid {
			shares = append(shares, s)
		}
	}

	// Finally, aggregate the shares to calculate the final signature
	finalSig, err := state.Aggregate(shares)
}
```
