package internal

// MessageType is the type of a message.
type MessageType int

const (
	// MessageTypeNone is the zero value for a message type.
	MessageTypeNone MessageType = iota
	// MessageTypeKeyGen1 is the message for the first round of the DKG protocol.
	MessageTypeKeyGen1
	// MessageTypeKeyGen2 is the message for the second round of the DKG protocol.
	MessageTypeKeyGen2
)

// Message is a generic message that can be sent between participants.
type Message struct {
	From           *Scalar
	Commitment     *Commitment
	SignatureShare *SignatureShare
}
