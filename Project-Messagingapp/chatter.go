// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	//fmt un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x01

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x02

// Label for deriving message keys from chain keys.
const KEY_LABEL = 0x03

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet      *KeyPair
	PartnerDHRatchet *PublicKey
	RootChain        *SymmetricKey
	SendChain        *SymmetricKey
	ReceiveChain     *SymmetricKey
	oldRoot          *SymmetricKey

	StaleReceiveKeys map[int]*SymmetricKey
	SendCounter      int
	LastUpdate       int
	ReceiveCounter   int
	//	oldRecieveCounter int
	iRatchet    bool // added aditional field
	PrevEpublic *PublicKey
	Initiator   int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = NewKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
// Part 6
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	// TODO: your code here

	c.Sessions[*partnerIdentity] = &Session{}
	delete(c.Sessions, *partnerIdentity)

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which initiates should be
// the first to choose a new DH ratchet value. Part of this code has been
// provided for you, you will need to fill in the key derivation code.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		StaleReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:      NewKeyPair(),
		PartnerDHRatchet: nil,
		RootChain:        nil,
		SendChain:        nil,
		ReceiveChain:     nil,
		SendCounter:      0,
		LastUpdate:       0,
		ReceiveCounter:   0,
		PrevEpublic:      nil,
		iRatchet:         true,
		Initiator:        1,
		oldRoot:          nil,
		//	oldChain:          nil,
		//	oldPartner:        nil,
		//	oldRecieveCounter: 0,
	}

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, nil

}

// ReturnHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. Part of this code has been provided for you, you will
// need to fill in the key derivation code. The partner which calls this
// method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	c.Sessions[*partnerIdentity] = &Session{
		StaleReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:      NewKeyPair(),
		PartnerDHRatchet: partnerEphemeral,
		RootChain:        nil,
		SendChain:        nil,
		ReceiveChain:     nil,
		SendCounter:      0,
		LastUpdate:       0,
		ReceiveCounter:   0,
		PrevEpublic:      nil,
		iRatchet:         false,
		Initiator:        0,
		oldRoot:          nil,
	}

	firstsym := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	twosym := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	threesym := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	c.Sessions[*partnerIdentity].RootChain = CombineKeys(firstsym, twosym, threesym)
	c.Sessions[*partnerIdentity].oldRoot = c.Sessions[*partnerIdentity].RootChain
	c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
	c.Sessions[*partnerIdentity].ReceiveChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)

	return &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey, c.Sessions[*partnerIdentity].RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL), nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake. Part of this code has been provided, you will
// need to fill in the key derivation code. The partner which calls this
// method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	// TODO: your code here
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral

	firstsym := DHCombine(partnerEphemeral, &c.Identity.PrivateKey)
	twosym := DHCombine(partnerIdentity, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
	threesym := DHCombine(partnerEphemeral, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)

	c.Sessions[*partnerIdentity].RootChain = CombineKeys(firstsym, twosym, threesym)
	c.Sessions[*partnerIdentity].oldRoot = c.Sessions[*partnerIdentity].RootChain
	c.Sessions[*partnerIdentity].ReceiveChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
	c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)

	return c.Sessions[*partnerIdentity].RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL), nil
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		// TODO: your code here
		NextDHRatchet: &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey,
		Counter:       0,
		LastUpdate:    0,
		IV:            NewIV(),
	}

	// TODO: your code here

	if c.Sessions[*partnerIdentity].iRatchet != true {

		if c.Sessions[*partnerIdentity].PrevEpublic != nil {
			message.NextDHRatchet = c.Sessions[*partnerIdentity].PrevEpublic
		}

	} else {
		c.Sessions[*partnerIdentity].oldRoot = c.Sessions[*partnerIdentity].RootChain
		c.Sessions[*partnerIdentity].MyDHRatchet = NewKeyPair()
		message.NextDHRatchet = &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey
		newkey := DHCombine(c.Sessions[*partnerIdentity].PartnerDHRatchet, &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey)
		c.Sessions[*partnerIdentity].RootChain = CombineKeys(c.Sessions[*partnerIdentity].RootChain, newkey)

		c.Sessions[*partnerIdentity].iRatchet = false
		c.Sessions[*partnerIdentity].PrevEpublic = &c.Sessions[*partnerIdentity].MyDHRatchet.PublicKey
		c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].RootChain.DeriveKey(CHAIN_LABEL)
		c.Sessions[*partnerIdentity].LastUpdate = c.Sessions[*partnerIdentity].SendCounter
	}

	msgkey := c.Sessions[*partnerIdentity].SendChain.DeriveKey(KEY_LABEL)
	c.Sessions[*partnerIdentity].SendChain = c.Sessions[*partnerIdentity].SendChain.DeriveKey(CHAIN_LABEL)
	message.LastUpdate = c.Sessions[*partnerIdentity].LastUpdate

	c.Sessions[*partnerIdentity].SendCounter++
	message.Counter = c.Sessions[*partnerIdentity].SendCounter

	message.Ciphertext = msgkey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), message.IV)

	msgkey.Zeroize()
	return message, nil

}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// TODO: your code here
	oldChain := c.Sessions[*message.Sender].ReceiveChain
	oldRoot := c.Sessions[*message.Sender].RootChain
	partner := c.Sessions[*message.Sender].PartnerDHRatchet
	ogroot := c.Sessions[*message.Sender].oldRoot
	c.Sessions[*message.Sender].ReceiveCounter++

	//if message is not out of order
	if message.Counter == c.Sessions[*message.Sender].ReceiveCounter {
		/* 		fmt.Println()
		   		fmt.Println("message not out of order, ", c.Sessions[*message.Sender].iRatchet)
				   fmt.Println() */

		if c.Sessions[*message.Sender].iRatchet == false {
			c.Sessions[*message.Sender].oldRoot = c.Sessions[*message.Sender].RootChain
			newkey := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
			c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, newkey)
			c.Sessions[*message.Sender].iRatchet = true
			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain.DeriveKey(CHAIN_LABEL)
			c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
			newkey.Zeroize()
		}

		msgkey := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(KEY_LABEL)
		c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)

		plain, er := msgkey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)

		msgkey.Zeroize()
		if er == nil {
			return plain, nil

		}

		c.Sessions[*message.Sender].ReceiveChain = oldChain
		c.Sessions[*message.Sender].RootChain = oldRoot
		c.Sessions[*message.Sender].PartnerDHRatchet = partner
		c.Sessions[*message.Sender].oldRoot = ogroot
		if c.Sessions[*message.Sender].iRatchet == true {
			c.Sessions[*message.Sender].iRatchet = false
		}
		c.Sessions[*message.Sender].ReceiveCounter--
		return "", er

	} else if message.Counter > c.Sessions[*message.Sender].ReceiveCounter {
		if message.LastUpdate == 0 {
			prev := c.Sessions[*message.Sender].ReceiveChain

			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].oldRoot

			if c.Sessions[*message.Sender].ReceiveCounter == 1 {
				if c.Sessions[*message.Sender].Initiator == 0 {
					c.Sessions[*message.Sender].oldRoot = c.Sessions[*message.Sender].RootChain
					newkey := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
					c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, newkey)
					c.Sessions[*message.Sender].iRatchet = true
					c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain
					c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
				}
			}
			for i := 1; i < message.Counter; i++ {
				chain := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
				msg := chain.DeriveKey(KEY_LABEL)
				c.Sessions[*message.Sender].ReceiveChain = chain
				c.Sessions[*message.Sender].StaleReceiveKeys[i] = msg
			}
			chain := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			msg := chain.DeriveKey(KEY_LABEL)

			plain, er := msg.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
			c.Sessions[*message.Sender].ReceiveChain = prev
			prev.Zeroize()
			chain.Zeroize()
			msg.Zeroize()

			if er != nil {
				c.Sessions[*message.Sender].ReceiveChain = oldChain
				oldChain.Zeroize()
				c.Sessions[*message.Sender].RootChain = oldRoot
				c.Sessions[*message.Sender].PartnerDHRatchet = partner
				c.Sessions[*message.Sender].oldRoot = ogroot

				if c.Sessions[*message.Sender].ReceiveCounter == 1 && c.Sessions[*message.Sender].Initiator == 0 {
					if c.Sessions[*message.Sender].iRatchet == true {
						c.Sessions[*message.Sender].iRatchet = false
					}
				}
				for i := 1; i < message.Counter; i++ {
					c.Sessions[*message.Sender].StaleReceiveKeys[i].Zeroize()
					delete(c.Sessions[*message.Sender].StaleReceiveKeys, i)
				}
				c.Sessions[*message.Sender].ReceiveCounter--
				return "", er
			}
			return plain, nil

		} else if message.LastUpdate > 0 {

			prev := c.Sessions[*message.Sender].RootChain

			c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].oldRoot

			for i := 1; i <= message.LastUpdate; i++ {
				chain := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
				msg := chain.DeriveKey(KEY_LABEL)
				c.Sessions[*message.Sender].ReceiveChain = chain
				c.Sessions[*message.Sender].StaleReceiveKeys[i] = msg
			}

			if c.Sessions[*message.Sender].iRatchet == false {
				c.Sessions[*message.Sender].oldRoot = c.Sessions[*message.Sender].RootChain
				newkey := DHCombine(message.NextDHRatchet, &c.Sessions[*message.Sender].MyDHRatchet.PrivateKey)
				c.Sessions[*message.Sender].RootChain = CombineKeys(c.Sessions[*message.Sender].RootChain, newkey)
				c.Sessions[*message.Sender].iRatchet = true
				c.Sessions[*message.Sender].ReceiveChain = c.Sessions[*message.Sender].RootChain
				c.Sessions[*message.Sender].PartnerDHRatchet = message.NextDHRatchet
				newkey.Zeroize()
			}

			for i := message.LastUpdate + 1; i < message.Counter; i++ {
				chain := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
				msg := chain.DeriveKey(KEY_LABEL)
				c.Sessions[*message.Sender].ReceiveChain = chain
				c.Sessions[*message.Sender].StaleReceiveKeys[i] = msg
			}

			chain := c.Sessions[*message.Sender].ReceiveChain.DeriveKey(CHAIN_LABEL)
			msg := chain.DeriveKey(KEY_LABEL)

			plain, er := msg.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
			c.Sessions[*message.Sender].ReceiveChain = prev
			prev.Zeroize()
			chain.Zeroize()
			msg.Zeroize()

			if er != nil {
				for i := 1; i < message.Counter; i++ {
					c.Sessions[*message.Sender].StaleReceiveKeys[i].Zeroize()
					delete(c.Sessions[*message.Sender].StaleReceiveKeys, i)
				}
				c.Sessions[*message.Sender].ReceiveCounter--
				return "", er
			}
			return plain, nil

		}

	} else if message.Counter < c.Sessions[*message.Sender].ReceiveCounter {

		if c.Sessions[*message.Sender].StaleReceiveKeys[message.Counter] == nil {
			return "", errors.New("Cannot replay a late message")

		}
		msg := c.Sessions[*message.Sender].StaleReceiveKeys[message.Counter]
		delete(c.Sessions[*message.Sender].StaleReceiveKeys, message.Counter)
		plain, _ := msg.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
		msg.Zeroize()
		return plain, nil

	}
	return "", errors.New("error")

}
