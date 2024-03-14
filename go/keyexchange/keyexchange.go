package keyexchange

import (
	"github.com/christoffercarlsson/autograph/cert"
	c "github.com/christoffercarlsson/autograph/constants"
	e "github.com/christoffercarlsson/autograph/external"
	"github.com/christoffercarlsson/autograph/kdf"
	s "github.com/christoffercarlsson/autograph/state"
	t "github.com/christoffercarlsson/autograph/types"
)

func DeriveSecretKeys(state *t.State, isInitiator bool) bool {
	var sharedSecret t.SharedSecret = [c.SHARED_SECRET_SIZE]byte{}
	var okm t.Okm = [c.OKM_SIZE]byte{}
	dhSuccess := e.DiffieHellman(
		&sharedSecret,
		s.GetEphemeralPrivateKey(state),
		s.GetTheirEphemeralKey(state),
	)
	kdfSuccess := kdf.Kdf(&okm, &sharedSecret)
	s.SetSecretKeys(state, isInitiator, &okm)

	for i := range okm {
		if i < 32 {
			sharedSecret[i] = 0
		}
		okm[i] = 0
	}
	return dhSuccess && kdfSuccess
}

func KeyExchange(ourSignature *t.Signature, state *t.State, isInitiator bool) bool {
	s.SetTranscript(state, isInitiator)
	keySuccess := DeriveSecretKeys(state, isInitiator)
	s.DeleteEphemeralPrivateKey(state)
	transcript := s.GetTranscript(state)[:]
	certifySuccess := cert.CertifyDataOwnership(
		ourSignature,
		state,
		s.GetTheirIdentityKey(state),
		&transcript,
	)
	if !certifySuccess || !keySuccess {
		for i := range state {
			state[i] = 0
		}
		return false
	}
	return true
}

func VerifyKeyExchange(state *t.State, theirSignature t.Signature) bool {
	transcript := s.GetTranscript(state)[:]
	if !cert.VerifyDataOwnership(
		s.GetIdentityPublicKey(state),
		&transcript,
		s.GetTheirIdentityKey(state),
		&theirSignature,
	) {
		for i := range state {
			state[i] = 0
		}
		return false
	}
	s.ZeroizeSkippedIndexes(state)
	return true
}
