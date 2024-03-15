package keypair

import (
	"fmt"

	c "github.com/danba340/autograph/constants"
	e "github.com/danba340/autograph/external"
	t "github.com/danba340/autograph/types"
)

func EphemeralKeyPair(keyPair *t.KeyPair) bool {
	if !e.Init() {
		return false
	}
	return e.KeyPairEphemeral(keyPair)
}

func IdentityKeyPair(keyPair *t.KeyPair) bool {
	if !e.Init() {
		return false
	}
	return e.KeyPairIdentity(keyPair)
}

func GenerateKeyPair() (t.KeyPair, error) {
	var keyPair t.KeyPair = [c.KEY_PAIR_SIZE]byte{}
	success := EphemeralKeyPair(&keyPair)
	if !success {
		return [c.KEY_PAIR_SIZE]byte{}, fmt.Errorf("failed to generate KeyPair")
	}
	return keyPair, nil
}

func GenerateIdentityKeyPair() (t.KeyPair, error) {
	var keyPair t.KeyPair = [c.KEY_PAIR_SIZE]byte{}
	success := IdentityKeyPair(&keyPair)
	if !success {
		return [c.KEY_PAIR_SIZE]byte{}, fmt.Errorf("failed to generate identity KeyPair")
	}
	return keyPair, nil
}
