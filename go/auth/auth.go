package auth

import (
	"bytes"

	c "github.com/christoffercarlsson/autograph/constants"
	"github.com/christoffercarlsson/autograph/external"
	"github.com/christoffercarlsson/autograph/numbers"
	s "github.com/christoffercarlsson/autograph/state"
	t "github.com/christoffercarlsson/autograph/types"
)

func EncodeFingerprint(fingerprint *t.Fingerprint, digest *t.Digest) {
	for i := uint16(0); i < c.FINGERPRINT_SIZE; i += 4 {
		dig := digest[:]
		n := numbers.GetUint32(&dig, int(i))
		finger := fingerprint[:]
		numbers.SetUint32(&finger, int(i), n%c.FINGERPRINT_DIVISOR)
	}
}

func CalculateFingerprint(fingerprint *t.Fingerprint, publicKey *t.PublicKey) bool {
	a := [c.DIGEST_SIZE]byte{}
	b := [c.DIGEST_SIZE]byte{}
	external.Hash(&a, publicKey[:])
	for i := 1; i < int(c.FINGERPRINT_ITERATIONS); i += 1 {
		external.Hash(&b, a[:])
		for i := range a {
			a[i] = b[i]
		}
	}
	EncodeFingerprint(fingerprint, &a)
	return true
}

func SetSafetyNumber(safetyNumber *t.SafetyNumber, a *t.Fingerprint, b *t.Fingerprint) {
	for i := range a {
		safetyNumber[i] = a[i]
		safetyNumber[i+int(c.FINGERPRINT_SIZE)] = b[i]
	}
}

func Authenticate(safetyNumber *t.SafetyNumber, state *t.State) bool {
	ourFingerprint := [c.FINGERPRINT_SIZE]byte{}
	theirFingerprint := [c.FINGERPRINT_SIZE]byte{}
	if !CalculateFingerprint(&ourFingerprint, s.GetIdentityPublicKey(state)) {
		return false
	}
	if !CalculateFingerprint(&theirFingerprint, s.GetTheirIdentityKey(state)) {
		return false
	}
	if bytes.Compare(ourFingerprint[:], theirFingerprint[:]) < 0 {
		SetSafetyNumber(safetyNumber, &theirFingerprint, &ourFingerprint)
	} else {
		SetSafetyNumber(safetyNumber, &ourFingerprint, &theirFingerprint)
	}
	return true
}
