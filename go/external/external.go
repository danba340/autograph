package external

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"io"

	c "github.com/christoffercarlsson/autograph/constants"
	t "github.com/christoffercarlsson/autograph/types"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func Init() bool {
	return true
}

func Encrypt(cipherText *[]byte, key *t.SecretKey, nonce *t.Nonce, plaintext *[]byte) bool {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false
	}
	result := aead.Seal([]byte{}, nonce[:], *plaintext, nil)
	copy(*cipherText, result)
	return true
}

func Decrypt(plainText *[]byte, key *t.SecretKey, nonce *t.Nonce, cipherText *[]byte) bool {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false
	}
	result, err := aead.Open([]byte{}, nonce[:], *cipherText, nil)
	if err != nil {
		return false
	}
	for i := range len(result) {
		(*plainText)[i] = result[i]
	}
	*plainText = (*plainText)[:len(result)]
	return true
}

func DiffieHellman(
	sharedSecretRef *t.SharedSecret,
	ourPrivateKey *t.PrivateKey,
	theirPublicKey *t.PublicKey,
) bool {
	sharedSecret, err := curve25519.X25519(ourPrivateKey[:], theirPublicKey[:])
	if err != nil {
		return false
	}
	for i := range sharedSecretRef {
		sharedSecretRef[i] = sharedSecret[i]
		sharedSecret[i] = 0 // zeroize
	}
	return true
}

func CreateKeyPair(keyPair *t.KeyPair, privateKey *t.PrivateKey, publicKey *t.PublicKey) {
	for i := range privateKey {
		keyPair[i] = privateKey[i]
		privateKey[i] = 0 // zeroize
		keyPair[i+int(c.PRIVATE_KEY_SIZE)] = publicKey[i]
		publicKey[i] = 0 // zeroize
	}
}

func KeyPairEphemeral(keyPair *t.KeyPair) bool {
	var private, public [32]byte

	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return false
	}

	curve25519.ScalarBaseMult(&public, &private)
	for i := range private {
		keyPair[i] = private[i]
		private[i] = 0 // zeroize
		keyPair[i+int(c.PRIVATE_KEY_SIZE)] = public[i]
		public[i] = 0 // zeroize
	}
	return true
}

func KeyPairIdentity(keyPair *t.KeyPair) bool {
	pub, privSeed64, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	var privSeed32 = [32]byte(privSeed64)
	var privateKey = [32]byte(ed25519.NewKeyFromSeed(privSeed32[:]))
	var publicKey = [32]byte(pub)
	CreateKeyPair(keyPair, &privateKey, &publicKey)
	// zeroize
	for i := range privSeed64 {
		privSeed64[i] = 0
		if i < 32 {
			privSeed32[i] = 0
			pub[i] = 0
			privateKey[i] = 0
			publicKey[i] = 0
		}
	}
	return true
}

func Sign(signature *t.Signature, keyPair *t.KeyPair, message *[]byte) bool {
	key := ed25519.NewKeyFromSeed(keyPair[:32])
	signed := ed25519.Sign(key, *message)
	for i := range signature {
		signature[i] = signed[i]
	}
	return true
}

func Verify(publicKey *t.PublicKey, signature *t.Signature, message *[]byte) bool {
	return ed25519.Verify(publicKey[:], *message, signature[:])
}

func Hash(digest *t.Digest, message []byte) bool {
	result := sha512.Sum512(message)
	for i := range digest {
		digest[i] = result[i]
	}
	return true
}

func Hkdf(okm *[]byte, ikm *[]byte, salt *[]byte, info *[]byte) bool {
	hkdf := hkdf.New(sha512.New, *ikm, *salt, *info)
	_, err := io.ReadFull(hkdf, (*okm))
	return err == nil
}
