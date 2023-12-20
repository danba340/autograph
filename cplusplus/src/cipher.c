#include "autograph/cipher.h"

#include "autograph/bytes.h"
#include "sodium.h"

uint8_t autograph_decrypt(uint8_t *plaintext, const uint8_t *key,
                          const uint8_t *ciphertext,
                          const uint32_t ciphertext_size) {
  uint8_t nonce[12];
  autograph_write_zero(nonce, 0, 12);
  return crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, NULL, NULL,
                                                   ciphertext, ciphertext_size,
                                                   NULL, 0, nonce, key) == 0
             ? 1
             : 0;
}

uint8_t autograph_encrypt(uint8_t *ciphertext, const uint8_t *key,
                          const uint8_t *plaintext,
                          const uint32_t plaintext_size) {
  uint8_t nonce[12];
  autograph_write_zero(nonce, 0, 12);
  return crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, plaintext,
                                                   plaintext_size, NULL, 0,
                                                   NULL, nonce, key) == 0
             ? 1
             : 0;
}
