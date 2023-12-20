#ifndef AUTOGRAPH_CIPHER_H
#define AUTOGRAPH_CIPHER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_decrypt(uint8_t *plaintext, const uint8_t *secret_key,
                          const uint8_t *ciphertext,
                          const uint32_t ciphertext_size);

uint8_t autograph_encrypt(uint8_t *ciphertext, const uint8_t *secret_key,
                          const uint8_t *plaintext,
                          const uint32_t plaintext_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
