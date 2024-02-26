#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "autograph.h"
#include "cert.h"
#include "constants.h"
#include "external.h"
#include "state.h"

size_t calculate_padded_size(const size_t plaintext_size) {
  return plaintext_size + PADDING_BLOCK_SIZE -
         (plaintext_size % PADDING_BLOCK_SIZE);
}

void pad(uint8_t *padded, const size_t padded_size, const uint8_t *plaintext,
         const size_t plaintext_size) {
  zeroize(padded, padded_size);
  memmove(padded, plaintext, plaintext_size);
  padded[plaintext_size] = PADDING_BYTE;
}

bool encrypt_plaintext(uint8_t *ciphertext, const uint8_t *key,
                       const uint8_t *nonce, const uint8_t *plaintext,
                       const size_t plaintext_size) {
  size_t padded_size = calculate_padded_size(plaintext_size);
  uint8_t padded[padded_size];
  pad(padded, padded_size, plaintext, plaintext_size);
  return encrypt(ciphertext, key, nonce, padded, padded_size);
}

bool autograph_encrypt_message(uint8_t *ciphertext, uint8_t *state,
                               const uint8_t *plaintext,
                               const size_t plaintext_size) {
  if (!increment_sending_index(state)) {
    zeroize(state, STATE_SIZE);
    return false;
  }
  if (!encrypt_plaintext(ciphertext, get_sending_key(state),
                         get_sending_nonce(state), plaintext, plaintext_size)) {
    zeroize(state, STATE_SIZE);
    return false;
  }
  return true;
}

size_t calculate_unpadded_size(const uint8_t *padded,
                               const size_t padded_size) {
  if (padded_size == 0 || (padded_size % PADDING_BLOCK_SIZE) > 0) {
    return 0;
  }
  for (uint8_t i = padded_size - 1; i >= (padded_size - PADDING_BLOCK_SIZE);
       --i) {
    uint8_t byte = padded[i];
    if (byte == PADDING_BYTE) {
      return i;
    }
    if (byte != 0) {
      return 0;
    }
  }
  return 0;
}

bool unpad(size_t *unpadded_size, const uint8_t *padded,
           const size_t padded_size) {
  size_t size = calculate_unpadded_size(padded, padded_size);
  if (size == 0) {
    return false;
  }
  *unpadded_size = size;
  return true;
}

size_t autograph_ciphertext_size(const size_t plaintext_size) {
  return calculate_padded_size(plaintext_size) + TAG_SIZE;
}

size_t autograph_plaintext_size(const size_t ciphertext_size) {
  return ciphertext_size - TAG_SIZE;
}

bool autograph_decrypt_message(uint8_t *plaintext, size_t *plaintext_size,
                               uint8_t *state, const uint8_t *ciphertext,
                               const size_t ciphertext_size) {
  if (!increment_receiving_index(state)) {
    zeroize(state, STATE_SIZE);
    return false;
  }
  if (decrypt(plaintext, get_receiving_key(state), get_receiving_nonce(state),
              ciphertext, ciphertext_size)) {
    return unpad(plaintext_size, plaintext,
                 autograph_plaintext_size(ciphertext_size));
  }
  return false;
}
