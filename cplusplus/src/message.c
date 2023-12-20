#include "autograph.h"
#include "autograph/bytes.h"
#include "autograph/cipher.h"
#include "autograph/pad.h"
#include "autograph/sizes.h"
#include "autograph/state.h"

uint8_t autograph_decrypt_ciphertext(uint8_t *plaintext,
                                     uint8_t *plaintext_size,
                                     const uint8_t *key,
                                     const uint8_t *ciphertext,
                                     const uint32_t ciphertext_size) {
  uint8_t decrypt_result =
      autograph_decrypt(plaintext, key, ciphertext, ciphertext_size);
  uint8_t pad_result =
      autograph_unpad(plaintext_size, plaintext, ciphertext_size - 16);
  return decrypt_result && pad_result ? 1 : 0;
}

uint8_t autograph_decrypt_skipped(uint8_t *plaintext, uint8_t *plaintext_size,
                                  uint8_t *index, uint8_t *state,
                                  const uint8_t *ciphertext,
                                  const uint32_t ciphertext_size) {
  uint8_t key[32];
  uint16_t offset = autograph_read_key(index, key, state, 0);
  while (offset > 0) {
    if (autograph_decrypt_ciphertext(plaintext, plaintext_size, key, ciphertext,
                                     ciphertext_size)) {
      autograph_delete_key(state, offset);
      autograph_write_zero(key, 0, 32);
      return 1;
    }
    offset = autograph_read_key(index, key, state, offset);
  }
  autograph_write_zero(key, 0, 32);
  return 0;
}

uint8_t autograph_decrypt_current(uint8_t *plaintext, uint8_t *plaintext_size,
                                  const uint8_t *state,
                                  const uint8_t *ciphertext,
                                  const uint32_t ciphertext_size) {
  uint8_t key[32];
  autograph_read_receiving_key(key, state);
  uint8_t result = autograph_decrypt_ciphertext(plaintext, plaintext_size, key,
                                                ciphertext, ciphertext_size);
  autograph_write_zero(key, 0, 32);
  return result;
}

uint8_t autograph_decrypt_message(uint8_t *plaintext, uint8_t *plaintext_size,
                                  uint8_t *index, uint8_t *state,
                                  const uint8_t *ciphertext,
                                  const uint32_t ciphertext_size) {
  uint8_t result = autograph_decrypt_skipped(
      plaintext, plaintext_size, index, state, ciphertext, ciphertext_size);
  while (!result) {
    if (!autograph_ratchet_receiving_key(state)) {
      return autograph_abort(state);
    }
    result = autograph_decrypt_current(plaintext, plaintext_size, state,
                                       ciphertext, ciphertext_size);
    if (result) {
      autograph_read_receiving_index(index, state);
    } else {
      if (!autograph_skip_key(state)) {
        return autograph_abort(state);
      }
    }
  }
  return result;
}

uint8_t autograph_encrypt_message(uint8_t *ciphertext, uint8_t *index,
                                  uint8_t *state, const uint8_t *plaintext,
                                  const uint32_t plaintext_size) {
  if (!autograph_ratchet_sending_key(state)) {
    return autograph_abort(state);
  }
  uint8_t key[32];
  autograph_read_sending_index(index, state);
  autograph_read_sending_key(key, state);
  uint32_t padded_size = autograph_padded_size(plaintext_size);
  uint8_t padded[padded_size];
  uint8_t pad_result = autograph_pad(padded, plaintext, plaintext_size);
  uint8_t encrypt_result =
      autograph_encrypt(ciphertext, key, padded, padded_size);
  autograph_write_zero(key, 0, 32);
  return pad_result && encrypt_result ? 1 : autograph_abort(state);
}
