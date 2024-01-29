#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "autograph.h"
#include "cert.h"
#include "constants.h"
#include "external.h"
#include "kdf.h"
#include "numbers.h"
#include "state.h"

bool autograph_use_key_pairs(uint8_t *public_keys, uint8_t *state,
                             const uint8_t *identity_key_pair,
                             const uint8_t *ephemeral_key_pair) {
  zeroize(state, STATE_SIZE);
  if (!init()) {
    return false;
  }
  set_identity_key_pair(state, identity_key_pair);
  set_ephemeral_key_pair(state, ephemeral_key_pair);
  memmove(public_keys, identity_key_pair + PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE);
  memmove(public_keys + PUBLIC_KEY_SIZE, ephemeral_key_pair + PRIVATE_KEY_SIZE,
          PUBLIC_KEY_SIZE);
  return true;
}

void autograph_use_public_keys(uint8_t *state, const uint8_t *public_keys) {
  set_their_identity_key(state, public_keys);
  set_their_ephemeral_key(state, public_keys + PUBLIC_KEY_SIZE);
}

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

bool autograph_encrypt_message(uint8_t *ciphertext, uint8_t *index,
                               uint8_t *state, const uint8_t *plaintext,
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
  memmove(index, get_sending_index(state), INDEX_SIZE);
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

bool unpad(uint8_t *unpadded_size, const uint8_t *padded,
           const size_t padded_size) {
  size_t size = calculate_unpadded_size(padded, padded_size);
  if (size == 0) {
    return false;
  }
  set_uint64(unpadded_size, 0, (uint64_t)size);
  return true;
}

size_t autograph_ciphertext_size(const size_t plaintext_size) {
  return calculate_padded_size(plaintext_size) + TAG_SIZE;
}

size_t autograph_plaintext_size(const size_t ciphertext_size) {
  return ciphertext_size - TAG_SIZE;
}

bool decrypt_ciphertext(uint8_t *plaintext, uint8_t *plaintext_size,
                        const uint8_t *key, const uint8_t *nonce,
                        const uint8_t *ciphertext,
                        const size_t ciphertext_size) {
  if (decrypt(plaintext, key, nonce, ciphertext, ciphertext_size)) {
    return unpad(plaintext_size, plaintext,
                 autograph_plaintext_size(ciphertext_size));
  }
  return false;
}

bool decrypt_current(uint8_t *plaintext, uint8_t *plaintext_size,
                     uint8_t *state, const uint8_t *ciphertext,
                     const size_t ciphertext_size) {
  return decrypt_ciphertext(plaintext, plaintext_size, get_receiving_key(state),
                            get_receiving_nonce(state), ciphertext,
                            ciphertext_size);
}

bool decrypt_skipped(uint8_t *plaintext, uint8_t *plaintext_size,
                     uint8_t *index, uint8_t *state, const uint8_t *ciphertext,
                     const size_t ciphertext_size) {
  uint8_t *key = get_receiving_key(state);
  uint8_t nonce[NONCE_SIZE];
  size_t offset = get_skipped_index(index, nonce, state, 0);
  while (offset > 0) {
    if (decrypt_ciphertext(plaintext, plaintext_size, key, nonce, ciphertext,
                           ciphertext_size)) {
      delete_skipped_index(state, offset);
      return true;
    }
    offset = get_skipped_index(index, nonce, state, offset);
  }
  return false;
}

bool autograph_decrypt_message(uint8_t *plaintext, uint8_t *plaintext_size,
                               uint8_t *index, uint8_t *state,
                               const uint8_t *ciphertext,
                               const size_t ciphertext_size) {
  bool success = decrypt_skipped(plaintext, plaintext_size, index, state,
                                 ciphertext, ciphertext_size);
  while (!success) {
    if (!increment_receiving_index(state)) {
      zeroize(state, STATE_SIZE);
      return false;
    }
    success = decrypt_current(plaintext, plaintext_size, state, ciphertext,
                              ciphertext_size);
    if (success) {
      memmove(index, get_receiving_index(state), INDEX_SIZE);
    } else if (!skip_index(state)) {
      zeroize(state, STATE_SIZE);
      return false;
    }
  }
  return true;
}

bool autograph_certify_data(uint8_t *signature, uint8_t *state,
                            const uint8_t *data, const size_t data_size) {
  return certify_data_ownership(signature, state, get_their_identity_key(state),
                                data, data_size);
}

bool autograph_certify_identity(uint8_t *signature, uint8_t *state) {
  return certify_identity_ownership(signature, state,
                                    get_their_identity_key(state));
}

bool autograph_verify_data(uint8_t *state, const uint8_t *data,
                           const size_t data_size, const uint8_t *public_key,
                           const uint8_t *signature) {
  return verify_data_ownership(get_their_identity_key(state), data, data_size,
                               public_key, signature);
}

bool autograph_verify_identity(uint8_t *state, const uint8_t *public_key,
                               const uint8_t *signature) {
  return verify_identity_ownership(get_their_identity_key(state), public_key,
                                   signature);
}

bool derive_session_key(uint8_t *key, uint8_t *state) {
  uint8_t okm[OKM_SIZE];
  bool success = kdf(okm, get_sending_key(state));
  if (success) {
    memmove(key, okm, SECRET_KEY_SIZE);
  }
  zeroize(okm, OKM_SIZE);
  return success;
}

bool autograph_close_session(uint8_t *key, uint8_t *ciphertext,
                             uint8_t *state) {
  if (!derive_session_key(key, state)) {
    zeroize(state, STATE_SIZE);
    return false;
  }
  size_t plaintext_size = autograph_session_size(state);
  uint8_t plaintext[plaintext_size];
  memmove(plaintext, state, plaintext_size);
  uint8_t nonce[NONCE_SIZE];
  zeroize(nonce, NONCE_SIZE);
  bool success =
      encrypt_plaintext(ciphertext, key, nonce, plaintext, plaintext_size);
  zeroize(state, STATE_SIZE);
  zeroize(plaintext, plaintext_size);
  return success;
}

bool autograph_open_session(uint8_t *state, uint8_t *key,
                            const uint8_t *ciphertext,
                            const size_t ciphertext_size) {
  zeroize(state, STATE_SIZE);
  size_t padded_size = autograph_plaintext_size(ciphertext_size);
  uint8_t plaintext[padded_size];
  uint8_t plaintext_size[SIZE_SIZE];
  uint8_t nonce[NONCE_SIZE];
  zeroize(nonce, NONCE_SIZE);
  bool success = decrypt_ciphertext(plaintext, plaintext_size, key, nonce,
                                    ciphertext, ciphertext_size);
  zeroize(key, SECRET_KEY_SIZE);
  if (success) {
    memmove(state, plaintext, autograph_read_size(plaintext_size));
  }
  return success;
}
