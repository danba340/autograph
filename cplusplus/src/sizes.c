#include "autograph.h"
#include "autograph/bytes.h"
#include "autograph/state.h"

uint32_t autograph_padded_size(const uint32_t plaintext_size) {
  uint32_t limit = UINT32_MAX - 16;
  if (plaintext_size > limit) {
    return limit;
  }
  return plaintext_size + 16 - plaintext_size % 16;
}

uint32_t autograph_ciphertext_size(const uint32_t plaintext_size) {
  return autograph_padded_size(plaintext_size) + 16;
}

uint32_t autograph_plaintext_size(const uint32_t ciphertext_size) {
  return ciphertext_size - 16;
}

uint16_t autograph_session_size(const uint8_t *state) {
  uint16_t size = autograph_state_size(state);
  return autograph_ciphertext_size(size);
}

uint32_t autograph_subject_size(const uint32_t data_size) {
  if (data_size > UINT32_MAX - 32) {
    return UINT32_MAX;
  }
  return data_size + 32;
}
