#include "autograph.h"
#include "autograph/bytes.h"
#include "autograph/sign.h"
#include "autograph/sizes.h"
#include "autograph/state.h"

void autograph_subject(uint8_t *subject, const uint32_t subject_size,
                       const uint8_t *state, const uint8_t *data) {
  uint8_t their_public_key[32];
  uint32_t public_key_offset = subject_size - 32;
  autograph_read_their_public_key(their_public_key, state);
  autograph_write(subject, 0, data, 0, public_key_offset);
  autograph_write(subject, public_key_offset, their_public_key, 0, 32);
}

uint8_t autograph_sign_subject(uint8_t *signature, const uint8_t *state,
                               const uint8_t *subject,
                               const uint32_t subject_size) {
  uint8_t our_private_key[32];
  autograph_read_our_private_key(our_private_key, state);
  uint8_t result =
      autograph_sign(signature, our_private_key, subject, subject_size);
  autograph_write_zero(our_private_key, 0, 32);
  return result;
}

uint8_t autograph_certify_data(uint8_t *signature, const uint8_t *state,
                               const uint8_t *data, const uint32_t data_size) {
  uint32_t subject_size = autograph_subject_size(data_size);
  uint8_t subject[subject_size];
  autograph_subject(subject, subject_size, state, data);
  return autograph_sign_subject(signature, state, subject, subject_size);
}

uint8_t autograph_certify_identity(uint8_t *signature, const uint8_t *state) {
  uint8_t their_public_key[32];
  autograph_read_their_public_key(their_public_key, state);
  return autograph_sign_subject(signature, state, their_public_key, 32);
}

uint8_t autograph_verify_data(const uint8_t *state, const uint8_t *data,
                              const uint32_t data_size,
                              const uint8_t *public_key,
                              const uint8_t *signature) {
  uint32_t subject_size = autograph_subject_size(data_size);
  uint8_t subject[subject_size];
  autograph_subject(subject, subject_size, state, data);
  return autograph_verify(public_key, subject, subject_size, signature);
}

uint8_t autograph_verify_identity(const uint8_t *state,
                                  const uint8_t *public_key,
                                  const uint8_t *signature) {
  uint8_t their_public_key[32];
  autograph_read_their_public_key(their_public_key, state);
  return autograph_verify(public_key, their_public_key, 32, signature);
}
