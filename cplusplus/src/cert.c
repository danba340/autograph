#include "cert.h"

#include <string.h>

#include "constants.h"
#include "external.h"
#include "state.h"

size_t calculate_subject_size(const size_t data_size) {
  size_t max_size = UINT32_MAX - PUBLIC_KEY_SIZE;
  size_t size = data_size > max_size ? max_size : data_size;
  return size + PUBLIC_KEY_SIZE;
}

void calculate_subject(uint8_t *subject, const size_t subject_size,
                       const uint8_t *public_key, const uint8_t *data) {
  size_t key_offset = subject_size - PUBLIC_KEY_SIZE;
  memmove(subject, data, key_offset);
  memmove(subject + key_offset, public_key, PUBLIC_KEY_SIZE);
}

bool sign_subject(uint8_t *signature, uint8_t *state, const uint8_t *subject,
                  const size_t subject_size) {
  return sign(signature, get_identity_key_pair(state), subject, subject_size);
}

bool certify_data_ownership(uint8_t *signature, uint8_t *state,
                            const uint8_t *owner_public_key,
                            const uint8_t *data, const size_t data_size) {
  size_t subject_size = calculate_subject_size(data_size);
  uint8_t subject[subject_size];
  calculate_subject(subject, subject_size, owner_public_key, data);
  return sign_subject(signature, state, subject, subject_size);
}

bool certify_identity_ownership(uint8_t *signature, uint8_t *state,
                                const uint8_t *owner_public_key) {
  return sign_subject(signature, state, owner_public_key, PUBLIC_KEY_SIZE);
}

bool verify_data_ownership(const uint8_t *owner_public_key, const uint8_t *data,
                           const size_t data_size,
                           const uint8_t *certifier_public_key,
                           const uint8_t *signature) {
  size_t subject_size = calculate_subject_size(data_size);
  uint8_t subject[subject_size];
  calculate_subject(subject, subject_size, owner_public_key, data);
  return verify(certifier_public_key, signature, subject, subject_size);
}

bool verify_identity_ownership(const uint8_t *owner_public_key,
                               const uint8_t *certifier_public_key,
                               const uint8_t *signature) {
  return verify(certifier_public_key, signature, owner_public_key,
                PUBLIC_KEY_SIZE);
}
