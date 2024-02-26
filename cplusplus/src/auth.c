#include <string.h>

#include "constants.h"
#include "external.h"
#include "state.h"

uint32_t get_uint32(const uint8_t *bytes, const size_t offset) {
  uint32_t number = ((uint32_t)bytes[offset] << 24) |
                    ((uint32_t)bytes[offset + 1] << 16) |
                    ((uint32_t)bytes[offset + 2] << 8) | bytes[offset + 3];
  return number;
}

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number) {
  bytes[offset] = (number >> 24) & 0xFF;
  bytes[offset + 1] = (number >> 16) & 0xFF;
  bytes[offset + 2] = (number >> 8) & 0xFF;
  bytes[offset + 3] = number & 0xFF;
}

void encode_fingerprint(uint8_t *fingerprint, const uint8_t *digest) {
  for (uint8_t i = 0; i < FINGERPRINT_SIZE; i += 4) {
    uint32_t n = get_uint32(digest, i);
    set_uint32(fingerprint, i, n % FINGERPRINT_DIVISOR);
  }
}

bool calculate_fingerprint(uint8_t *fingerprint, const uint8_t *public_key) {
  uint8_t a[DIGEST_SIZE];
  uint8_t b[DIGEST_SIZE];
  if (!hash(a, public_key, PUBLIC_KEY_SIZE)) {
    return false;
  }
  for (uint16_t i = 1; i < FINGERPRINT_ITERATIONS; i++) {
    if (!hash(b, a, DIGEST_SIZE)) {
      return false;
    }
    memmove(a, b, DIGEST_SIZE);
  }
  encode_fingerprint(fingerprint, a);
  return true;
}

void set_safety_number(uint8_t *safety_number, uint8_t *a, uint8_t *b) {
  memmove(safety_number, a, FINGERPRINT_SIZE);
  memmove(safety_number + FINGERPRINT_SIZE, b, FINGERPRINT_SIZE);
}

bool autograph_safety_number(uint8_t *safety_number, const uint8_t *state) {
  uint8_t our_fingerprint[FINGERPRINT_SIZE];
  uint8_t their_fingerprint[FINGERPRINT_SIZE];
  if (!calculate_fingerprint(our_fingerprint, get_identity_public_key(state))) {
    return false;
  }
  if (!calculate_fingerprint(their_fingerprint,
                             get_their_identity_key(state))) {
    return false;
  }
  if (memcmp(their_fingerprint, our_fingerprint, FINGERPRINT_SIZE) > 0) {
    set_safety_number(safety_number, their_fingerprint, our_fingerprint);
  } else {
    set_safety_number(safety_number, our_fingerprint, their_fingerprint);
  }
  return true;
}
