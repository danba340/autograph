#include "autograph.h"
#include "autograph/bytes.h"
#include "autograph/hash.h"
#include "autograph/state.h"

void autograph_encode_fingerprint(uint8_t *fingerprint) {
  uint32_t n;
  for (uint8_t i = 0; i < 32; i += 4) {
    n = autograph_read_uint32(fingerprint, i);
    autograph_write_uint32(fingerprint, i, n % 100000);
  }
}

uint8_t autograph_fingerprint(uint8_t *fingerprint, const uint8_t *public_key) {
  uint8_t in[64];
  uint8_t out[64];
  uint8_t result = autograph_hash(in, public_key, 32);
  if (!result) {
    return 0;
  }
  for (uint16_t i = 1; i < 5200; i++) {
    result = autograph_hash(out, in, 64);
    if (!result) {
      return 0;
    }
    autograph_write(in, 0, out, 0, 64);
  }
  autograph_write(fingerprint, 0, in, 0, 32);
  autograph_encode_fingerprint(fingerprint);
  return 1;
}

uint8_t autograph_our_fingerprint(uint8_t *fingerprint, const uint8_t *state) {
  uint8_t our_public_key[32];
  autograph_read_our_public_key(our_public_key, state);
  return autograph_fingerprint(fingerprint, our_public_key);
}

uint8_t autograph_their_fingerprint(uint8_t *fingerprint,
                                    const uint8_t *state) {
  uint8_t their_public_key[32];
  autograph_read_their_public_key(their_public_key, state);
  return autograph_fingerprint(fingerprint, their_public_key);
}

uint8_t autograph_safety_number(uint8_t *safety_number, const uint8_t *state) {
  uint8_t a[32];
  uint8_t b[32];
  uint8_t our_result = autograph_our_fingerprint(a, state);
  uint8_t their_result = autograph_their_fingerprint(b, state);
  if (!our_result || !their_result) {
    return 0;
  }
  if (autograph_compare(a, b, 32)) {
    autograph_write(safety_number, 0, a, 0, 32);
    autograph_write(safety_number, 32, b, 0, 32);
  } else {
    autograph_write(safety_number, 0, b, 0, 32);
    autograph_write(safety_number, 32, a, 0, 32);
  }
  return 1;
}
