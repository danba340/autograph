#include "autograph.h"
#include "autograph/bytes.h"
#include "sodium.h"

uint8_t autograph_ephemeral_key_pair(uint8_t *private_key,
                                     uint8_t *public_key) {
  if (sodium_init() < 0) {
    return 0;
  }
  return crypto_box_keypair(public_key, private_key) == 0 ? 1 : 0;
}

uint8_t autograph_identity_key_pair(uint8_t *private_key, uint8_t *public_key) {
  if (sodium_init() < 0) {
    return 0;
  }
  uint8_t sk[64];
  uint8_t result = crypto_sign_keypair(public_key, sk) == 0 ? 1 : 0;
  autograph_write(private_key, 0, sk, 0, 32);
  autograph_write_zero(sk, 0, 64);
  return result;
}
