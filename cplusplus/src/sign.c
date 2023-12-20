#include "autograph/sign.h"

#include "autograph/bytes.h"
#include "sodium.h"

uint8_t autograph_sign(uint8_t *signature, const uint8_t *private_key,
                       const uint8_t *message, const uint32_t message_size) {
  uint8_t sk[64];
  uint8_t pk[32];
  uint8_t seed_result =
      crypto_sign_seed_keypair(pk, sk, private_key) == 0 ? 1 : 0;
  uint8_t sign_result =
      crypto_sign_detached(signature, NULL, message, message_size, sk) == 0 ? 1
                                                                            : 0;
  autograph_write_zero(sk, 0, 64);
  return seed_result && sign_result ? 1 : 0;
}

uint8_t autograph_verify(const uint8_t *public_key, const uint8_t *message,
                         const uint32_t message_size,
                         const uint8_t *signature) {
  return crypto_sign_verify_detached(signature, message, message_size,
                                     public_key) == 0
             ? 1
             : 0;
}
