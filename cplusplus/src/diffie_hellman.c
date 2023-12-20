#include "autograph/diffie_hellman.h"

#include "sodium.h"

uint8_t autograph_diffie_hellman(uint8_t *ikm, const uint8_t *our_private_key,
                                 const uint8_t *their_public_key) {
  return crypto_scalarmult(ikm, our_private_key, their_public_key) == 0 ? 1 : 0;
}
