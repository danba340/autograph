#include "autograph/hash.h"

#include "sodium.h"

uint8_t autograph_hash(uint8_t *digest, const uint8_t *message,
                       const uint32_t message_size) {
  return crypto_hash_sha512(digest, message, message_size) == 0 ? 1 : 0;
}
