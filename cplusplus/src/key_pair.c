#include "autograph.h"
#include "external.h"

bool autograph_identity_key_pair(uint8_t *key_pair) {
  if (!init()) {
    return false;
  }
  return key_pair_identity(key_pair);
}

bool autograph_key_pair(uint8_t *key_pair) {
  if (!init()) {
    return false;
  }
  return key_pair_ephemeral(key_pair);
}
