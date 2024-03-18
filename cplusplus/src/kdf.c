#include "kdf.h"

#include "constants.h"
#include "external.h"

bool kdf(uint8_t *okm, const uint8_t *ikm) {
  uint8_t salt[SALT_SIZE] = {0};
  uint8_t info[INFO_SIZE] = INFO;
  return hkdf(okm, OKM_SIZE, ikm, IKM_SIZE, salt, SALT_SIZE, info, INFO_SIZE);
}
