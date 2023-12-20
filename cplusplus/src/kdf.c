#include "autograph/kdf.h"

#include "autograph/bytes.h"
#include "sodium.h"

uint8_t autograph_kdf_extract(uint8_t *prk, const uint8_t *salt,
                              const uint8_t *ikm) {
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, salt, 64);
  crypto_auth_hmacsha512_update(&state, ikm, 32);
  return crypto_auth_hmacsha512_final(&state, prk) == 0 ? 1 : 0;
}

uint8_t autograph_kdf_expand(uint8_t *okm, const uint8_t *prk,
                             const uint8_t *context) {
  crypto_auth_hmacsha512_state state;
  crypto_auth_hmacsha512_init(&state, prk, 64);
  crypto_auth_hmacsha512_update(&state, context, 4);
  uint8_t counter = 1;
  crypto_auth_hmacsha512_update(&state, &counter, 1);
  return crypto_auth_hmacsha512_final(&state, okm) == 0 ? 1 : 0;
}

uint8_t autograph_kdf(uint8_t *secret_key, const uint8_t *ikm,
                      const uint8_t *context) {
  uint8_t okm[64];
  uint8_t prk[64];
  uint8_t salt[64];
  autograph_write_zero(salt, 0, 64);
  uint8_t extract_result = autograph_kdf_extract(prk, salt, ikm);
  uint8_t expand_result = autograph_kdf_expand(okm, prk, context);
  autograph_write(secret_key, 0, okm, 0, 32);
  autograph_write_zero(okm, 0, 64);
  autograph_write_zero(prk, 0, 64);
  return extract_result && expand_result ? 1 : 0;
}
