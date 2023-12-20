#ifndef AUTOGRAPH_KDF_H
#define AUTOGRAPH_KDF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_kdf(uint8_t *secret_key, const uint8_t *ikm,
                      const uint8_t *context);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
