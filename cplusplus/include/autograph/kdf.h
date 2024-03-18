#ifndef AUTOGRAPH_KDF_H
#define AUTOGRAPH_KDF_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool kdf(uint8_t *okm, const uint8_t *ikm);

#ifdef __cplusplus
}
#endif

#endif
