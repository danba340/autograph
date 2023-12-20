#ifndef AUTOGRAPH_HASH_H
#define AUTOGRAPH_HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_hash(uint8_t *digest, const uint8_t *message,
                       const uint32_t message_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
