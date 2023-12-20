#ifndef AUTOGRAPH_SIGN_H
#define AUTOGRAPH_SIGN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_sign(uint8_t *signature, const uint8_t *private_key,
                       const uint8_t *message, const uint32_t message_size);

uint8_t autograph_verify(const uint8_t *public_key, const uint8_t *message,
                         const uint32_t message_size, const uint8_t *signature);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
