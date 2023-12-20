#ifndef AUTOGRAPH_DIFFIE_HELLMAN_H
#define AUTOGRAPH_DIFFIE_HELLMAN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_diffie_hellman(uint8_t *ikm, const uint8_t *our_private_key,
                                 const uint8_t *their_public_key);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
