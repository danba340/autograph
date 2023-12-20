#ifndef AUTOGRAPH_PAD_H
#define AUTOGRAPH_PAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_pad(uint8_t *padded, const uint8_t *unpadded,
                      const uint32_t unpadded_size);

uint8_t autograph_unpad(uint8_t *unpadded_size, const uint8_t *padded,
                        const uint32_t padded_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
