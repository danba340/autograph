#ifndef AUTOGRAPH_SIZES_H
#define AUTOGRAPH_SIZES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t autograph_padded_size(const uint32_t plaintext_size);

uint32_t autograph_subject_size(const uint32_t data_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
