#ifndef AUTOGRAPH_NUMBERS_H
#define AUTOGRAPH_NUMBERS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t get_uint32(const uint8_t *bytes, const size_t offset);

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number);

uint64_t get_uint64(const uint8_t *bytes, const size_t offset);

void set_uint64(uint8_t *bytes, const size_t offset, const uint64_t number);

#ifdef __cplusplus
}
#endif

#endif
