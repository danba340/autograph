#include "autograph/bytes.h"

#include <string.h>

#include "autograph.h"
#include "sodium.h"

uint8_t autograph_compare(const uint8_t *a, const uint8_t *b,
                          const uint16_t size) {
  return memcmp(a, b, size) > 0 ? 1 : 0;
}

uint32_t autograph_read_index(const uint8_t *bytes) {
  return autograph_read_uint32(bytes, 0);
}

uint32_t autograph_read_size(const uint8_t *bytes) {
  return autograph_read_uint32(bytes, 0);
}

uint32_t autograph_read_uint32(const uint8_t *dest, const uint16_t offset) {
  uint32_t number = ((uint32_t)dest[offset] << 24) |
                    ((uint32_t)dest[offset + 1] << 16) |
                    ((uint32_t)dest[offset + 2] << 8) | dest[offset + 3];
  return number;
}

void autograph_write(uint8_t *dest, const uint16_t dest_offset,
                     const uint8_t *src, const uint16_t src_offset,
                     const uint32_t size) {
  memmove(dest + dest_offset, src + src_offset, size);
}

void autograph_write_uint32(uint8_t *dest, const uint16_t offset,
                            const uint32_t number) {
  dest[offset] = (number >> 24) & 0xFF;
  dest[offset + 1] = (number >> 16) & 0xFF;
  dest[offset + 2] = (number >> 8) & 0xFF;
  dest[offset + 3] = number & 0xFF;
}

void autograph_write_zero(uint8_t *dest, const uint16_t offset,
                          const uint32_t size) {
  sodium_memzero(dest + offset, size);
}
