#include "numbers.h"

#include "autograph.h"

uint32_t get_uint32(const uint8_t *bytes, const size_t offset) {
  uint32_t number = ((uint32_t)bytes[offset] << 24) |
                    ((uint32_t)bytes[offset + 1] << 16) |
                    ((uint32_t)bytes[offset + 2] << 8) | bytes[offset + 3];
  return number;
}

void set_uint32(uint8_t *bytes, const size_t offset, const uint32_t number) {
  bytes[offset] = (number >> 24) & 0xFF;
  bytes[offset + 1] = (number >> 16) & 0xFF;
  bytes[offset + 2] = (number >> 8) & 0xFF;
  bytes[offset + 3] = number & 0xFF;
}

uint64_t get_uint64(const uint8_t *bytes, const size_t offset) {
  uint64_t number =
      ((uint64_t)bytes[offset] << 56) | ((uint64_t)bytes[offset + 1] << 48) |
      ((uint64_t)bytes[offset + 2] << 40) |
      ((uint64_t)bytes[offset + 3] << 32) |
      ((uint64_t)bytes[offset + 4] << 24) |
      ((uint64_t)bytes[offset + 5] << 16) | ((uint64_t)bytes[offset + 6] << 8) |
      (uint64_t)bytes[offset + 7];
  return number;
}

void set_uint64(uint8_t *bytes, const size_t offset, const uint64_t number) {
  bytes[offset] = (number >> 56) & 0xFF;
  bytes[offset + 1] = (number >> 48) & 0xFF;
  bytes[offset + 2] = (number >> 40) & 0xFF;
  bytes[offset + 3] = (number >> 32) & 0xFF;
  bytes[offset + 4] = (number >> 24) & 0xFF;
  bytes[offset + 5] = (number >> 16) & 0xFF;
  bytes[offset + 6] = (number >> 8) & 0xFF;
  bytes[offset + 7] = number & 0xFF;
}

uint32_t autograph_read_index(const uint8_t *bytes) {
  return get_uint32(bytes, 0);
}

size_t autograph_read_size(const uint8_t *bytes) {
  return get_uint64(bytes, 0);
}
