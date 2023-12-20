#include "autograph/pad.h"

#include "autograph/bytes.h"
#include "sodium.h"

uint8_t autograph_pad(uint8_t *padded, const uint8_t *unpadded,
                      const uint32_t unpadded_size) {
  autograph_write(padded, 0, unpadded, 0, unpadded_size);
  return sodium_pad(NULL, padded, unpadded_size, 16, unpadded_size + 16) == 0
             ? 1
             : 0;
}

uint8_t autograph_unpad(uint8_t *unpadded_size, const uint8_t *padded,
                        const uint32_t padded_size) {
  size_t size;
  int result = sodium_unpad(&size, padded, padded_size, 16);
  autograph_write_uint32(unpadded_size, 0, size);
  return result == 0 ? 1 : 0;
}
