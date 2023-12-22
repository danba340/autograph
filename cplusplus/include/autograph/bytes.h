#ifndef AUTOGRAPH_BYTES_H
#define AUTOGRAPH_BYTES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_compare(const uint8_t *a, const uint8_t *b,
                          const uint16_t size);

uint32_t autograph_read_uint32(const uint8_t *dest, const uint16_t offset);

void autograph_write(uint8_t *dest, const uint16_t dest_offset,
                     const uint8_t *src, const uint16_t src_offset,
                     const uint32_t size);

void autograph_write_uint32(uint8_t *dest, const uint16_t offset,
                            const uint32_t number);

void autograph_write_zero(uint8_t *dest, const uint16_t offset,
                          const uint32_t size);

#ifdef __cplusplus
}  // extern "C"

#include <vector>

namespace Autograph {

using Bytes = std::vector<uint8_t>;

Bytes createCiphertext(const Bytes &plaintext);

Bytes createHandshake();

Bytes createIndex();

Bytes createPlaintext(const Bytes &ciphertext);

Bytes createPrivateKey();

Bytes createPublicKey();

Bytes createSafetyNumber();

Bytes createSecretKey();

Bytes createSession(const Bytes &state);

Bytes createSignature();

Bytes createSize();

uint32_t readIndex(const Bytes &bytes);

void resize(Bytes &bytes, const Bytes &sizeBytes);

}  // namespace Autograph

#endif

#endif
