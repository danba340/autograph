#ifndef AUTOGRAPH_CERT_H
#define AUTOGRAPH_CERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool certify_data_ownership(uint8_t *signature, uint8_t *state,
                            const uint8_t *owner_public_key,
                            const uint8_t *data, const size_t data_size);

bool certify_identity_ownership(uint8_t *signature, uint8_t *state,
                                const uint8_t *owner_public_key);

bool verify_data_ownership(const uint8_t *owner_public_key, const uint8_t *data,
                           const size_t data_size,
                           const uint8_t *certifier_public_key,
                           const uint8_t *signature);

bool verify_identity_ownership(const uint8_t *owner_public_key,
                               const uint8_t *certifier_public_key,
                               const uint8_t *signature);

#ifdef __cplusplus
}
#endif

#endif
