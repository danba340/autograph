#ifndef AUTOGRAPH_STATE_H
#define AUTOGRAPH_STATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_abort(uint8_t *state);

void autograph_delete_key(uint8_t *state, const uint16_t offset);

void autograph_init(uint8_t *state);

uint8_t autograph_ratchet_receiving_key(uint8_t *state);

uint8_t autograph_ratchet_sending_key(uint8_t *state);

uint16_t autograph_read_key(uint8_t *index, uint8_t *secret_key, uint8_t *state,
                            const uint16_t offset);

void autograph_read_our_private_key(uint8_t *our_private_key,
                                    const uint8_t *state);

void autograph_read_our_public_key(uint8_t *our_public_key,
                                   const uint8_t *state);

void autograph_read_receiving_index(uint8_t *index, const uint8_t *state);

void autograph_read_receiving_key(uint8_t *secret_key, const uint8_t *state);

void autograph_read_sending_index(uint8_t *index, const uint8_t *state);

void autograph_read_sending_key(uint8_t *secret_key, const uint8_t *state);

void autograph_read_their_public_key(uint8_t *their_public_key,
                                     const uint8_t *state);

uint8_t autograph_skip_key(uint8_t *state);

uint16_t autograph_state_size(const uint8_t *state);

void autograph_write_our_private_key(uint8_t *state,
                                     const uint8_t *private_key);

void autograph_write_our_public_key(uint8_t *state, const uint8_t *public_key);

void autograph_write_receiving_index(uint8_t *state, const uint32_t index);

void autograph_write_receiving_key(uint8_t *state, const uint8_t *key);

void autograph_write_sending_index(uint8_t *state, const uint32_t index);

void autograph_write_sending_key(uint8_t *state, const uint8_t *key);

void autograph_write_their_public_key(uint8_t *state,
                                      const uint8_t *public_key);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
