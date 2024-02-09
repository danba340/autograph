#ifndef AUTOGRAPH_STATE_H
#define AUTOGRAPH_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void set_identity_key_pair(uint8_t *state, const uint8_t *key_pair);

uint8_t *get_identity_key_pair(uint8_t *state);

uint8_t *get_identity_public_key(uint8_t *state);

uint8_t *get_their_identity_key(uint8_t *state);

void set_their_identity_key(uint8_t *state, const uint8_t *public_key);

uint8_t *get_sending_nonce(uint8_t *state);

uint8_t *get_sending_index(uint8_t *state);

uint8_t *get_sending_key(uint8_t *state);

uint8_t *get_receiving_nonce(uint8_t *state);

uint8_t *get_receiving_index(uint8_t *state);

uint8_t *get_receiving_key(uint8_t *state);

void set_secret_keys(uint8_t *state, bool is_initiator, const uint8_t *okm);

bool increment_sending_index(uint8_t *state);

bool increment_receiving_index(uint8_t *state);

void set_ephemeral_key_pair(uint8_t *state, const uint8_t *key_pair);

uint8_t *get_ephemeral_private_key(uint8_t *state);

void delete_ephemeral_private_key(uint8_t *state);

uint8_t *get_their_ephemeral_key(uint8_t *state);

void set_their_ephemeral_key(uint8_t *state, const uint8_t *public_key);

void set_transcript(uint8_t *state, bool is_initiator);

uint8_t *get_transcript(uint8_t *state);

void zeroize_skipped_indexes(uint8_t *state);

bool skip_index(uint8_t *state);

size_t get_skipped_index(uint8_t *index, uint8_t *nonce, const uint8_t *state,
                         const size_t offset);

void delete_skipped_index(uint8_t *state, const size_t next_offset);

#ifdef __cplusplus
}
#endif

#endif
