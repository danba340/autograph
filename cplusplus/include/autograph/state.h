#ifndef AUTOGRAPH_STATE_H
#define AUTOGRAPH_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void set_identity_key_pair(uint8_t *state, const uint8_t *key_pair);

const uint8_t *get_identity_key_pair(const uint8_t *state);

const uint8_t *get_identity_public_key(const uint8_t *state);

const uint8_t *get_their_identity_key(const uint8_t *state);

void set_their_identity_key(uint8_t *state, const uint8_t *public_key);

const uint8_t *get_sending_nonce(const uint8_t *state);

const uint8_t *get_sending_key(const uint8_t *state);

const uint8_t *get_receiving_nonce(const uint8_t *state);

const uint8_t *get_receiving_key(const uint8_t *state);

void set_secret_keys(uint8_t *state, bool is_initiator, const uint8_t *okm);

bool increment_sending_index(uint8_t *state);

bool increment_receiving_index(uint8_t *state);

void set_ephemeral_key_pair(uint8_t *state, const uint8_t *key_pair);

const uint8_t *get_ephemeral_private_key(const uint8_t *state);

void delete_ephemeral_private_key(uint8_t *state);

const uint8_t *get_their_ephemeral_key(const uint8_t *state);

void set_their_ephemeral_key(uint8_t *state, const uint8_t *public_key);

void set_transcript(uint8_t *state, bool is_initiator);

const uint8_t *get_transcript(const uint8_t *state);

#ifdef __cplusplus
}
#endif

#endif
