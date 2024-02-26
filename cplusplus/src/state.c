#include "state.h"

#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "external.h"

void set_identity_key_pair(uint8_t *state, const uint8_t *key_pair) {
  memmove(state + IDENTITY_KEY_PAIR_OFFSET, key_pair, KEY_PAIR_SIZE);
}

const uint8_t *get_identity_key_pair(const uint8_t *state) {
  return state + IDENTITY_KEY_PAIR_OFFSET;
}

const uint8_t *get_identity_public_key(const uint8_t *state) {
  return state + IDENTITY_PUBLIC_KEY_OFFSET;
}

const uint8_t *get_their_identity_key(const uint8_t *state) {
  return state + THEIR_IDENTITY_KEY_OFFSET;
}

void set_their_identity_key(uint8_t *state, const uint8_t *public_key) {
  memmove(state + THEIR_IDENTITY_KEY_OFFSET, public_key, PUBLIC_KEY_SIZE);
}

const uint8_t *get_sending_nonce(const uint8_t *state) {
  return state + SENDING_NONCE_OFFSET;
}

const uint8_t *get_sending_key(const uint8_t *state) {
  return state + SENDING_KEY_OFFSET;
}

const uint8_t *get_receiving_nonce(const uint8_t *state) {
  return state + RECEIVING_NONCE_OFFSET;
}

const uint8_t *get_receiving_key(const uint8_t *state) {
  return state + RECEIVING_KEY_OFFSET;
}

void set_secret_keys(uint8_t *state, bool is_initiator, const uint8_t *okm) {
  if (is_initiator) {
    memmove(state + SENDING_KEY_OFFSET, okm, SECRET_KEY_SIZE);
    memmove(state + RECEIVING_KEY_OFFSET, okm + SECRET_KEY_SIZE,
            SECRET_KEY_SIZE);
  } else {
    memmove(state + SENDING_KEY_OFFSET, okm + SECRET_KEY_SIZE, SECRET_KEY_SIZE);
    memmove(state + RECEIVING_KEY_OFFSET, okm, SECRET_KEY_SIZE);
  }
}

bool increment_index(uint8_t *state, const size_t offset) {
  uint8_t index = state[offset];
  if (index == UINT8_MAX) {
    return false;
  }
  state[offset] = index + 1;
  return true;
}

bool increment_sending_index(uint8_t *state) {
  return increment_index(state, SENDING_INDEX_OFFSET);
}

bool increment_receiving_index(uint8_t *state) {
  return increment_index(state, RECEIVING_INDEX_OFFSET);
}

void set_ephemeral_key_pair(uint8_t *state, const uint8_t *key_pair) {
  memmove(state + EPHEMERAL_KEY_PAIR_OFFSET, key_pair, KEY_PAIR_SIZE);
}

const uint8_t *get_ephemeral_private_key(const uint8_t *state) {
  return state + EPHEMERAL_KEY_PAIR_OFFSET;
}

void delete_ephemeral_private_key(uint8_t *state) {
  zeroize(state + EPHEMERAL_KEY_PAIR_OFFSET, PRIVATE_KEY_SIZE);
}

const uint8_t *get_ephemeral_public_key(const uint8_t *state) {
  return state + EPHEMERAL_PUBLIC_KEY_OFFSET;
}

const uint8_t *get_their_ephemeral_key(const uint8_t *state) {
  return state + THEIR_EPHEMERAL_KEY_OFFSET;
}

void set_their_ephemeral_key(uint8_t *state, const uint8_t *public_key) {
  memmove(state + THEIR_EPHEMERAL_KEY_OFFSET, public_key, PUBLIC_KEY_SIZE);
}

void set_transcript(uint8_t *state, bool is_initiator) {
  if (is_initiator) {
    memmove(state + TRANSCRIPT_OFFSET, get_ephemeral_public_key(state),
            PUBLIC_KEY_SIZE);
    memmove(state + TRANSCRIPT_OFFSET + PUBLIC_KEY_SIZE,
            get_their_ephemeral_key(state), PUBLIC_KEY_SIZE);
  } else {
    memmove(state + TRANSCRIPT_OFFSET, get_their_ephemeral_key(state),
            PUBLIC_KEY_SIZE);
    memmove(state + TRANSCRIPT_OFFSET + PUBLIC_KEY_SIZE,
            get_ephemeral_public_key(state), PUBLIC_KEY_SIZE);
  }
}

const uint8_t *get_transcript(const uint8_t *state) {
  return state + TRANSCRIPT_OFFSET;
}
