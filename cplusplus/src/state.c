#include "state.h"

#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"
#include "numbers.h"

void set_identity_key_pair(uint8_t *state, const uint8_t *key_pair) {
  memmove(state + IDENTITY_KEY_PAIR_OFFSET, key_pair, KEY_PAIR_SIZE);
}

uint8_t *get_identity_key_pair(uint8_t *state) {
  return state + IDENTITY_KEY_PAIR_OFFSET;
}

uint8_t *get_identity_public_key(uint8_t *state) {
  return state + IDENTITY_PUBLIC_KEY_OFFSET;
}

uint8_t *get_their_identity_key(uint8_t *state) {
  return state + THEIR_IDENTITY_KEY_OFFSET;
}

void set_their_identity_key(uint8_t *state, const uint8_t *public_key) {
  memmove(get_their_identity_key(state), public_key, PUBLIC_KEY_SIZE);
}

uint8_t *get_sending_nonce(uint8_t *state) {
  return state + SENDING_NONCE_OFFSET;
}

uint8_t *get_sending_index(uint8_t *state) {
  return state + SENDING_INDEX_OFFSET;
}

uint8_t *get_sending_key(uint8_t *state) { return state + SENDING_KEY_OFFSET; }

uint8_t *get_receiving_nonce(uint8_t *state) {
  return state + RECEIVING_NONCE_OFFSET;
}

uint8_t *get_receiving_index(uint8_t *state) {
  return state + RECEIVING_INDEX_OFFSET;
}

uint8_t *get_receiving_key(uint8_t *state) {
  return state + RECEIVING_KEY_OFFSET;
}

void set_secret_keys(uint8_t *state, bool is_initiator, const uint8_t *okm) {
  if (is_initiator) {
    memmove(get_sending_key(state), okm, SECRET_KEY_SIZE);
    memmove(get_receiving_key(state), okm + SECRET_KEY_SIZE, SECRET_KEY_SIZE);
  } else {
    memmove(get_sending_key(state), okm + SECRET_KEY_SIZE, SECRET_KEY_SIZE);
    memmove(get_receiving_key(state), okm, SECRET_KEY_SIZE);
  }
}

bool increment_index(uint8_t *state, const size_t offset) {
  uint32_t index = get_uint32(state, offset);
  if (index == UINT32_MAX) {
    return false;
  }
  set_uint32(state, offset, index + 1);
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

uint8_t *get_ephemeral_private_key(uint8_t *state) {
  return state + EPHEMERAL_KEY_PAIR_OFFSET;
}

void delete_ephemeral_private_key(uint8_t *state) {
  zeroize(state + EPHEMERAL_KEY_PAIR_OFFSET, PRIVATE_KEY_SIZE);
}

uint8_t *get_ephemeral_public_key(uint8_t *state) {
  return state + EPHEMERAL_PUBLIC_KEY_OFFSET;
}

uint8_t *get_their_ephemeral_key(uint8_t *state) {
  return state + THEIR_EPHEMERAL_KEY_OFFSET;
}

void set_their_ephemeral_key(uint8_t *state, const uint8_t *public_key) {
  memmove(get_their_ephemeral_key(state), public_key, PUBLIC_KEY_SIZE);
}

void zeroize_skipped_indexes(uint8_t *state) {
  zeroize(state + SKIPPED_INDEXES_MIN_OFFSET,
          STATE_SIZE - SKIPPED_INDEXES_MIN_OFFSET);
}

size_t autograph_session_size(const uint8_t *state) {
  if (get_uint32(state, SKIPPED_INDEXES_MAX_OFFSET) > 0) {
    return STATE_SIZE;
  }
  size_t offset = SKIPPED_INDEXES_MIN_OFFSET;
  while (offset < SKIPPED_INDEXES_MAX_OFFSET) {
    if (get_uint32(state, offset) == 0) {
      return offset;
    }
    offset += INDEX_SIZE;
  }
  return STATE_SIZE;
}

bool skip_index(uint8_t *state) {
  size_t offset = autograph_session_size(state);
  if (offset > SKIPPED_INDEXES_MAX_OFFSET) {
    return false;
  }
  memmove(state + offset, get_receiving_index(state), INDEX_SIZE);
  return true;
}

size_t get_skipped_index(uint8_t *index, uint8_t *nonce, const uint8_t *state,
                         const size_t offset) {
  size_t o;
  if (offset == 0) {
    zeroize(nonce, NONCE_SIZE);
    o = SKIPPED_INDEXES_MIN_OFFSET;
  } else {
    o = offset;
  }
  if (o > SKIPPED_INDEXES_MAX_OFFSET) {
    return 0;
  }
  memmove(index, state + o, INDEX_SIZE);
  memmove(nonce + NONCE_SIZE - INDEX_SIZE, state + o, INDEX_SIZE);
  return o + INDEX_SIZE;
}

void delete_skipped_index(uint8_t *state, const size_t next_offset) {
  size_t session_size = autograph_session_size(state);
  size_t offset = next_offset - INDEX_SIZE;
  size_t last_offset = session_size - INDEX_SIZE;
  if (offset != last_offset) {
    memmove(state + offset, state + last_offset, INDEX_SIZE);
  }
  zeroize(state + last_offset, STATE_SIZE - last_offset);
}
