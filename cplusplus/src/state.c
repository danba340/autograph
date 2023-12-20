#include "autograph/state.h"

#include "autograph/bytes.h"
#include "autograph/kdf.h"

uint8_t autograph_abort(uint8_t *state) {
  autograph_init(state);
  return 0;
}

uint16_t autograph_next_key_offset(const uint8_t *state) {
  uint32_t index;
  uint16_t offset;
  for (offset = 168; offset < 9312; offset += 36) {
    index = autograph_read_uint32(state, offset);
    if (index == 0) {
      return offset;
    }
  }
  return offset;
}

uint16_t autograph_last_key_offset(const uint8_t *state) {
  uint16_t offset = autograph_next_key_offset(state);
  if (autograph_read_uint32(state, offset) > 0) {
    return offset;
  }
  return offset == 168 ? offset : offset - 36;
}

void autograph_delete_key(uint8_t *state, const uint16_t next_offset) {
  uint16_t offset = next_offset - 36;
  uint16_t last_offset = autograph_last_key_offset(state);
  if (offset != last_offset) {
    autograph_write(state, offset, state, last_offset, 36);
  }
  autograph_write_zero(state, last_offset, 36);
}

uint8_t autograph_increment_index(uint8_t *state, const uint16_t offset) {
  uint32_t index = autograph_read_uint32(state, offset);
  if (index == UINT32_MAX) {
    return 0;
  }
  autograph_write_uint32(state, offset, index + 1);
  return 1;
}

void autograph_init(uint8_t *state) { autograph_write_zero(state, 0, 9348); }

uint8_t autograph_ratchet_key(uint8_t *state, const uint16_t offset) {
  uint8_t result = autograph_increment_index(state, offset);
  if (!result) {
    return 0;
  }
  uint8_t context[4];
  uint8_t ikm[32];
  uint8_t key[32];
  autograph_write(context, 0, state, offset, 4);
  autograph_write(ikm, 0, state, offset + 4, 32);
  result = autograph_kdf(key, ikm, context);
  autograph_write(state, offset + 4, key, 0, 32);
  autograph_write_zero(ikm, 0, 32);
  autograph_write_zero(key, 0, 32);
  return result;
}

uint8_t autograph_ratchet_receiving_key(uint8_t *state) {
  return autograph_ratchet_key(state, 132);
}

uint8_t autograph_ratchet_sending_key(uint8_t *state) {
  return autograph_ratchet_key(state, 96);
}

uint16_t autograph_read_key(uint8_t *index, uint8_t *secret_key, uint8_t *state,
                            const uint16_t offset) {
  uint16_t o = offset == 0 ? 168 : offset;
  uint32_t i = autograph_read_uint32(state, o);
  if (i == 0 || o > 9312) {
    return 0;
  }
  autograph_write_uint32(index, 0, i);
  autograph_write(secret_key, 0, state, o + 4, 32);
  return o + 36;
}

void autograph_read_our_private_key(uint8_t *our_private_key,
                                    const uint8_t *state) {
  autograph_write(our_private_key, 0, state, 0, 32);
}

void autograph_read_our_public_key(uint8_t *our_public_key,
                                   const uint8_t *state) {
  autograph_write(our_public_key, 0, state, 32, 32);
}

void autograph_read_state_index(uint8_t *index, const uint8_t *state,
                                const uint16_t offset) {
  autograph_write_uint32(index, 0, autograph_read_uint32(state, offset));
}

void autograph_read_receiving_index(uint8_t *index, const uint8_t *state) {
  return autograph_read_state_index(index, state, 132);
}

void autograph_read_receiving_key(uint8_t *secret_key, const uint8_t *state) {
  autograph_write(secret_key, 0, state, 136, 32);
}

void autograph_read_sending_index(uint8_t *index, const uint8_t *state) {
  return autograph_read_state_index(index, state, 96);
}

void autograph_read_sending_key(uint8_t *secret_key, const uint8_t *state) {
  autograph_write(secret_key, 0, state, 100, 32);
}

void autograph_read_their_public_key(uint8_t *their_public_key,
                                     const uint8_t *state) {
  autograph_write(their_public_key, 0, state, 64, 32);
}

uint16_t autograph_state_size(const uint8_t *state) {
  uint16_t offset = autograph_last_key_offset(state);
  if (autograph_read_uint32(state, offset) == 0) {
    return offset;
  }
  return offset + 36;
}

uint8_t autograph_skip_key(uint8_t *state) {
  uint16_t offset = autograph_next_key_offset(state);
  if (autograph_read_uint32(state, offset) > 0) {
    return 0;
  }
  autograph_write(state, offset, state, 132, 36);
  return 1;
}

void autograph_write_our_private_key(uint8_t *state,
                                     const uint8_t *private_key) {
  autograph_write(state, 0, private_key, 0, 32);
}

void autograph_write_our_public_key(uint8_t *state, const uint8_t *public_key) {
  autograph_write(state, 32, public_key, 0, 32);
}

void autograph_write_receiving_index(uint8_t *state, const uint32_t index) {
  autograph_write_uint32(state, 132, index);
}

void autograph_write_receiving_key(uint8_t *state, const uint8_t *key) {
  autograph_write(state, 136, key, 0, 32);
}

void autograph_write_sending_index(uint8_t *state, const uint32_t index) {
  autograph_write_uint32(state, 96, index);
}

void autograph_write_sending_key(uint8_t *state, const uint8_t *key) {
  autograph_write(state, 100, key, 0, 32);
}

void autograph_write_their_public_key(uint8_t *state,
                                      const uint8_t *public_key) {
  autograph_write(state, 64, public_key, 0, 32);
}
