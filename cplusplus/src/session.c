#include "autograph.h"
#include "autograph/bytes.h"
#include "autograph/cipher.h"
#include "autograph/kdf.h"
#include "autograph/pad.h"
#include "autograph/sizes.h"
#include "autograph/state.h"

uint8_t autograph_session_key(uint8_t *secret_key, const uint8_t *state) {
  uint8_t key[32];
  uint8_t ikm[32];
  uint8_t context[4];
  autograph_read_sending_key(key, state);
  autograph_write_uint32(context, 0, 0);
  autograph_write(ikm, 0, key, 0, 32);
  uint8_t result = autograph_kdf(key, ikm, context);
  if (result) {
    autograph_write(secret_key, 0, key, 0, 32);
  } else {
    autograph_write_zero(secret_key, 0, 32);
  }
  autograph_write_zero(key, 0, 32);
  autograph_write_zero(ikm, 0, 32);
  return result;
}

uint8_t autograph_close_session(uint8_t *secret_key, uint8_t *ciphertext,
                                uint8_t *state) {
  uint16_t state_size = autograph_state_size(state);
  uint32_t padded_size = autograph_padded_size(state_size);
  uint8_t padded[padded_size];
  uint8_t pad_result = autograph_pad(padded, state, state_size);
  uint8_t key_result = autograph_session_key(secret_key, state);
  uint8_t encrypt_result =
      autograph_encrypt(ciphertext, secret_key, padded, padded_size);
  autograph_init(state);
  return pad_result && key_result && encrypt_result ? 1 : 0;
}

uint8_t autograph_open_session(uint8_t *state, uint8_t *secret_key,
                               const uint8_t *ciphertext,
                               const uint32_t ciphertext_size) {
  uint32_t plaintext_size = ciphertext_size - 16;
  uint8_t plaintext[plaintext_size];
  uint8_t unpadded_size[4];
  uint8_t decrypt_result =
      autograph_decrypt(plaintext, secret_key, ciphertext, ciphertext_size);
  uint8_t pad_result =
      autograph_unpad(unpadded_size, plaintext, plaintext_size);
  autograph_write_zero(secret_key, 0, 32);
  autograph_init(state);
  if (decrypt_result && pad_result) {
    autograph_write(state, 0, plaintext, 0,
                    autograph_read_uint32(unpadded_size, 0));
    return 1;
  }
  return 0;
}
