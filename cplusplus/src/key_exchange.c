#include "autograph.h"
#include "autograph/bytes.h"
#include "autograph/cipher.h"
#include "autograph/diffie_hellman.h"
#include "autograph/sign.h"
#include "autograph/state.h"
#include "sodium.h"

uint8_t autograph_derive_keys(uint8_t *state, const uint8_t is_initiator,
                              uint8_t *our_private_key,
                              const uint8_t *their_public_key) {
  uint8_t ikm[32];
  uint8_t result =
      autograph_diffie_hellman(ikm, our_private_key, their_public_key);
  autograph_write_sending_key(state, ikm);
  autograph_write_receiving_key(state, ikm);
  if (is_initiator) {
    autograph_write_receiving_index(state, 1);
  } else {
    autograph_write_sending_index(state, 1);
  }
  autograph_ratchet_sending_key(state);
  autograph_ratchet_receiving_key(state);
  autograph_write_sending_index(state, 0);
  autograph_write_receiving_index(state, 0);
  autograph_write_zero(ikm, 0, 32);
  autograph_write_zero(our_private_key, 0, 32);
  return result;
}

void autograph_write_transcript(uint8_t *transcript, const uint8_t *first_key,
                                const uint8_t *second_key,
                                const uint8_t *third_key) {
  autograph_write(transcript, 0, first_key, 0, 32);
  autograph_write(transcript, 32, second_key, 0, 32);
  autograph_write(transcript, 64, third_key, 0, 32);
}

uint8_t autograph_handshake(uint8_t *our_handshake, const uint8_t *state,
                            const uint8_t *our_identity_private_key,
                            const uint8_t *our_identity_public_key,
                            const uint8_t *their_identity_public_key,
                            const uint8_t *their_ephemeral_public_key) {
  uint8_t transcript[96];
  uint8_t signature[64];
  uint8_t secret_key[32];
  autograph_write_transcript(transcript, their_identity_public_key,
                             our_identity_public_key,
                             their_ephemeral_public_key);
  uint8_t sign_result =
      autograph_sign(signature, our_identity_private_key, transcript, 96);
  autograph_read_sending_key(secret_key, state);
  uint8_t encrypt_result =
      autograph_encrypt(our_handshake, secret_key, signature, 64);
  autograph_write_zero(secret_key, 0, 32);
  return sign_result && encrypt_result ? 1 : 0;
}

uint8_t autograph_key_exchange(uint8_t *our_handshake, uint8_t *state,
                               const uint8_t is_initiator,
                               const uint8_t *our_identity_private_key,
                               const uint8_t *our_identity_public_key,
                               uint8_t *our_ephemeral_private_key,
                               const uint8_t *our_ephemeral_public_key,
                               const uint8_t *their_identity_public_key,
                               const uint8_t *their_ephemeral_public_key) {
  if (sodium_init() < 0) {
    return 0;
  }
  autograph_init(state);
  autograph_write_our_private_key(state, our_identity_private_key);
  autograph_write_our_public_key(state, our_identity_public_key);
  autograph_write_their_public_key(state, their_identity_public_key);
  uint8_t derive_result =
      autograph_derive_keys(state, is_initiator, our_ephemeral_private_key,
                            their_ephemeral_public_key);
  uint8_t handshake_result = autograph_handshake(
      our_handshake, state, our_identity_private_key, our_identity_public_key,
      their_identity_public_key, their_ephemeral_public_key);
  return derive_result && handshake_result ? 1 : autograph_abort(state);
}

uint8_t autograph_verify_key_exchange(uint8_t *state,
                                      const uint8_t *our_ephemeral_public_key,
                                      const uint8_t *their_handshake) {
  uint8_t secret_key[32];
  uint8_t signature[64];
  uint8_t our_identity_public_key[32];
  uint8_t their_identity_public_key[32];
  uint8_t transcript[96];
  autograph_read_our_public_key(our_identity_public_key, state);
  autograph_read_their_public_key(their_identity_public_key, state);
  autograph_write_transcript(transcript, our_identity_public_key,
                             their_identity_public_key,
                             our_ephemeral_public_key);
  autograph_read_receiving_key(secret_key, state);
  uint8_t decrypt_result =
      autograph_decrypt(signature, secret_key, their_handshake, 80);
  uint8_t verify_result =
      autograph_verify(their_identity_public_key, transcript, 96, signature);
  autograph_write_zero(secret_key, 0, 32);
  return decrypt_result && verify_result ? 1 : autograph_abort(state);
}
