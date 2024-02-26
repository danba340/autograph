#include "autograph.h"
#include "cert.h"
#include "constants.h"
#include "external.h"
#include "kdf.h"
#include "state.h"

bool derive_secret_keys(uint8_t *state, bool is_initiator) {
  uint8_t shared_secret[SHARED_SECRET_SIZE];
  uint8_t okm[OKM_SIZE];
  bool dh_success =
      diffie_hellman(shared_secret, get_ephemeral_private_key(state),
                     get_their_ephemeral_key(state));
  bool kdf_success = kdf(okm, shared_secret);
  set_secret_keys(state, is_initiator, okm);
  zeroize(shared_secret, SHARED_SECRET_SIZE);
  zeroize(okm, OKM_SIZE);
  return dh_success && kdf_success;
}

bool autograph_key_exchange(uint8_t *our_signature, uint8_t *state,
                            bool is_initiator) {
  set_transcript(state, is_initiator);
  bool key_success = derive_secret_keys(state, is_initiator);
  delete_ephemeral_private_key(state);
  bool certify_success = certify_data_ownership(
      our_signature, state, get_their_identity_key(state),
      get_transcript(state), TRANSCRIPT_SIZE);
  if (!certify_success || !key_success) {
    zeroize(state, STATE_SIZE);
    return false;
  }
  return true;
}

bool autograph_verify_key_exchange(uint8_t *state,
                                   const uint8_t *their_signature) {
  if (!verify_data_ownership(get_identity_public_key(state),
                             get_transcript(state), TRANSCRIPT_SIZE,
                             get_their_identity_key(state), their_signature)) {
    zeroize(state, STATE_SIZE);
    return false;
  }
  return true;
}
