#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "autograph.h"
#include "cert.h"
#include "constants.h"
#include "external.h"
#include "state.h"

void autograph_use_public_keys(uint8_t *state, const uint8_t *public_keys) {
  set_their_identity_key(state, public_keys);
  set_their_ephemeral_key(state, public_keys + PUBLIC_KEY_SIZE);
}

bool autograph_init(uint8_t *state, const uint8_t *identity_key_pair,
                    uint8_t *ephemeral_key_pair) {
  zeroize(state, STATE_SIZE);
  if (!ready()) {
    return false;
  }
  set_identity_key_pair(state, identity_key_pair);
  set_ephemeral_key_pair(state, ephemeral_key_pair);
  zeroize(ephemeral_key_pair, KEY_PAIR_SIZE);
  return true;
}

bool establish_channel_initiator(uint8_t *state, uint8_t *message,
                                 size_t *message_size, uint8_t *our_signature) {
  read_our_public_keys(message, state);
  if (!autograph_send(message, HELLO_SIZE)) {
    return false;
  }
  if (!autograph_receive(message, message_size)) {
    return false;
  }
  autograph_use_public_keys(state, message);
  if (!autograph_key_exchange(our_signature, state, true)) {
    return false;
  }
  if (!autograph_send(our_signature, SIGNATURE_SIZE)) {
    return false;
  }
  if (!autograph_verify_key_exchange(state, message + HELLO_SIZE)) {
    return false;
  }
  return true;
}

bool establish_channel_responder(uint8_t *state, uint8_t *message,
                                 size_t *message_size, uint8_t *our_signature) {
  if (!autograph_receive(message, message_size)) {
    return false;
  }
  autograph_use_public_keys(state, message);
  if (!autograph_key_exchange(our_signature, state, false)) {
    return false;
  }
  read_our_public_keys(message, state);
  memmove(message + HELLO_SIZE, our_signature, SIGNATURE_SIZE);
  if (!autograph_send(message, HELLO_SIZE + SIGNATURE_SIZE)) {
    return false;
  }
  if (!autograph_receive(message, message_size)) {
    return false;
  }
  if (!autograph_verify_key_exchange(state, message)) {
    return false;
  }
  return true;
}

bool establish_channel(uint8_t *state, uint8_t *message, size_t *message_size,
                       const bool is_initiator) {
  uint8_t our_signature[SIGNATURE_SIZE];
  if (is_initiator) {
    return establish_channel_initiator(state, message, message_size,
                                       our_signature);
  }
  return establish_channel_responder(state, message, message_size,
                                     our_signature);
}

bool perform_responder_operation(uint8_t *state, uint8_t *message,
                                 size_t *message_size, size_t max_data_size) {
  if (!autograph_receive(message, message_size)) {
    return false;
  }
  uint8_t plaintext[max_data_size];
  size_t plaintext_size = 0;
  if (!autograph_decrypt_message(plaintext, &plaintext_size, state, message,
                                 *message_size)) {
    return false;
  }
  bool authenticate = false;
  uint8_t operation = OPERATION_VERIFY;
  uint64_t data_type = DATA_TYPE_IDENTITY;
  size_t trusted_parties_size = 0;
  size_t trust_threshold = 0;
  if (!parse_operation(&authenticate, operation, &max_data_size,
                       &trusted_parties_size, &trust_threshold, plaintext,
                       plaintext_size)) {
    return false;
  }
  if (authenticate) {
    uint8_t safety_number[SAFETY_NUMBER_SIZE];
    if (!autograph_safety_number(safety_number, state)) {
      return false;
    }
    if (!autograph_authenticate(get_their_identity_key(state), safety_number)) {
      return false;
    }
  }
  size_t certificates_size =
      trust_threshold * (PUBLIC_KEY_SIZE + SIGNATURE_SIZE);
  size_t data_size = 0;
  if (!autograph_prove(plaintext + certificates_size, &data_size, plaintext,
                       get_their_identity_key(state), data_type,
                       max_data_size - certificates_size,
                       plaintext + TRUSTED_PARTIES_OFFSET, trust_threshold)) {
    return false;
  }
  plaintext_size = certificates_size + data_size;
  if (!autograph_encrypt_message(message, state, plaintext, plaintext_size)) {
    return false;
  }
  if (!autograph_send(message, plaintext_size + TAG_SIZE)) {
    return false;
  }
  if (operation == OPERATION_VERIFY) {
    return true;
  }
  if (!autograph_receive(message, message_size)) {
    return false;
  }
  if (!autograph_decrypt_message(plaintext, &plaintext_size, state, message,
                                 *message_size)) {
    return false;
  }
  if (operation == OPERATION_CERTIFY) {
  }
  if (!autograph_receive(message, message_size)) {
    return false;
  }
  if (!autograph_decrypt_message(plaintext, &plaintext_size, state, message,
                                 *message_size)) {
    return false;
  }
  if (operation == OPERATION_CERTIFY) {
    return autograph_proof(get_their_identity_key(state), plaintext,
                           get_uint64(plaintext, SIGNATURE_SIZE), data,
                           data_size);
  }
  if (operation == OPERATION_ESTABLISH_KEYS) {
  }

  if (!autograph_prove()) }

bool autograph_hello(uint8_t *state, size_t max_data_size) {
  uint8_t message[max_data_size + TAG_SIZE];
  size_t message_size = 0;
  if (!establish_channel(state, message, &message_size)) {
    return false;
  }
  return perform_responder_operation(state, message, &message_size,
                                     max_data_size);
}

bool autograph_certify(uint8_t *public_key, uint8_t *data, size_t *data_size,
                       uint8_t *state, const uint64_t data_type,
                       const uint8_t *trusted_parties,
                       const size_t trusted_parties_size,
                       const size_t trust_threshold, const bool authenticate);

bool autograph_verify(uint8_t *public_key, uint8_t *data, size_t *data_size,
                      uint8_t *state, const uint64_t data_type,
                      const uint8_t *trusted_parties,
                      const size_t trusted_parties_size,
                      const size_t trust_threshold, const bool authenticate);

bool autograph_establish_keys(uint8_t *public_key, uint8_t *sending_key,
                              uint8_t *receiving_key, uint8_t *state,
                              const uint8_t *trusted_parties,
                              const size_t trusted_parties_size,
                              const size_t trust_threshold,
                              const bool authenticate);
