#ifndef AUTOGRAPH_H
#define AUTOGRAPH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint8_t autograph_certify_data(uint8_t *signature, const uint8_t *state,
                               const uint8_t *data, const uint32_t data_size);

uint8_t autograph_certify_identity(uint8_t *signature, const uint8_t *state);

uint32_t autograph_ciphertext_size(const uint32_t plaintext_size);

uint8_t autograph_close_session(uint8_t *secret_key, uint8_t *ciphertext,
                                uint8_t *state);

uint8_t autograph_decrypt_message(uint8_t *plaintext, uint8_t *plaintext_size,
                                  uint8_t *index, uint8_t *state,
                                  const uint8_t *ciphertext,
                                  const uint32_t ciphertext_size);

uint8_t autograph_encrypt_message(uint8_t *ciphertext, uint8_t *index,
                                  uint8_t *state, const uint8_t *plaintext,
                                  const uint32_t plaintext_size);

uint8_t autograph_ephemeral_key_pair(uint8_t *private_key, uint8_t *public_key);

uint8_t autograph_identity_key_pair(uint8_t *private_key, uint8_t *public_key);

uint8_t autograph_key_exchange(uint8_t *our_handshake, uint8_t *state,
                               const uint8_t is_initiator,
                               const uint8_t *our_identity_private_key,
                               const uint8_t *our_identity_public_key,
                               uint8_t *our_ephemeral_private_key,
                               const uint8_t *our_ephemeral_public_key,
                               const uint8_t *their_identity_public_key,
                               const uint8_t *their_ephemeral_public_key);

uint8_t autograph_open_session(uint8_t *state, uint8_t *secret_key,
                               const uint8_t *ciphertext,
                               const uint32_t ciphertext_size);

uint32_t autograph_plaintext_size(const uint32_t ciphertext_size);

uint32_t autograph_read_index(const uint8_t *bytes);

uint32_t autograph_read_size(const uint8_t *bytes);

uint8_t autograph_safety_number(uint8_t *safety_number, const uint8_t *state);

uint16_t autograph_session_size(const uint8_t *state);

uint8_t autograph_verify_data(const uint8_t *state, const uint8_t *data,
                              const uint32_t data_size,
                              const uint8_t *public_key,
                              const uint8_t *signature);

uint8_t autograph_verify_identity(const uint8_t *state,
                                  const uint8_t *public_key,
                                  const uint8_t *signature);

uint8_t autograph_verify_key_exchange(uint8_t *state,
                                      const uint8_t *our_ephemeral_public_key,
                                      const uint8_t *their_handshake);

#ifdef __cplusplus
}  // extern "C"

#include <tuple>
#include <vector>

namespace Autograph {

using std::make_tuple;
using std::tuple;

using Bytes = std::vector<uint8_t>;

struct KeyPair {
  Bytes privateKey;
  Bytes publicKey;
};

class Channel {
 public:
  Channel(Bytes &state);

  tuple<bool, Bytes> calculateSafetyNumber() const;

  tuple<bool, Bytes> certifyData(const Bytes &data) const;

  tuple<bool, Bytes> certifyIdentity() const;

  tuple<bool, Bytes, Bytes> close();

  tuple<bool, uint32_t, Bytes> decrypt(const Bytes &message);

  tuple<bool, uint32_t, Bytes> encrypt(const Bytes &plaintext);

  bool open(Bytes &secretKey, const Bytes &ciphertext);

  tuple<bool, Bytes> performKeyExchange(const bool isInitiator,
                                        const KeyPair &ourIdentityKeyPair,
                                        KeyPair &ourEphemeralKeyPair,
                                        const Bytes &theirIdentityKey,
                                        const Bytes &theirEphemeralKey);

  bool verifyData(const Bytes &data, const Bytes &publicKey,
                  const Bytes &signature) const;

  bool verifyIdentity(const Bytes &publicKey, const Bytes &signature) const;

  bool verifyKeyExchange(const Bytes &ourEphemeralPublicKey,
                         const Bytes &theirHandshake);

 private:
  Bytes &state;
};

Bytes createStateBytes();

tuple<bool, KeyPair> generateEphemeralKeyPair();

tuple<bool, KeyPair> generateIdentityKeyPair();

}  // namespace Autograph
#endif

#endif
