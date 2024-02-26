#ifndef AUTOGRAPH_H
#define AUTOGRAPH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool autograph_send(const uint8_t *message, const size_t message_size);

extern bool autograph_receive(uint8_t *message, size_t *message_size);

extern bool autograph_prove(uint8_t *data, size_t *data_size,
                            uint8_t *certificates, const size_t max_data_size,
                            const uint64_t data_type, const uint8_t *public_key,
                            const uint8_t *trusted_parties,
                            const size_t trusted_parties_size,
                            const size_t trust_threshold);

extern bool autograph_proof(const uint8_t *public_key, const uint8_t *signature,
                            const uint64_t data_type, const uint8_t *data,
                            const size_t data_size);

extern bool autograph_secret_keys(const uint8_t *public_key,
                                  const uint8_t *sending_key,
                                  const uint8_t *receiving_key);

extern bool autograph_authenticate(const uint8_t *public_key,
                                   const uint8_t *safety_number);

bool autograph_init(uint8_t *state, const uint8_t *identity_key_pair,
                    uint8_t *ephemeral_key_pair);

bool autograph_hello(uint8_t *state, size_t max_data_size);

bool autograph_certify(uint8_t *public_key, uint8_t *data, size_t *data_size,
                       uint8_t *state, size_t max_data_size,
                       const uint64_t data_type, const uint8_t *trusted_parties,
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

bool autograph_identity_key_pair(uint8_t *key_pair);

bool autograph_ephemeral_key_pair(uint8_t *key_pair);

bool autograph_use_key_pairs(uint8_t *public_keys, uint8_t *state,
                             const uint8_t *identity_key_pair,
                             const uint8_t *ephemeral_key_pair);

void autograph_use_public_keys(uint8_t *state, const uint8_t *public_keys);

bool authograph_safety_number(uint8_t *safety_number, const uint8_t *state);

bool autograph_key_exchange(uint8_t *our_signature, uint8_t *state,
                            const bool is_initiator);

bool autograph_verify_key_exchange(uint8_t *state,
                                   const uint8_t *their_signature);

bool autograph_encrypt_message(uint8_t *ciphertext, uint8_t *state,
                               const uint8_t *plaintext,
                               const size_t plaintext_size);

bool autograph_decrypt_message(uint8_t *plaintext, size_t *plaintext_size,
                               uint8_t *state, const uint8_t *ciphertext,
                               const size_t ciphertext_size);

bool autograph_certify_data(uint8_t *signature, const uint8_t *state,
                            const uint8_t *data, const size_t data_size);

bool autograph_certify_identity(uint8_t *signature, const uint8_t *state);

bool autograph_verify_data(const uint8_t *state, const uint8_t *data,
                           const size_t data_size, const uint8_t *public_key,
                           const uint8_t *signature);

bool autograph_verify_identity(const uint8_t *state, const uint8_t *public_key,
                               const uint8_t *signature);

size_t autograph_hello_size();

size_t autograph_key_pair_size();

size_t autograph_public_key_size();

size_t autograph_safety_number_size();

size_t autograph_secret_key_size();

size_t autograph_signature_size();

size_t autograph_state_size();

size_t autograph_ciphertext_size(const size_t plaintext_size);

size_t autograph_plaintext_size(const size_t ciphertext_size);

#ifdef __cplusplus
}  // extern "C"

#include <array>
#include <tuple>
#include <vector>

namespace Autograph {

constexpr size_t HELLO_SIZE = 64;
constexpr size_t INDEX_SIZE = 4;
constexpr size_t KEY_PAIR_SIZE = 64;
constexpr size_t PUBLIC_KEY_SIZE = 32;
constexpr size_t SAFETY_NUMBER_SIZE = 64;
constexpr size_t SECRET_KEY_SIZE = 32;
constexpr size_t SIGNATURE_SIZE = 64;
constexpr size_t SIZE_SIZE = 8;
constexpr size_t STATE_SIZE = 2048;

using Bytes = std::vector<uint8_t>;
using Hello = std::array<uint8_t, HELLO_SIZE>;
using Index = std::array<uint8_t, INDEX_SIZE>;
using KeyPair = std::array<uint8_t, KEY_PAIR_SIZE>;
using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using SafetyNumber = std::array<uint8_t, SAFETY_NUMBER_SIZE>;
using SecretKey = std::array<uint8_t, SECRET_KEY_SIZE>;
using Signature = std::array<uint8_t, SIGNATURE_SIZE>;
using Size = std::array<uint8_t, SIZE_SIZE>;
using State = std::array<uint8_t, STATE_SIZE>;

using std::tuple;

class Channel {
 public:
  tuple<bool, Hello> useKeyPairs(const KeyPair &identityKeyPair,
                                 KeyPair &ephemeralKeyPair);

  void usePublicKeys(Hello &publicKeys);

  tuple<bool, SafetyNumber> authenticate() const;

  tuple<bool, Signature> keyExchange(const bool isInitiator);

  bool verifyKeyExchange(const Signature &signature);

  tuple<bool, uint32_t, Bytes> encrypt(const Bytes &plaintext);

  tuple<bool, uint32_t, Bytes> decrypt(const Bytes &ciphertext);

  tuple<bool, Signature> certifyData(const Bytes &data) const;

  tuple<bool, Signature> certifyIdentity() const;

  bool verifyData(const Bytes &data, const PublicKey &publicKey,
                  const Signature &signature) const;

  bool verifyIdentity(const PublicKey &publicKey,
                      const Signature &signature) const;

  tuple<bool, SecretKey, Bytes> close();

  bool open(SecretKey &key, const Bytes &ciphertext);

 private:
  State state;
};

tuple<bool, KeyPair> generateIdentityKeyPair();

tuple<bool, KeyPair> generateKeyPair();

}  // namespace Autograph
#endif

#endif
