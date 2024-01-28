#include "autograph.h"
#include "numbers.h"

namespace Autograph {

Bytes createCiphertext(const Bytes plaintext) {
  size_t size = autograph_ciphertext_size(plaintext.size());
  Bytes ciphertext(size);
  return ciphertext;
}

Bytes createPlaintext(const Bytes ciphertext) {
  size_t size = autograph_plaintext_size(ciphertext.size());
  Bytes plaintext(size);
  return plaintext;
}

Bytes createSessionCiphertext(const State &state) {
  size_t size = autograph_session_size(state.data());
  Bytes ciphertext(size);
  return ciphertext;
}

uint32_t readIndex(const Index &index) {
  return autograph_read_index(index.data());
}

Bytes resizePlaintext(Bytes plaintext, const Size plaintextSize) {
  size_t size = autograph_read_size(plaintextSize.data());
  plaintext.resize(size);
  return plaintext;
}

Channel::Channel(State &state) : state(state) {}

tuple<bool, Hello> Channel::useKeyPairs(KeyPair &identityKeyPair,
                                        KeyPair &ephemeralKeyPair) {
  Hello publicKeys;
  bool success =
      autograph_use_key_pairs(publicKeys.data(), state.data(),
                              identityKeyPair.data(), ephemeralKeyPair.data());
  return make_tuple(success, publicKeys);
}

void Channel::usePublicKeys(Hello &publicKeys) {
  autograph_use_public_keys(state.data(), publicKeys.data());
}

tuple<bool, SafetyNumber> Channel::authenticate() const {
  SafetyNumber safetyNumber;
  bool success = autograph_authenticate(safetyNumber.data(), state.data());
  return make_tuple(success, safetyNumber);
}

tuple<bool, Signature> Channel::keyExchange(const bool isInitiator) {
  Signature signature;
  bool success =
      autograph_key_exchange(signature.data(), state.data(), isInitiator);
  return make_tuple(success, signature);
}

bool Channel::verifyKeyExchange(const Signature &signature) {
  return autograph_verify_key_exchange(state.data(), signature.data());
}

tuple<bool, uint32_t, Bytes> Channel::encrypt(const Bytes &plaintext) {
  Bytes ciphertext = createCiphertext(plaintext);
  Index index;
  bool success =
      autograph_encrypt_message(ciphertext.data(), index.data(), state.data(),
                                plaintext.data(), plaintext.size());
  return make_tuple(success, readIndex(index), ciphertext);
}

tuple<bool, uint32_t, Bytes> Channel::decrypt(const Bytes &ciphertext) {
  Bytes plaintext = createPlaintext(ciphertext);
  Size size;
  Index index;
  bool success = autograph_decrypt_message(
      plaintext.data(), size.data(), index.data(), state.data(),
      ciphertext.data(), ciphertext.size());
  return make_tuple(success, readIndex(index),
                    resizePlaintext(plaintext, size));
}

tuple<bool, Signature> Channel::certifyData(const Bytes &data) const {
  Signature signature;
  bool success = autograph_certify_data(signature.data(), state.data(),
                                        data.data(), data.size());
  return make_tuple(success, signature);
}

tuple<bool, Signature> Channel::certifyIdentity() const {
  Signature signature;
  bool success = autograph_certify_identity(signature.data(), state.data());
  return make_tuple(success, signature);
}

bool Channel::verifyData(const Bytes &data, const PublicKey &publicKey,
                         const Signature &signature) const {
  return autograph_verify_data(state.data(), data.data(), data.size(),
                               publicKey.data(), signature.data());
}

bool Channel::verifyIdentity(const PublicKey &publicKey,
                             const Signature &signature) const {
  return autograph_verify_identity(state.data(), publicKey.data(),
                                   signature.data());
}

tuple<bool, SecretKey, Bytes> Channel::close() {
  SecretKey key;
  Bytes ciphertext = createSessionCiphertext(state);
  bool success =
      autograph_close_session(key.data(), ciphertext.data(), state.data());
  return make_tuple(success, key, ciphertext);
}

bool Channel::open(SecretKey &key, const Bytes &ciphertext) {
  return autograph_open_session(state.data(), key.data(), ciphertext.data(),
                                ciphertext.size());
}

}  // namespace Autograph
