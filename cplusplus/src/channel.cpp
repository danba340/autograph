#include "autograph.h"
#include "autograph/bytes.h"

namespace Autograph {

Channel::Channel(Bytes &state) : state(state) {}

tuple<bool, Bytes> Channel::calculateSafetyNumber() const {
  auto safetyNumber = createSafetyNumber();
  bool success = autograph_safety_number(safetyNumber.data(), state.data());
  return make_tuple(success, safetyNumber);
}

tuple<bool, Bytes> Channel::certifyData(const Bytes &data) const {
  auto signature = createSignature();
  bool success = autograph_certify_data(signature.data(), state.data(),
                                        data.data(), data.size());
  return make_tuple(success, signature);
}

tuple<bool, Bytes> Channel::certifyIdentity() const {
  auto signature = createSignature();
  bool success = autograph_certify_identity(signature.data(), state.data());
  return make_tuple(success, signature);
}

tuple<bool, Bytes, Bytes> Channel::close() {
  auto key = createSecretKey();
  auto ciphertext = createSession(state);
  bool success =
      autograph_close_session(key.data(), ciphertext.data(), state.data());
  return make_tuple(success, key, ciphertext);
}

tuple<bool, uint32_t, Bytes> Channel::decrypt(const Bytes &message) {
  auto plaintext = createPlaintext(message);
  auto plaintextSize = createSize();
  auto index = createIndex();
  bool success = autograph_decrypt_message(
      plaintext.data(), plaintextSize.data(), index.data(), state.data(),
      message.data(), message.size());
  if (success) {
    resize(plaintext, plaintextSize);
  }
  return make_tuple(success, readIndex(index), plaintext);
}

tuple<bool, uint32_t, Bytes> Channel::encrypt(const Bytes &plaintext) {
  auto index = createIndex();
  auto ciphertext = createCiphertext(plaintext);
  bool success =
      autograph_encrypt_message(ciphertext.data(), index.data(), state.data(),
                                plaintext.data(), plaintext.size());
  return make_tuple(success, readIndex(index), ciphertext);
}

bool Channel::open(Bytes &secretKey, const Bytes &ciphertext) {
  return autograph_open_session(state.data(), secretKey.data(),
                                ciphertext.data(), ciphertext.size());
}

tuple<bool, Bytes> Channel::performKeyExchange(
    const bool isInitiator, const KeyPair &ourIdentityKeyPair,
    KeyPair &ourEphemeralKeyPair, const Bytes &theirIdentityKey,
    const Bytes &theirEphemeralKey) {
  auto handshake = createHandshake();
  bool success = autograph_key_exchange(
      handshake.data(), state.data(), isInitiator ? 1 : 0,
      ourIdentityKeyPair.privateKey.data(), ourIdentityKeyPair.publicKey.data(),
      ourEphemeralKeyPair.privateKey.data(),
      ourEphemeralKeyPair.publicKey.data(), theirIdentityKey.data(),
      theirEphemeralKey.data());
  return make_tuple(success, handshake);
}

bool Channel::verifyData(const Bytes &data, const Bytes &publicKey,
                         const Bytes &signature) const {
  return autograph_verify_data(state.data(), data.data(), data.size(),
                               publicKey.data(), signature.data());
}

bool Channel::verifyIdentity(const Bytes &publicKey,
                             const Bytes &signature) const {
  return autograph_verify_identity(state.data(), publicKey.data(),
                                   signature.data());
}

bool Channel::verifyKeyExchange(const Bytes &ourEphemeralPublicKey,
                                const Bytes &theirHandshake) {
  return autograph_verify_key_exchange(
      state.data(), ourEphemeralPublicKey.data(), theirHandshake.data());
}

}  // namespace Autograph
