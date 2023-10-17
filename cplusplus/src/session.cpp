#include "session.h"

#include "numbers.h"
#include "private.h"
#include "sizes.h"

namespace Autograph {

DecryptFunction createDecrypt(Bytes theirSecretKey) {
  Bytes messageIndex(INDEX_SIZE);
  Bytes decryptIndex(INDEX_SIZE);
  Bytes plaintextSize(SIZE_SIZE);
  Bytes skippedKeys(SKIPPED_KEYS_SIZE);
  auto decryptFunction = [theirSecretKey, messageIndex, decryptIndex,
                          skippedKeys,
                          plaintextSize](const Bytes message) mutable {
    Bytes plaintext(getPlaintextSize(message.size()));
    bool success = autograph_decrypt(plaintext.data(), plaintextSize.data(),
                                     messageIndex.data(), decryptIndex.data(),
                                     skippedKeys.data(), theirSecretKey.data(),
                                     message.data(), message.size()) == 0;
    if (success) {
      plaintext.resize(autograph_read_uint32(plaintextSize.data()));
    }
    DecryptionResult result = {
        success, autograph_read_uint64(messageIndex.data()), plaintext};
    return result;
  };
  return decryptFunction;
}

EncryptFunction createEncrypt(Bytes ourSecretKey) {
  Bytes index(INDEX_SIZE);
  auto encryptFunction = [ourSecretKey, index](const Bytes plaintext) mutable {
    Bytes ciphertext(getCiphertextSize(plaintext.size()));
    bool success =
        autograph_encrypt(ciphertext.data(), index.data(), ourSecretKey.data(),
                          plaintext.data(), plaintext.size()) == 0;
    EncryptionResult result = {success, autograph_read_uint64(index.data()),
                               ciphertext};
    return result;
  };
  return encryptFunction;
}

SignDataFunction createSignData(const SignFunction sign,
                                const Bytes theirPublicKey) {
  auto signDataFunction = [sign, theirPublicKey](const Bytes data) {
    Bytes subject(getSubjectSize(data.size()));
    autograph_subject(subject.data(), theirPublicKey.data(), data.data(),
                      data.size());
    auto signResult = sign(subject);
    SignResult result = {signResult.success, signResult.signature};
    return result;
  };
  return signDataFunction;
}

SignIdentityFunction createSignIdentity(const SignFunction sign,
                                        const Bytes theirPublicKey) {
  auto signIdentityFunction = [sign, theirPublicKey]() {
    auto signResult = sign(theirPublicKey);
    SignResult result = {signResult.success, signResult.signature};
    return result;
  };
  return signIdentityFunction;
}

unsigned int countCertificates(const Bytes certificates) {
  return certificates.size() / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE);
}

VerifyDataFunction createVerifyData(const Bytes theirIdentityKey) {
  auto verifyDataFunction = [theirIdentityKey](const Bytes certificates,
                                               const Bytes data) {
    return autograph_verify_data(theirIdentityKey.data(), certificates.data(),
                                 countCertificates(certificates), data.data(),
                                 data.size()) == 0;
  };
  return verifyDataFunction;
}

VerifyIdentityFunction createVerifyIdentity(const Bytes theirIdentityKey) {
  auto verifyIdentityFunction = [theirIdentityKey](const Bytes certificates) {
    return autograph_verify_identity(theirIdentityKey.data(),
                                     certificates.data(),
                                     countCertificates(certificates)) == 0;
  };
  return verifyIdentityFunction;
}

}  // namespace Autograph
