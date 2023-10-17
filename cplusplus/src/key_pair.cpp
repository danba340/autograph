#include "key_pair.h"

#include "sizes.h"

namespace Autograph {

KeyPair createKeyPair() {
  Bytes privateKey(PRIVATE_KEY_SIZE);
  Bytes publicKey(PUBLIC_KEY_SIZE);
  KeyPair keyPair = {privateKey, publicKey};
  return keyPair;
}

KeyPairResult generateEphemeralKeyPair() {
  auto keyPair = createKeyPair();
  bool success = autograph_key_pair_ephemeral(keyPair.privateKey.data(),
                                              keyPair.publicKey.data()) == 0;
  KeyPairResult result = {success, keyPair};
  return result;
}

KeyPairResult generateIdentityKeyPair() {
  auto keyPair = createKeyPair();
  bool success = autograph_key_pair_identity(keyPair.privateKey.data(),
                                             keyPair.publicKey.data()) == 0;
  KeyPairResult result = {success, keyPair};
  return result;
}

}  // namespace Autograph
