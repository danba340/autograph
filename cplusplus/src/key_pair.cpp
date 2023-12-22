#include "autograph.h"
#include "autograph/bytes.h"

namespace Autograph {

KeyPair createKeyPair() {
  auto privateKey = createPrivateKey();
  auto publicKey = createPublicKey();
  KeyPair keyPair = {privateKey, publicKey};
  return keyPair;
}

tuple<bool, KeyPair> generateEphemeralKeyPair() {
  auto keyPair = createKeyPair();
  bool success = autograph_ephemeral_key_pair(keyPair.privateKey.data(),
                                              keyPair.publicKey.data());
  return make_tuple(success, keyPair);
}

tuple<bool, KeyPair> generateIdentityKeyPair() {
  auto keyPair = createKeyPair();
  bool success = autograph_identity_key_pair(keyPair.privateKey.data(),
                                             keyPair.publicKey.data());
  return make_tuple(success, keyPair);
}

}  // namespace Autograph
