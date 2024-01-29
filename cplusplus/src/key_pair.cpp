#include "autograph.h"

namespace Autograph {

tuple<bool, KeyPair> generateIdentityKeyPair() {
  KeyPair keyPair;
  bool success = autograph_identity_key_pair(keyPair.data());
  return make_tuple(success, keyPair);
}

tuple<bool, KeyPair> generateKeyPair() {
  KeyPair keyPair;
  bool success = autograph_ephemeral_key_pair(keyPair.data());
  return make_tuple(success, keyPair);
}

}  // namespace Autograph
