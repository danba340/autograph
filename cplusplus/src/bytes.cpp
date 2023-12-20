#include "autograph/bytes.h"

#include "autograph.h"

namespace Autograph {

Bytes createBytes(const uint32_t size) {
  Bytes bytes(size);
  return bytes;
}

Bytes createCiphertextBytes(const Bytes &plaintext) {
  return createBytes(autograph_ciphertext_size(plaintext.size()));
}

Bytes createHandshakeBytes() { return createBytes(80); }

Bytes createIndexBytes() { return createBytes(4); }

Bytes createPlaintextBytes(const Bytes &ciphertext) {
  return createBytes(autograph_plaintext_size(ciphertext.size()));
}

Bytes createPrivateKeyBytes() { return createBytes(32); }

Bytes createPublicKeyBytes() { return createBytes(32); }

Bytes createSafetyNumberBytes() { return createBytes(64); }

Bytes createSecretKeyBytes() { return createBytes(32); }

Bytes createSessionBytes(const Bytes &state) {
  return createBytes(autograph_session_size(state.data()));
}

Bytes createSignatureBytes() { return createBytes(64); }

Bytes createSizeBytes() { return createBytes(4); }

Bytes createStateBytes() { return createBytes(9348); }

uint32_t readIndex(const Bytes &bytes) {
  return autograph_read_index(bytes.data());
}

void resizeBytes(Bytes &bytes, const Bytes &sizeBytes) {
  auto size = autograph_read_size(sizeBytes.data());
  bytes.resize(size);
}

}  // namespace Autograph
