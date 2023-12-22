#include "autograph/bytes.h"

#include "autograph.h"

namespace Autograph {

Bytes createBytes(const uint32_t size) {
  Bytes bytes(size);
  return bytes;
}

Bytes createCiphertext(const Bytes &plaintext) {
  return createBytes(autograph_ciphertext_size(plaintext.size()));
}

Bytes createHandshake() { return createBytes(80); }

Bytes createIndex() { return createBytes(4); }

Bytes createPlaintext(const Bytes &ciphertext) {
  return createBytes(autograph_plaintext_size(ciphertext.size()));
}

Bytes createPrivateKey() { return createBytes(32); }

Bytes createPublicKey() { return createBytes(32); }

Bytes createSafetyNumber() { return createBytes(64); }

Bytes createSecretKey() { return createBytes(32); }

Bytes createSession(const Bytes &state) {
  return createBytes(autograph_session_size(state.data()));
}

Bytes createSignature() { return createBytes(64); }

Bytes createSize() { return createBytes(4); }

Bytes createState() { return createBytes(9348); }

uint32_t readIndex(const Bytes &bytes) {
  return autograph_read_index(bytes.data());
}

void resize(Bytes &bytes, const Bytes &sizeBytes) {
  auto size = autograph_read_size(sizeBytes.data());
  bytes.resize(size);
}

}  // namespace Autograph
