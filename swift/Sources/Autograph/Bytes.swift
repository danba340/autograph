import Clibautograph
import Foundation

public typealias Bytes = [UInt8]

private func createBytes(_ size: Int) -> Bytes {
  [UInt8](repeating: 0, count: size)
}

private func createBytes(_ size: UInt16) -> Bytes {
  createBytes(Int(size))
}

private func createBytes(_ size: UInt32) -> Bytes {
  createBytes(Int(size))
}

func createCiphertextBytes(_ plaintext: Bytes) -> Bytes {
  let size = autograph_ciphertext_size(UInt32(plaintext.count))
  return createBytes(size)
}

func createHandshakeBytes() -> Bytes {
  createBytes(80)
}

func createIndexBytes() -> Bytes {
  createBytes(4)
}

func createPlaintextBytes(_ ciphertext: Bytes) -> Bytes {
  let size = autograph_plaintext_size(UInt32(ciphertext.count))
  return createBytes(size)
}

func createPrivateKeyBytes() -> Bytes {
  createBytes(32)
}

func createPublicKeyBytes() -> Bytes {
  createBytes(32)
}

func createSafetyNumberBytes() -> Bytes {
  createBytes(64)
}

func createSecretKeyBytes() -> Bytes {
  createBytes(32)
}

func createSessionBytes(_ state: Bytes) -> Bytes {
  let size = autograph_session_size(state)
  return createBytes(size)
}

func createSignatureBytes() -> Bytes {
  createBytes(64)
}

func createSizeBytes() -> Bytes {
  createBytes(4)
}

func createStateBytes() -> Bytes {
  createBytes(9348)
}

func readIndex(_ bytes: Bytes) -> UInt32 {
  autograph_read_index(bytes)
}

func resizeBytes(
  _ bytes: Bytes,
  _ sizeBytes: Bytes
) -> Bytes {
  let size = Int(autograph_read_size(sizeBytes))
  return Array(bytes[0 ..< size])
}
