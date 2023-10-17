import Clibautograph
import Foundation

internal let HANDSHAKE_SIZE = autograph_handshake_size()
internal let INDEX_SIZE = autograph_index_size()
internal let PRIVATE_KEY_SIZE = autograph_private_key_size()
internal let PUBLIC_KEY_SIZE = autograph_public_key_size()
internal let SAFETY_NUMBER_SIZE = autograph_safety_number_size()
internal let SECRET_KEY_SIZE = autograph_safety_number_size()
internal let SIGNATURE_SIZE = autograph_signature_size()
internal let SIZE_SIZE = autograph_size_size()
internal let SKIPPED_KEYS_SIZE = autograph_skipped_keys_size()
internal let TRANSCRIPT_SIZE = autograph_transcript_size()

internal func createBytes(_ size: Int) -> Bytes {
  Bytes(repeating: 0, count: size)
}

internal func createBytes(_ size: UInt32) -> Bytes {
  createBytes(Int(size))
}

internal func createCiphertextBytes(_ size: Int) -> Bytes {
  let ciphertextSize = autograph_ciphertext_size(UInt32(size))
  return createBytes(ciphertextSize)
}

internal func createHandshakeBytes() -> Bytes {
  createBytes(HANDSHAKE_SIZE)
}

internal func createIndexBytes() -> Bytes {
  createBytes(INDEX_SIZE)
}

internal func createPlaintextBytes(_ size: Int) -> Bytes {
  let plaintextSize = autograph_plaintext_size(UInt32(size))
  return createBytes(plaintextSize)
}

internal func createPrivateKeyBytes() -> Bytes {
  createBytes(PRIVATE_KEY_SIZE)
}

internal func createPublicKeyBytes() -> Bytes {
  createBytes(PUBLIC_KEY_SIZE)
}

internal func createSafetyNumberBytes() -> Bytes {
  createBytes(SAFETY_NUMBER_SIZE)
}

internal func createSecretKeyBytes() -> Bytes {
  createBytes(SECRET_KEY_SIZE)
}

internal func createSignatureBytes() -> Bytes {
  createBytes(SIGNATURE_SIZE)
}

internal func createSizeBytes() -> Bytes {
  createBytes(SIZE_SIZE)
}

internal func createSkippedKeysBytes() -> Bytes {
  createBytes(SKIPPED_KEYS_SIZE)
}

internal func createSubjectBytes(_ size: Int) -> Bytes {
  let subjectSize = autograph_subject_size(UInt32(size))
  return createBytes(subjectSize)
}

internal func createTranscriptBytes() -> Bytes {
  createBytes(TRANSCRIPT_SIZE)
}

internal func createSafeSign(sign: @escaping SignFunction) -> SignFunction {
  let safeSign: SignFunction = { [sign] subject in
    let result = sign(subject)
    if result.signature.count != SIGNATURE_SIZE {
      return SignResult(success: false, signature: createSignatureBytes())
    }
    return result
  }
  return safeSign
}
