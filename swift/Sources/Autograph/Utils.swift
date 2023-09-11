import Clibautograph
import Foundation

internal let HANDSHAKE_SIZE = 80
internal let MESSAGE_EXTRA_SIZE = 24
internal let PRIVATE_KEY_SIZE = 32
internal let PUBLIC_KEY_SIZE = 32
internal let SAFETY_NUMBER_SIZE = 60
internal let SECRET_KEY_SIZE = 32
internal let SIGNATURE_SIZE = 64
internal let TRANSCRIPT_SIZE = 128

internal func createBytes(_ size: Int) -> Bytes {
  Bytes(repeating: 0, count: size)
}

internal func createHandshakeBytes() -> Bytes {
  createBytes(HANDSHAKE_SIZE)
}

internal func createMessageBytes(size: Int) -> Bytes {
  createBytes(size + MESSAGE_EXTRA_SIZE)
}

internal func createPlaintextBytes(size: Int) -> Bytes {
  createBytes(size - MESSAGE_EXTRA_SIZE)
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

internal func createSubjectBytes(size: Int) -> Bytes {
  createBytes(PUBLIC_KEY_SIZE + size)
}

internal func createTranscriptBytes() -> Bytes {
  createBytes(TRANSCRIPT_SIZE)
}

internal func createSafeSign(sign: @escaping SignFunction) -> SignFunction {
  let safeSign: SignFunction = { [sign] subject in
    let result = sign(subject)
    if result.signature.count != 64 {
      return SignResult(success: false, signature: createSignatureBytes())
    }
    return result
  }
  return safeSign
}
