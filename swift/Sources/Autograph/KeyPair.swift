import Clibautograph
import Foundation

public class KeyPair {
  public var privateKey: [UInt8]
  public var publicKey: [UInt8]

  init(privateKey: [UInt8], publicKey: [UInt8]) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }
}

private func createKeyPair() -> KeyPair {
  KeyPair(
    privateKey: createPrivateKeyBytes(), publicKey: createPublicKeyBytes()
  )
}

public func generateEphemeralKeyPair() throws -> KeyPair {
  let keyPair = createKeyPair()
  let success =
    autograph_ephemeral_key_pair(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 1
  if !success {
    throw AutographError.keyPair
  }
  return keyPair
}

public func generateIdentityKeyPair() throws -> KeyPair {
  let keyPair = createKeyPair()
  let success =
    autograph_identity_key_pair(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 1
  if !success {
    throw AutographError.keyPair
  }
  return keyPair
}
