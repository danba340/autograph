import Clibautograph
import Foundation

public struct Autograph {
  public init() {
    autograph_init()
  }

  public func createInitiator(
    identityKeyPair: KeyPair
  ) -> Party {
    createParty(
      isInitiator: true,
      identityKeyPair: identityKeyPair
    )
  }

  public func createResponder(
    identityKeyPair: KeyPair
  ) -> Party {
    createParty(
      isInitiator: false,
      identityKeyPair: identityKeyPair
    )
  }

  public func generateEphemeralKeyPair() -> KeyPairResult {
    let keyPair = KeyPair(
      privateKey: createPrivateKeyBytes(),
      publicKey: createPublicKeyBytes()
    )
    let success = autograph_key_pair_ephemeral(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 0
    return KeyPairResult(success: success, keyPair: keyPair)
  }

  public func generateIdentityKeyPair() -> KeyPairResult {
    let keyPair = KeyPair(
      privateKey: createPrivateKeyBytes(),
      publicKey: createPublicKeyBytes()
    )
    let success = autograph_key_pair_identity(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 0
    return KeyPairResult(success: success, keyPair: keyPair)
  }
}
