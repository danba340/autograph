import Clibautograph
import Foundation

public class KeyPair {
    public var privateKey: Bytes
    public var publicKey: Bytes

    init(privateKey: Bytes, publicKey: Bytes) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

private func createKeyPair() -> KeyPair {
    KeyPair(
        privateKey: createPrivateKey(), publicKey: createPublicKey()
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
