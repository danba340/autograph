import Clibautograph
import Foundation

private func createKeyPair() -> Bytes {
    createBytes(autograph_key_pair_size())
}

public func generateIdentityKeyPair() throws -> Bytes {
    var keyPair = createKeyPair()
    let success = autograph_identity_key_pair(&keyPair)
    if !success {
        throw Error.keyPair
    }
    return keyPair
}

public func generateKeyPair() throws -> Bytes {
    var keyPair = createKeyPair()
    let success = autograph_key_pair(&keyPair)
    if !success {
        throw Error.keyPair
    }
    return keyPair
}
