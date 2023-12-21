import Clibautograph
import Foundation

public class Channel {
    var state: Bytes

    init() {
        state = createStateBytes()
    }

    public func calculateSafetyNumber() throws -> Bytes {
        var safetyNumber = createSafetyNumberBytes()
        let success = autograph_safety_number(&safetyNumber, &state) == 1
        if !success {
            throw AutographError.safetyNumber
        }
        return safetyNumber
    }

    public func certifyData(data: Bytes) throws -> Bytes {
        var signature = createSignatureBytes()
        let success = autograph_certify_data(
            &signature,
            &state,
            data,
            UInt32(data.count)
        ) == 1
        if !success {
            throw AutographError.certification
        }
        return signature
    }

    public func certifyIdentity() throws -> Bytes {
        var signature = createSignatureBytes()
        let success = autograph_certify_identity(
            &signature,
            &state
        ) == 1
        if !success {
            throw AutographError.certification
        }
        return signature
    }

    public func close() throws -> (Bytes, Bytes) {
        var key = createSecretKeyBytes()
        var ciphertext = createSessionBytes(state)
        let success = autograph_close_session(&key, &ciphertext, &state) == 1
        if !success {
            throw AutographError.session
        }
        return (key, ciphertext)
    }

    public func decrypt(message: Bytes) throws -> (UInt32, Bytes) {
        var plaintext = createPlaintextBytes(message)
        var index = createIndexBytes()
        var size = createSizeBytes()
        let success = autograph_decrypt_message(
            &plaintext,
            &size,
            &index,
            &state,
            message,
            UInt32(message.count)
        ) == 1
        if !success {
            throw AutographError.decryption
        }
        return (readIndex(index), resizeBytes(plaintext, size))
    }

    public func encrypt(plaintext: Bytes) throws -> (UInt32, Bytes) {
        var ciphertext = createCiphertextBytes(plaintext)
        var index = createIndexBytes()
        let success = autograph_encrypt_message(
            &ciphertext,
            &index,
            &state,
            plaintext,
            UInt32(plaintext.count)
        ) == 1
        if !success {
            throw AutographError.encryption
        }
        return (readIndex(index), ciphertext)
    }

    public func open(secretKey: inout Bytes, ciphertext: Bytes) throws {
        let success = autograph_open_session(
            &state,
            &secretKey,
            ciphertext,
            UInt32(ciphertext.count)
        ) == 1
        if !success {
            throw AutographError.session
        }
    }

    public func performKeyExchange(
        isInitiator: Bool,
        ourIdentityKeyPair: KeyPair,
        ourEphemeralKeyPair: inout KeyPair,
        theirIdentityKey: Bytes,
        theirEphemeralKey: Bytes
    ) throws -> Bytes {
        var handshake = createHandshakeBytes()
        let success = autograph_key_exchange(
            &handshake,
            &state,
            isInitiator ? 1 : 0,
            ourIdentityKeyPair.privateKey,
            ourIdentityKeyPair.publicKey,
            &ourEphemeralKeyPair.privateKey,
            ourEphemeralKeyPair.publicKey,
            theirIdentityKey,
            theirEphemeralKey
        ) == 1
        if !success {
            throw AutographError.keyExchange
        }
        return handshake
    }

    public func verifyData(
        data: Bytes,
        publicKey: Bytes,
        signature: Bytes
    ) -> Bool {
        autograph_verify_data(
            &state,
            data,
            UInt32(data.count),
            publicKey,
            signature
        ) == 1
    }

    public func verifyIdentity(
        publicKey: Bytes,
        signature: Bytes
    ) -> Bool {
        autograph_verify_identity(
            &state,
            publicKey,
            signature
        ) == 1
    }

    public func verifyKeyExchange(
        ourEphemeralPublicKey: Bytes,
        theirHandshake: Bytes
    ) -> Bool {
        autograph_verify_key_exchange(
            &state,
            ourEphemeralPublicKey,
            theirHandshake
        ) == 1
    }
}
