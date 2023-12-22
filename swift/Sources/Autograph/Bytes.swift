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

func createCiphertext(_ plaintext: Bytes) -> Bytes {
    let size = autograph_ciphertext_size(UInt32(plaintext.count))
    return createBytes(size)
}

func createHandshake() -> Bytes {
    createBytes(80)
}

func createIndex() -> Bytes {
    createBytes(4)
}

func createPlaintext(_ ciphertext: Bytes) -> Bytes {
    let size = autograph_plaintext_size(UInt32(ciphertext.count))
    return createBytes(size)
}

func createPrivateKey() -> Bytes {
    createBytes(32)
}

func createPublicKey() -> Bytes {
    createBytes(32)
}

func createSafetyNumber() -> Bytes {
    createBytes(64)
}

func createSecretKey() -> Bytes {
    createBytes(32)
}

func createSession(_ state: Bytes) -> Bytes {
    let size = autograph_session_size(state)
    return createBytes(size)
}

func createSignature() -> Bytes {
    createBytes(64)
}

func createSize() -> Bytes {
    createBytes(4)
}

func createState() -> Bytes {
    createBytes(9348)
}

func readIndex(_ bytes: Bytes) -> UInt32 {
    autograph_read_index(bytes)
}

func resize(
    _ bytes: Bytes,
    _ sizeBytes: Bytes
) -> Bytes {
    let size = Int(autograph_read_size(sizeBytes))
    return Array(bytes[0 ..< size])
}
