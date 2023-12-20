import {
  ciphertext_size,
  plaintext_size,
  read_index,
  read_size,
  session_size
} from './clib'

const createBytes = (size: number) => new Uint8Array(size)

export const createCiphertextBytes = (plaintext: Uint8Array) => {
  const size = ciphertext_size(plaintext.byteLength)
  return createBytes(size)
}

export const createHandshakeBytes = () => createBytes(80)

export const createIndexBytes = () => createBytes(4)

export const createPlaintextBytes = (ciphertext: Uint8Array) => {
  const size = plaintext_size(ciphertext.byteLength)
  return createBytes(size)
}

export const createPrivateKeyBytes = () => createBytes(32)

export const createPublicKeyBytes = () => createBytes(32)

export const createSafetyNumberBytes = () => createBytes(64)

export const createSecretKeyBytes = () => createBytes(32)

export const createSessionBytes = (state: Uint8Array) => {
  const size = session_size(state)
  return createBytes(size)
}

export const createSignatureBytes = () => createBytes(64)

export const createSizeBytes = () => createBytes(4)

export const createStateBytes = () => createBytes(9348)

export const readIndex = (bytes: Uint8Array) => read_index(bytes)

export const resizeBytes = (bytes: Uint8Array, sizeBytes: Uint8Array) => {
  const size = read_size(sizeBytes)
  return bytes.subarray(0, size)
}
