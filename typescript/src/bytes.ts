import {
  ciphertext_size,
  plaintext_size,
  read_index,
  read_size,
  session_size
} from './clib'

const createBytes = (size: number) => new Uint8Array(size)

export const createCiphertext = (plaintext: Uint8Array) => {
  const size = ciphertext_size(plaintext.byteLength)
  return createBytes(size)
}

export const createHandshake = () => createBytes(80)

export const createIndex = () => createBytes(4)

export const createPlaintext = (ciphertext: Uint8Array) => {
  const size = plaintext_size(ciphertext.byteLength)
  return createBytes(size)
}

export const createPrivateKey = () => createBytes(32)

export const createPublicKey = () => createBytes(32)

export const createSafetyNumber = () => createBytes(64)

export const createSecretKey = () => createBytes(32)

export const createSession = (state: Uint8Array) => {
  const size = session_size(state)
  return createBytes(size)
}

export const createSignature = () => createBytes(64)

export const createSize = () => createBytes(4)

export const createState = () => createBytes(9348)

export const readIndex = (bytes: Uint8Array) => read_index(bytes)

export const resize = (bytes: Uint8Array, sizeBytes: Uint8Array) => {
  const size = read_size(sizeBytes)
  return bytes.subarray(0, size)
}
