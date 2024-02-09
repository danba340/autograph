import {
  autograph_authenticate,
  autograph_certify_data,
  autograph_certify_identity,
  autograph_ciphertext_size,
  autograph_close_session,
  autograph_decrypt_message,
  autograph_encrypt_message,
  autograph_hello_size,
  autograph_index_size,
  autograph_key_exchange,
  autograph_open_session,
  autograph_plaintext_size,
  autograph_read_index,
  autograph_read_size,
  autograph_safety_number_size,
  autograph_secret_key_size,
  autograph_session_size,
  autograph_signature_size,
  autograph_size_size,
  autograph_state_size,
  autograph_use_key_pairs,
  autograph_use_public_keys,
  autograph_verify_data,
  autograph_verify_identity,
  autograph_verify_key_exchange
} from './clib'

const createHello = () => new Uint8Array(autograph_hello_size())

const createIndex = () => new Uint8Array(autograph_index_size())

const createSafetyNumber = () => new Uint8Array(autograph_safety_number_size())

const createSecretKey = () => new Uint8Array(autograph_secret_key_size())

const createSignature = () => new Uint8Array(autograph_signature_size())

const createSize = () => new Uint8Array(autograph_size_size())

export const createState = () => new Uint8Array(autograph_state_size())

const createCiphertext = (plaintext: Uint8Array) => {
  const size = autograph_ciphertext_size(plaintext.byteLength)
  return new Uint8Array(size)
}

const createPlaintext = (ciphertext: Uint8Array) => {
  const size = autograph_plaintext_size(ciphertext.byteLength)
  return new Uint8Array(size)
}

const createSessionCiphertext = (state: Uint8Array) => {
  const size = autograph_ciphertext_size(autograph_session_size(state))
  return new Uint8Array(size)
}

const readIndex = (bytes: Uint8Array) => autograph_read_index(bytes)

const readSize = (bytes: Uint8Array) => autograph_read_size(bytes)

const resizePlaintext = (plaintext: Uint8Array, size: Uint8Array) =>
  plaintext.subarray(0, readSize(size))

export default class Channel {
  private state: Uint8Array

  constructor(state: Uint8Array) {
    this.state = state
  }

  useKeyPairs(
    identityKeyPair: Uint8Array,
    ephemeralKeyPair: Uint8Array
  ): [boolean, Uint8Array] {
    const publicKeys = createHello()
    const success = autograph_use_key_pairs(
      publicKeys,
      this.state,
      identityKeyPair,
      ephemeralKeyPair
    )
    return [success, publicKeys]
  }

  usePublicKeys(publicKeys: Uint8Array) {
    autograph_use_public_keys(this.state, publicKeys)
  }

  authenticate(): [boolean, Uint8Array] {
    const safetyNumber = createSafetyNumber()
    const success = autograph_authenticate(safetyNumber, this.state)
    return [success, safetyNumber]
  }

  keyExchange(isInitiator: boolean): [boolean, Uint8Array] {
    const signature = createSignature()
    const success = autograph_key_exchange(signature, this.state, isInitiator)
    return [success, signature]
  }

  verifyKeyExchange(signature: Uint8Array): boolean {
    return autograph_verify_key_exchange(this.state, signature)
  }

  encrypt(plaintext: Uint8Array): [boolean, number, Uint8Array] {
    const ciphertext = createCiphertext(plaintext)
    const index = createIndex()
    const success = autograph_encrypt_message(
      ciphertext,
      index,
      this.state,
      plaintext,
      plaintext.byteLength
    )
    return [success, readIndex(index), ciphertext]
  }

  decrypt(ciphertext: Uint8Array): [boolean, number, Uint8Array] {
    const plaintext = createPlaintext(ciphertext)
    const index = createIndex()
    const size = createSize()
    const success = autograph_decrypt_message(
      plaintext,
      size,
      index,
      this.state,
      ciphertext,
      ciphertext.byteLength
    )
    return [success, readIndex(index), resizePlaintext(plaintext, size)]
  }

  certifyData(data: Uint8Array): [boolean, Uint8Array] {
    const signature = createSignature()
    const success = autograph_certify_data(
      signature,
      this.state,
      data,
      data.byteLength
    )
    return [success, signature]
  }

  certifyIdentity(): [boolean, Uint8Array] {
    const signature = createSignature()
    const success = autograph_certify_identity(signature, this.state)
    return [success, signature]
  }

  verifyData(
    data: Uint8Array,
    publicKey: Uint8Array,
    signature: Uint8Array
  ): boolean {
    return autograph_verify_data(
      this.state,
      data,
      data.byteLength,
      publicKey,
      signature
    )
  }

  verifyIdentity(publicKey: Uint8Array, signature: Uint8Array): boolean {
    return autograph_verify_identity(this.state, publicKey, signature)
  }

  close(): [boolean, Uint8Array, Uint8Array] {
    const key = createSecretKey()
    const ciphertext = createSessionCiphertext(this.state)
    const success = autograph_close_session(key, ciphertext, this.state)
    return [success, key, ciphertext]
  }

  open(key: Uint8Array, ciphertext: Uint8Array): boolean {
    return autograph_open_session(
      this.state,
      key,
      ciphertext,
      ciphertext.byteLength
    )
  }
}
