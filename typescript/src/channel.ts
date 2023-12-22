import { KeyPair } from '../../types'
import {
  createCiphertext,
  createHandshake,
  createIndex,
  createPlaintext,
  createSafetyNumber,
  createSecretKey,
  createSession,
  createSignature,
  createSize,
  createState,
  readIndex,
  resize
} from './bytes'
import {
  certify_data,
  certify_identity,
  close_session,
  decrypt_message,
  encrypt_message,
  key_exchange,
  open_session,
  ready,
  safety_number,
  verify_data,
  verify_identity,
  verify_key_exchange
} from './clib'

export default class Channel {
  private state: Uint8Array

  constructor() {
    this.state = createState()
  }

  calculateSafetyNumber(): [boolean, Uint8Array] {
    const safetyNumber = createSafetyNumber()
    const success = safety_number(safetyNumber, this.state)
    return [!!success, safetyNumber]
  }

  certifyData(data: Uint8Array): [boolean, Uint8Array] {
    const signature = createSignature()
    const success = certify_data(signature, this.state, data, data.byteLength)
    return [!!success, signature]
  }

  certifyIdentity(): [boolean, Uint8Array] {
    const signature = createSignature()
    const success = certify_identity(signature, this.state)
    return [!!success, signature]
  }

  close(): [boolean, Uint8Array, Uint8Array] {
    const key = createSecretKey()
    const ciphertext = createSession(this.state)
    const success = close_session(key, ciphertext, this.state)
    return [!!success, key, ciphertext]
  }

  decrypt(message: Uint8Array): [boolean, number, Uint8Array] {
    const plaintext = createPlaintext(message)
    const index = createIndex()
    const size = createSize()
    const success = decrypt_message(
      plaintext,
      size,
      index,
      this.state,
      message,
      message.byteLength
    )
    return [!!success, readIndex(index), resize(plaintext, size)]
  }

  encrypt(plaintext: Uint8Array): [boolean, number, Uint8Array] {
    const ciphertext = createCiphertext(plaintext)
    const index = createIndex()
    const success = encrypt_message(
      ciphertext,
      index,
      this.state,
      plaintext,
      plaintext.byteLength
    )
    return [!!success, readIndex(index), ciphertext]
  }

  async open(secretKey: Uint8Array, ciphertext: Uint8Array): Promise<boolean> {
    await ready()
    return !!open_session(
      this.state,
      secretKey,
      ciphertext,
      ciphertext.byteLength
    )
  }

  async performKeyExchange(
    isInitiator: boolean,
    ourIdentityKeyPair: KeyPair,
    ourEphemeralKeyPair: KeyPair,
    theirIdentityKey: Uint8Array,
    theirEphemeralKey: Uint8Array
  ): Promise<[boolean, Uint8Array]> {
    await ready()
    const handshake = createHandshake()
    const success = key_exchange(
      handshake,
      this.state,
      isInitiator ? 1 : 0,
      ourIdentityKeyPair.privateKey,
      ourIdentityKeyPair.publicKey,
      ourEphemeralKeyPair.privateKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    return [!!success, handshake]
  }

  verifyData(
    data: Uint8Array,
    publicKey: Uint8Array,
    signature: Uint8Array
  ): boolean {
    return !!verify_data(
      this.state,
      data,
      data.byteLength,
      publicKey,
      signature
    )
  }

  verifyIdentity(publicKey: Uint8Array, signature: Uint8Array): boolean {
    return !!verify_identity(this.state, publicKey, signature)
  }

  verifyKeyExchange(
    ourEphemeralPublicKey: Uint8Array,
    theirHandshake: Uint8Array
  ): boolean {
    return !!verify_key_exchange(
      this.state,
      ourEphemeralPublicKey,
      theirHandshake
    )
  }
}
