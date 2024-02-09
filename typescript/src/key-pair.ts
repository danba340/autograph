import {
  autograph_ephemeral_key_pair,
  autograph_identity_key_pair,
  autograph_key_pair_size
} from './clib'

const createKeyPair = () => new Uint8Array(autograph_key_pair_size())

export const generateIdentityKeyPair = (): Uint8Array => {
  const keyPair = createKeyPair()
  const success = autograph_identity_key_pair(keyPair)
  if (!success) {
    throw new Error('Key generation failed')
  }
  return keyPair
}

export const generateKeyPair = (): Uint8Array => {
  const keyPair = createKeyPair()
  const success = autograph_ephemeral_key_pair(keyPair)
  if (!success) {
    throw new Error('Key generation failed')
  }
  return keyPair
}
