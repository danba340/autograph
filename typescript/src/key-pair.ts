import {
  autograph_ephemeral_key_pair,
  autograph_identity_key_pair,
  autograph_key_pair_size
} from './clib'

const createKeyPair = () => new Uint8Array(autograph_key_pair_size())

export const generateIdentityKeyPair = (): [boolean, Uint8Array] => {
  const keyPair = createKeyPair()
  const success = autograph_identity_key_pair(keyPair)
  return [success, keyPair]
}

export const generateKeyPair = (): [boolean, Uint8Array] => {
  const keyPair = createKeyPair()
  const success = autograph_ephemeral_key_pair(keyPair)
  return [success, keyPair]
}
