import {
  autograph_ephemeral_key_pair,
  autograph_identity_key_pair
} from './clib'
import { KEY_PAIR_SIZE } from './contants'

const createKeyPair = () => new Uint8Array(KEY_PAIR_SIZE)

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
