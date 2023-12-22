import { KeyPair } from '../../types'
import { createPrivateKey, createPublicKey } from './bytes'
import { ephemeral_key_pair, identity_key_pair, ready } from './clib'

const createKeyPair = () => ({
  privateKey: createPrivateKey(),
  publicKey: createPublicKey()
})

export const generateEphemeralKeyPair = async (): Promise<
  [boolean, KeyPair]
> => {
  await ready()
  const keyPair = createKeyPair()
  const success = ephemeral_key_pair(keyPair.privateKey, keyPair.publicKey)
  return [!!success, keyPair]
}

export const generateIdentityKeyPair = async (): Promise<
  [boolean, KeyPair]
> => {
  await ready()
  const keyPair = createKeyPair()
  const success = identity_key_pair(keyPair.privateKey, keyPair.publicKey)
  return [!!success, keyPair]
}
