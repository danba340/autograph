import { autograph_sign_subject } from './clib'
import { SignFunction, SignResult } from '../types'
import { SIGNATURE_SIZE, createSignatureBytes } from './utils'

const createErrorSignResult = (): SignResult => ({
  success: false,
  signature: new Uint8Array(SIGNATURE_SIZE)
})

const ensureSignResult = (result: SignResult): SignResult => {
  if (result.signature.byteLength !== SIGNATURE_SIZE) {
    return createErrorSignResult()
  }
  return result
}

export const createSafeSign =
  (sign: SignFunction): SignFunction =>
  async (subject: Uint8Array) => {
    try {
      const result = await sign(subject)
      return ensureSignResult(result)
    } catch (error) {
      return createErrorSignResult()
    }
  }

export const createSign =
  (identityPrivateKey: Uint8Array): SignFunction =>
  (subject: Uint8Array) => {
    const signature = createSignatureBytes()
    const success = autograph_sign_subject(
      signature,
      identityPrivateKey,
      subject,
      subject.byteLength
    )
    return { success, signature }
  }
