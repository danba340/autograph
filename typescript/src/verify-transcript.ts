import decrypt from './decrypt'
import verify from './verify-signature'

const verifyTranscript = async (
  transcript: BufferSource,
  theirIdentityKey: BufferSource,
  theirSecretKey: BufferSource,
  ciphertext: BufferSource
) => {
  try {
    const signature = await decrypt(theirSecretKey, 0, ciphertext)
    const verified = await verify(transcript, theirIdentityKey, signature)
    return verified
  } catch (error) {
    return false
  }
}

export default verifyTranscript
