import {
  generateEphemeralKeyPair,
  generateIdentityKeyPair
} from '../src/autograph'

describe('Key pair', () => {
  const emptyKey = new Uint8Array(32)

  it('should generate ephemeral key pairs', async () => {
    const keyPair = await generateEphemeralKeyPair()
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.privateKey.byteLength).toBe(32)
    expect(keyPair.publicKey.byteLength).toBe(32)
    expect(keyPair.privateKey).not.toEqual(emptyKey)
    expect(keyPair.publicKey).not.toEqual(emptyKey)
  })

  it('should generate identity key pairs', async () => {
    const keyPair = await generateIdentityKeyPair()
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.privateKey.byteLength).toBe(32)
    expect(keyPair.publicKey.byteLength).toBe(32)
    expect(keyPair.privateKey).not.toEqual(emptyKey)
    expect(keyPair.publicKey).not.toEqual(emptyKey)
  })
})
