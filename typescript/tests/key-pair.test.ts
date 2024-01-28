import {
  generateKeyPair,
  generateIdentityKeyPair,
  ready
} from '../src/autograph'

describe('Key pair', () => {
  const emptyKeyPair = new Uint8Array(64)

  beforeAll(async () => {
    await ready()
  })

  it('should generate identity key pairs', () => {
    const [success, keyPair] = generateIdentityKeyPair()
    expect(success).toBe(true)
    expect(keyPair.byteLength).toBe(64)
    expect(keyPair).not.toEqual(emptyKeyPair)
  })

  it('should generate ephemeral key pairs', () => {
    const [success, keyPair] = generateKeyPair()
    expect(success).toBe(true)
    expect(keyPair.byteLength).toBe(64)
    expect(keyPair).not.toEqual(emptyKeyPair)
  })
})
