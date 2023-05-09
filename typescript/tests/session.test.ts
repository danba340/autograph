import { createFrom } from 'stedy/bytes'
import { createInitiator, createResponder } from '../src/autograph'
import { Session } from '../types'

describe('Session', () => {
  const keyPairs = {
    alice: {
      identity: {
        publicKey: createFrom([
          91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16, 210,
          14, 244, 60, 251, 140, 48, 190, 65, 194, 35, 166, 246, 1, 209, 4, 33
        ]),
        privateKey: createFrom([
          43, 6, 246, 172, 137, 170, 33, 12, 118, 177, 111, 60, 19, 37, 65, 122,
          28, 34, 200, 251, 96, 35, 187, 52, 74, 224, 143, 39, 90, 51, 33, 140
        ])
      },
      ephemeral: {
        publicKey: createFrom([
          16, 9, 47, 109, 23, 19, 165, 137, 95, 186, 203, 186, 154, 179, 116, 3,
          160, 119, 225, 180, 226, 19, 172, 45, 113, 125, 124, 86, 94, 159, 161,
          119
        ]),
        privateKey: createFrom([
          171, 243, 152, 144, 76, 145, 84, 13, 243, 173, 102, 244, 84, 223, 43,
          104, 182, 128, 230, 247, 121, 221, 222, 203, 10, 80, 43, 88, 177, 155,
          1, 114
        ])
      }
    },
    bob: {
      identity: {
        publicKey: createFrom([
          232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3, 241,
          131, 200, 140, 54, 155, 28, 46, 158, 76, 96, 4, 150, 61, 34, 13, 133,
          138
        ]),
        privateKey: createFrom([
          243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158, 83,
          255, 187, 192, 29, 114, 69, 126, 243, 111, 122, 143, 170, 247, 140,
          129, 60, 0
        ])
      },
      ephemeral: {
        publicKey: createFrom([
          249, 212, 82, 190, 253, 45, 230, 86, 74, 150, 239, 0, 26, 41, 131,
          245, 177, 87, 106, 105, 167, 58, 158, 184, 244, 65, 205, 42, 40, 80,
          134, 52
        ]),
        privateKey: createFrom([
          252, 67, 175, 250, 230, 100, 145, 82, 139, 125, 242, 5, 40, 8, 155,
          104, 37, 224, 5, 96, 105, 46, 42, 202, 158, 63, 177, 43, 112, 184,
          207, 85
        ])
      }
    }
  }
  const messages = {
    alice: createFrom([
      0, 0, 0, 1, 203, 203, 240, 117, 151, 142, 77, 113, 252, 151, 171, 12, 154,
      177, 105, 6, 248, 79, 37, 105, 238, 243, 135, 194, 50, 34, 253
    ]),
    bob: createFrom([
      0, 0, 0, 1, 139, 162, 147, 198, 9, 205, 34, 7, 221, 213, 250, 54, 187,
      229, 89, 17, 48, 96, 18, 187, 111, 237, 72, 189, 169, 210, 108
    ])
  }
  const signatures = {
    alice: {
      data: createFrom([
        86, 231, 106, 104, 140, 212, 209, 113, 91, 48, 249, 242, 132, 150, 129,
        18, 62, 67, 44, 187, 71, 9, 28, 5, 164, 244, 165, 222, 124, 11, 197, 55,
        123, 174, 9, 14, 186, 118, 86, 242, 240, 170, 239, 176, 78, 255, 85, 28,
        88, 148, 202, 108, 151, 160, 93, 1, 128, 129, 255, 123, 238, 191, 29, 1
      ]),
      identity: createFrom([
        183, 19, 9, 47, 241, 207, 111, 69, 199, 68, 135, 48, 131, 140, 112, 168,
        61, 244, 34, 107, 219, 194, 177, 99, 178, 109, 218, 237, 118, 1, 13,
        205, 231, 138, 74, 246, 88, 149, 36, 65, 219, 62, 154, 70, 185, 35, 251,
        98, 186, 16, 56, 79, 18, 144, 193, 183, 27, 2, 11, 71, 83, 20, 168, 7
      ])
    },
    bob: {
      data: createFrom([
        188, 36, 195, 130, 177, 84, 21, 74, 125, 139, 109, 135, 207, 42, 213,
        11, 153, 158, 183, 160, 112, 141, 216, 204, 167, 194, 159, 123, 221,
        162, 50, 220, 49, 54, 123, 73, 132, 73, 15, 144, 65, 252, 249, 192, 145,
        159, 22, 224, 143, 25, 226, 32, 54, 44, 139, 196, 85, 254, 198, 61, 138,
        244, 223, 4
      ]),
      identity: createFrom([
        173, 114, 114, 160, 51, 91, 40, 39, 223, 144, 168, 53, 94, 199, 250,
        184, 88, 132, 31, 232, 50, 177, 147, 144, 102, 146, 120, 27, 57, 63, 60,
        151, 237, 224, 85, 65, 200, 38, 227, 34, 88, 131, 168, 236, 107, 4, 200,
        54, 232, 176, 16, 44, 144, 106, 77, 28, 246, 104, 17, 77, 150, 92, 116,
        0
      ])
    }
  }
  const certificates = {
    alice: {
      data: {
        identityKey: createFrom([
          123, 223, 90, 28, 163, 65, 187, 199, 14, 78, 92, 116, 38, 48, 178,
          123, 72, 213, 94, 252, 250, 127, 184, 0, 187, 249, 157, 102, 227, 241,
          114, 20
        ]),
        signature: createFrom([
          82, 239, 167, 88, 84, 82, 16, 198, 184, 193, 35, 9, 78, 135, 162, 198,
          47, 53, 179, 3, 242, 165, 38, 18, 209, 74, 113, 86, 99, 124, 196, 124,
          75, 99, 159, 106, 233, 232, 188, 251, 194, 157, 166, 7, 134, 203, 32,
          253, 65, 90, 40, 91, 76, 25, 252, 156, 139, 154, 148, 183, 71, 7, 109,
          5
        ])
      },
      identity: {
        identityKey: createFrom([
          97, 114, 246, 28, 48, 150, 138, 154, 28, 234, 226, 183, 186, 225, 166,
          166, 43, 109, 145, 194, 105, 51, 155, 138, 48, 180, 100, 51, 113, 57,
          150, 211
        ]),
        signature: createFrom([
          94, 131, 142, 67, 234, 107, 103, 51, 205, 132, 182, 252, 157, 59, 44,
          23, 12, 141, 221, 157, 239, 30, 80, 111, 164, 85, 21, 221, 217, 98,
          151, 57, 213, 250, 195, 119, 178, 45, 107, 31, 26, 153, 30, 132, 207,
          177, 67, 160, 231, 198, 207, 32, 134, 210, 55, 9, 188, 20, 186, 130,
          156, 122, 77, 4
        ])
      }
    },
    bob: {
      data: {
        identityKey: createFrom([
          251, 196, 170, 200, 183, 119, 18, 130, 9, 255, 140, 77, 56, 104, 92,
          11, 42, 224, 208, 28, 110, 241, 103, 77, 34, 32, 164, 58, 255, 108,
          255, 222
        ]),
        signature: createFrom([
          20, 76, 211, 173, 168, 254, 145, 154, 196, 46, 118, 241, 200, 158,
          125, 189, 120, 214, 213, 161, 217, 229, 164, 90, 10, 128, 115, 116,
          69, 30, 153, 219, 68, 143, 64, 1, 161, 239, 230, 6, 82, 13, 100, 27,
          126, 169, 42, 49, 85, 79, 232, 15, 30, 22, 109, 118, 6, 196, 207, 18,
          60, 63, 25, 1
        ])
      },
      identity: {
        identityKey: createFrom([
          126, 118, 172, 19, 4, 38, 118, 77, 202, 146, 28, 11, 166, 253, 115,
          109, 204, 196, 31, 146, 128, 17, 242, 19, 95, 146, 105, 135, 38, 36,
          178, 138
        ]),
        signature: createFrom([
          141, 196, 191, 87, 226, 187, 57, 49, 19, 119, 116, 5, 5, 247, 5, 171,
          137, 143, 52, 144, 19, 146, 38, 120, 124, 247, 154, 251, 30, 247, 63,
          28, 229, 241, 8, 34, 86, 159, 15, 87, 120, 95, 0, 58, 188, 176, 71,
          18, 254, 57, 98, 211, 129, 168, 241, 51, 236, 181, 12, 63, 185, 130,
          176, 2
        ])
      }
    }
  }
  const data = createFrom('Hello World')
  let a: Session
  let b: Session

  beforeEach(async () => {
    const alice = await createInitiator(
      keyPairs.alice.identity,
      keyPairs.alice.ephemeral
    )
    const bob = await createResponder(
      keyPairs.bob.identity,
      keyPairs.bob.ephemeral
    )
    const handshakes = {
      alice: await alice.performHandshake(
        keyPairs.bob.identity.publicKey,
        keyPairs.bob.ephemeral.publicKey
      ),
      bob: await bob.performHandshake(
        keyPairs.alice.identity.publicKey,
        keyPairs.alice.ephemeral.publicKey
      )
    }
    a = await handshakes.alice.establishSession(handshakes.bob.handshake)
    b = await handshakes.bob.establishSession(handshakes.alice.handshake)
  })

  it('should allow Alice to send encrypted data to Bob', async () => {
    const message = await a.encrypt(data)
    const result = await b.decrypt(message)
    expect(message).toEqual(messages.alice)
    expect(result).toEqual(data)
  })

  it('should allow Bob to send encrypted data to Alice', async () => {
    const message = await b.encrypt(data)
    const result = await a.decrypt(message)
    expect(message).toEqual(messages.bob)
    expect(result).toEqual(data)
  })

  it("should allow Bob to certify Alice's ownership of her identity key and data", async () => {
    const message = await a.encrypt(data)
    const signature = await b.certify(message)
    expect(signature).toEqual(signatures.bob.data)
  })

  it("should allow Alice to certify Bob's ownership of his identity key and data", async () => {
    const message = await b.encrypt(data)
    const signature = await a.certify(message)
    expect(signature).toEqual(signatures.alice.data)
  })

  it("should allow Bob to certify Alice's ownership of her identity key", async () => {
    const signature = await b.certify()
    expect(signature).toEqual(signatures.bob.identity)
  })

  it("should allow Alice to certify Bob's ownership of his identity key", async () => {
    const signature = await a.certify()
    expect(signature).toEqual(signatures.alice.identity)
  })

  it("should allow Bob to verify Alice's ownership of her identity key and data based on Charlie's public key and signature", async () => {
    const message = await a.encrypt(data)
    const verified = await b.verify(certificates.alice.data, message)
    expect(verified).toBe(true)
  })

  it("should allow Alice to verify Bob's ownership of his identity key and data based on Charlie's public key and signature", async () => {
    const message = await b.encrypt(data)
    const verified = await a.verify(certificates.bob.data, message)
    expect(verified).toBe(true)
  })

  it("should allow Bob to verify Alice's ownership of her identity key based on Charlie's public key and signature", async () => {
    const verified = await b.verify(certificates.alice.identity)
    expect(verified).toBe(true)
  })

  it("should allow Alice to verify Bob's ownership of his identity key based on Charlie's public key and signature", async () => {
    const verified = await a.verify(certificates.bob.identity)
    expect(verified).toBe(true)
  })
})
