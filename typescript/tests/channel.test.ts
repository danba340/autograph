import { Channel } from '../src/autograph'

describe('Channel', () => {
  const aliceHandshake = Uint8Array.from([
    159, 242, 216, 99, 227, 6, 170, 116, 241, 86, 48, 60, 160, 128, 234, 7, 118,
    43, 226, 89, 48, 56, 90, 4, 180, 141, 175, 112, 238, 107, 14, 181, 167, 246,
    102, 132, 75, 13, 181, 5, 47, 174, 244, 74, 94, 113, 56, 140, 85, 178, 112,
    105, 108, 75, 154, 82, 191, 5, 197, 87, 213, 162, 234, 108, 184, 11, 61,
    242, 143, 198, 61, 43, 33, 37, 75, 135, 190, 41, 74, 208
  ])

  const bobHandshake = Uint8Array.from([
    105, 178, 89, 152, 225, 150, 49, 251, 77, 155, 134, 254, 92, 168, 57, 159,
    252, 72, 82, 106, 91, 57, 65, 119, 0, 72, 102, 245, 247, 26, 62, 212, 237,
    20, 252, 233, 27, 144, 35, 93, 180, 235, 237, 96, 46, 167, 156, 114, 58, 12,
    43, 214, 201, 79, 108, 134, 34, 34, 36, 220, 228, 255, 233, 146, 248, 162,
    157, 164, 237, 38, 77, 217, 133, 180, 27, 98, 3, 247, 199, 24
  ])

  const aliceMessage = Uint8Array.from([
    131, 234, 21, 146, 246, 197, 94, 148, 235, 8, 84, 219, 17, 162, 128, 103,
    112, 25, 127, 50, 73, 12, 174, 1, 124, 118, 175, 10, 130, 195, 225, 29
  ])

  const bobMessage = Uint8Array.from([
    129, 139, 133, 26, 75, 190, 117, 105, 17, 240, 174, 247, 25, 28, 206, 173,
    50, 234, 25, 63, 174, 147, 185, 113, 226, 164, 21, 197, 114, 198, 43, 8
  ])

  const aliceSignatureBobData = Uint8Array.from([
    198, 235, 143, 145, 121, 29, 143, 128, 167, 118, 33, 71, 38, 209, 169, 2,
    134, 90, 203, 72, 171, 252, 236, 237, 55, 41, 227, 248, 198, 165, 58, 185,
    31, 70, 147, 96, 181, 33, 188, 7, 146, 43, 24, 197, 158, 216, 215, 49, 126,
    186, 88, 238, 233, 86, 167, 207, 20, 150, 227, 38, 160, 68, 82, 8
  ])

  const aliceSignatureBobIdentity = Uint8Array.from([
    170, 64, 159, 119, 20, 17, 130, 46, 124, 70, 154, 47, 90, 7, 116, 204, 255,
    198, 56, 60, 24, 112, 214, 188, 212, 64, 210, 117, 228, 145, 111, 250, 84,
    20, 216, 222, 21, 82, 213, 225, 31, 28, 152, 211, 16, 82, 131, 7, 248, 186,
    255, 184, 35, 205, 183, 167, 138, 179, 217, 135, 163, 124, 13, 5
  ])

  const bobSignatureAliceData = Uint8Array.from([
    17, 229, 247, 220, 138, 161, 5, 224, 147, 178, 230, 168, 132, 164, 94, 3,
    119, 118, 16, 163, 222, 85, 3, 160, 88, 222, 210, 140, 222, 158, 254, 231,
    182, 232, 78, 211, 150, 146, 127, 164, 238, 221, 119, 12, 230, 54, 49, 103,
    177, 72, 126, 225, 214, 41, 80, 214, 247, 95, 23, 145, 227, 87, 172, 4
  ])

  const bobSignatureAliceIdentity = Uint8Array.from([
    186, 27, 195, 159, 150, 127, 96, 11, 25, 224, 30, 145, 56, 194, 138, 164,
    70, 54, 243, 213, 229, 203, 179, 218, 207, 213, 168, 160, 56, 32, 164, 245,
    49, 102, 200, 36, 172, 152, 113, 5, 82, 196, 154, 90, 20, 27, 180, 61, 189,
    171, 20, 194, 165, 165, 65, 178, 190, 16, 44, 82, 157, 68, 102, 13
  ])

  const charlieIdentityKey = Uint8Array.from([
    129, 128, 10, 70, 174, 223, 175, 90, 43, 37, 148, 125, 188, 163, 110, 136,
    15, 246, 192, 76, 167, 8, 26, 149, 219, 223, 83, 47, 193, 159, 6, 3
  ])

  const charlieSignatureAliceData = Uint8Array.from([
    231, 126, 138, 39, 145, 83, 130, 243, 2, 56, 53, 185, 199, 242, 217, 239,
    118, 208, 172, 6, 201, 132, 94, 179, 57, 59, 160, 23, 150, 221, 67, 122,
    176, 56, 160, 63, 7, 161, 169, 101, 240, 97, 108, 137, 142, 99, 197, 44,
    179, 142, 37, 4, 135, 162, 118, 160, 119, 245, 234, 39, 26, 75, 71, 6
  ])

  const charlieSignatureAliceIdentity = Uint8Array.from([
    146, 120, 170, 85, 78, 187, 162, 243, 234, 149, 138, 201, 18, 132, 187, 129,
    45, 53, 116, 227, 178, 209, 200, 224, 149, 91, 166, 120, 203, 73, 138, 189,
    63, 231, 213, 177, 163, 114, 66, 151, 61, 253, 109, 250, 226, 140, 249, 3,
    188, 44, 127, 108, 196, 131, 204, 216, 54, 239, 157, 49, 107, 202, 123, 9
  ])

  const charlieSignatureBobData = Uint8Array.from([
    135, 249, 64, 214, 240, 146, 173, 141, 97, 18, 16, 47, 83, 125, 13, 166,
    169, 96, 99, 21, 215, 217, 236, 173, 120, 50, 143, 251, 228, 76, 195, 8,
    248, 133, 170, 103, 122, 169, 190, 57, 51, 14, 171, 199, 229, 55, 55, 195,
    53, 202, 139, 118, 93, 68, 131, 96, 175, 50, 31, 243, 170, 34, 102, 1
  ])

  const charlieSignatureBobIdentity = Uint8Array.from([
    198, 41, 56, 189, 24, 9, 75, 102, 228, 51, 193, 102, 25, 51, 92, 1, 192,
    219, 16, 17, 22, 28, 22, 16, 198, 67, 248, 16, 98, 164, 99, 243, 254, 45,
    69, 156, 50, 115, 205, 43, 155, 242, 78, 64, 205, 218, 80, 171, 34, 128,
    255, 51, 237, 60, 37, 224, 232, 149, 153, 213, 204, 93, 26, 7
  ])

  const data = Uint8Array.from([
    72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
  ])

  const safetyNumber = Uint8Array.from([
    0, 0, 126, 217, 0, 0, 218, 180, 0, 1, 102, 162, 0, 0, 41, 97, 0, 0, 40, 245,
    0, 1, 15, 218, 0, 0, 12, 28, 0, 0, 98, 95, 0, 0, 96, 224, 0, 0, 16, 147, 0,
    1, 74, 101, 0, 1, 33, 26, 0, 0, 234, 68, 0, 0, 190, 212, 0, 1, 96, 162, 0,
    0, 48, 226
  ])

  const aliceIdentityKeyPair = {
    privateKey: Uint8Array.from([
      118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2,
      56, 252, 122, 177, 18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17
    ]),
    publicKey: Uint8Array.from([
      213, 153, 88, 124, 93, 136, 104, 111, 196, 208, 155, 156, 165, 31, 120,
      186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243, 24, 225, 91, 220,
      141, 150
    ])
  }

  const bobIdentityKeyPair = {
    privateKey: Uint8Array.from([
      52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17, 150, 95,
      221, 247, 33, 201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190
    ]),
    publicKey: Uint8Array.from([
      177, 67, 45, 125, 158, 190, 181, 222, 101, 149, 224, 200, 223, 235, 222,
      110, 67, 61, 200, 62, 29, 37, 150, 228, 137, 114, 143, 77, 115, 135, 143,
      103
    ])
  }

  let a: Channel
  let b: Channel
  let handshakeAlice: Uint8Array
  let handshakeBob: Uint8Array
  let aliceKeyExchangeVerified: boolean
  let bobKeyExchangeVerified: boolean

  beforeEach(async () => {
    const aliceEphemeralKeyPair = {
      privateKey: Uint8Array.from([
        201, 142, 54, 248, 151, 150, 224, 79, 30, 126, 207, 157, 118, 85, 9,
        212, 148, 156, 73, 176, 107, 107, 47, 111, 95, 98, 33, 192, 80, 223, 48,
        221
      ]),
      publicKey: Uint8Array.from([
        35, 16, 23, 37, 205, 131, 166, 97, 13, 81, 136, 246, 193, 253, 139, 193,
        230, 155, 222, 221, 37, 114, 190, 87, 104, 44, 210, 144, 127, 176, 198,
        45
      ])
    }

    const bobEphemeralKeyPair = {
      privateKey: Uint8Array.from([
        74, 233, 106, 152, 76, 212, 181, 144, 132, 237, 223, 58, 122, 173, 99,
        100, 152, 219, 214, 210, 213, 72, 171, 73, 167, 92, 199, 196, 176, 66,
        213, 208
      ]),
      publicKey: Uint8Array.from([
        88, 115, 171, 4, 34, 181, 120, 21, 10, 39, 204, 215, 158, 210, 177, 243,
        28, 138, 52, 91, 236, 55, 30, 117, 10, 125, 87, 232, 80, 6, 232, 93
      ])
    }

    a = new Channel()
    b = new Channel()
    const aliceKeyExchange = await a.performKeyExchange(
      true,
      aliceIdentityKeyPair,
      aliceEphemeralKeyPair,
      bobIdentityKeyPair.publicKey,
      bobEphemeralKeyPair.publicKey
    )
    const bobKeyExchange = await b.performKeyExchange(
      false,
      bobIdentityKeyPair,
      bobEphemeralKeyPair,
      aliceIdentityKeyPair.publicKey,
      aliceEphemeralKeyPair.publicKey
    )
    handshakeAlice = aliceKeyExchange[1]
    handshakeBob = bobKeyExchange[1]
    aliceKeyExchangeVerified = a.verifyKeyExchange(
      aliceEphemeralKeyPair.publicKey,
      handshakeBob
    )
    bobKeyExchangeVerified = b.verifyKeyExchange(
      bobEphemeralKeyPair.publicKey,
      handshakeAlice
    )
  })

  it('should allow Alice and Bob to perform a key exchange', () => {
    expect(handshakeAlice).toEqual(aliceHandshake)
    expect(handshakeBob).toEqual(bobHandshake)
  })

  it('should allow Alice and Bob to verify the key exchange', () => {
    expect(aliceKeyExchangeVerified).toBe(true)
    expect(bobKeyExchangeVerified).toBe(true)
  })

  it('should calculate safety numbers correctly', () => {
    const [aliceSuccess, aliceSafetyNumber] = a.calculateSafetyNumber()
    const [bobSuccess, bobSafetyNumber] = b.calculateSafetyNumber()
    expect(aliceSuccess).toBe(true)
    expect(bobSuccess).toBe(true)
    expect(aliceSafetyNumber).toEqual(safetyNumber)
    expect(bobSafetyNumber).toEqual(safetyNumber)
  })

  it('should allow Alice to send encrypted data to Bob', () => {
    const [encryptSuccess, encryptIndex, message] = a.encrypt(data)
    const [decryptSuccess, decryptIndex, plaintext] = b.decrypt(message)
    expect(encryptSuccess).toBe(true)
    expect(decryptSuccess).toBe(true)
    expect(encryptIndex).toBe(1)
    expect(decryptIndex).toBe(1)
    expect(message).toEqual(aliceMessage)
    expect(plaintext).toEqual(data)
  })

  it('should allow Bob to send encrypted data to Alice', () => {
    const [, , message] = b.encrypt(data)
    const [, , plaintext] = a.decrypt(message)
    expect(message).toEqual(bobMessage)
    expect(plaintext).toEqual(data)
  })

  it("should allow Bob to certify Alice's ownership of her identity key and data", () => {
    const [success, signature] = b.certifyData(data)
    expect(success).toBe(true)
    expect(signature).toEqual(bobSignatureAliceData)
  })

  it("should allow Alice to certify Bob's ownership of his identity key and data", () => {
    const [success, signature] = a.certifyData(data)
    expect(success).toBe(true)
    expect(signature).toEqual(aliceSignatureBobData)
  })

  it("should allow Bob to certify Alice's ownership of her identity key", () => {
    const [success, signature] = b.certifyIdentity()
    expect(success).toBe(true)
    expect(signature).toEqual(bobSignatureAliceIdentity)
  })

  it("should allow Alice to certify Bob's ownership of his identity key", () => {
    const [success, signature] = a.certifyIdentity()
    expect(success).toBe(true)
    expect(signature).toEqual(aliceSignatureBobIdentity)
  })

  it("should allow Bob to verify Alice's ownership of her identity key and data based on Charlie's public key and signature", () => {
    expect(
      b.verifyData(data, charlieIdentityKey, charlieSignatureAliceData)
    ).toBe(true)
  })

  it("should allow Alice to verify Bob's ownership of his identity key and data based on Charlie's public key and signature", () => {
    expect(
      a.verifyData(data, charlieIdentityKey, charlieSignatureBobData)
    ).toBe(true)
  })

  it("should allow Bob to verify Alice's ownership of her identity key based on Charlie's public key and signature", () => {
    expect(
      b.verifyIdentity(charlieIdentityKey, charlieSignatureAliceIdentity)
    ).toBe(true)
  })

  it("should allow Alice to verify Bob's ownership of his identity key based on Charlie's public key and signature", () => {
    expect(
      a.verifyIdentity(charlieIdentityKey, charlieSignatureBobIdentity)
    ).toBe(true)
  })

  it('should handle out of order messages correctly', () => {
    const data1 = Uint8Array.from([1, 2, 3])
    const data2 = Uint8Array.from([4, 5, 6])
    const data3 = Uint8Array.from([7, 8, 9])
    const data4 = Uint8Array.from([10, 11, 12])
    const [, , message1] = a.encrypt(data1)
    const [, , message2] = a.encrypt(data2)
    const [, , message3] = a.encrypt(data3)
    const [, , message4] = a.encrypt(data4)
    const [success4, index4, plaintext4] = b.decrypt(message4)
    const [success2, index2, plaintext2] = b.decrypt(message2)
    const [success3, index3, plaintext3] = b.decrypt(message3)
    const [success1, index1, plaintext1] = b.decrypt(message1)
    expect(success1).toBe(true)
    expect(success2).toBe(true)
    expect(success3).toBe(true)
    expect(success4).toBe(true)
    expect(index1).toEqual(1)
    expect(index2).toEqual(2)
    expect(index3).toEqual(3)
    expect(index4).toEqual(4)
    expect(plaintext1).toEqual(data1)
    expect(plaintext2).toEqual(data2)
    expect(plaintext3).toEqual(data3)
    expect(plaintext4).toEqual(data4)
  })
})
