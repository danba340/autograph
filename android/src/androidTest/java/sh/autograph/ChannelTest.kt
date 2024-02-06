package sh.autograph

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ChannelTest {
    private val aliceHandshake: ByteArray =
        byteArrayOf(
            108, -35, 39, -121, 29, -24, -23, 41, -54, -70, -124, 24, -117, -72, -108, 25,
            -80, -36, 36, -23, -115, -58, 70, -54, 20, -56, 68, -20, 107, -97, 123, -117,
            -103, -102, 90, 113, 25, -99, 63, -95, 100, -80, 57, 50, -40, -4, 93, 76, 25,
            -92, 40, 82, 84, -32, -26, -115, 109, -10, 107, 3, -18, 97, 56, 4,
        )

    private val bobHandshake: ByteArray =
        byteArrayOf(
            -6, -33, 89, -65, -72, -43, -101, -23, 5, -103, 109, -123, -108, -104, -9, 25,
            100, -9, -37, -9, -82, 18, 52, 119, 23, 0, -27, 18, 104, -98, -79, -35, 100,
            44, 83, 20, -127, -127, 39, -100, 119, -9, 59, 12, -36, -72, -49, 44, -45, -96,
            50, -31, -93, 106, 15, 116, 0, 104, 33, -103, 120, 111, -86, 11,
        )

    private val aliceMessage: ByteArray =
        byteArrayOf(
            51, -13, 8, -91, -50, 25, -127, 63, 124, 51, -80, 40, 21, 4, -78, 3, -128, -61, 26, 68, 65,
            -56, -64, -44, 63, 10, -55, -9, -79, 3, -119, 113,
        )

    private val bobMessage: ByteArray =
        byteArrayOf(
            -3, -57, 105, -53, -117, -120, -124, -28, -58, -99, 65, -116, 116, 90, -44, 112, 55, -66, -70,
            -35, -51, 80, 46, 24, -95, 117, -55, 113, -123, -43, 29, 105,
        )

    private val aliceSignatureBobData: ByteArray =
        byteArrayOf(
            -58, -21, -113, -111, 121, 29, -113, -128, -89, 118, 33, 71, 38, -47, -87, 2, -122, 90, -53, 72,
            -85, -4, -20, -19, 55, 41, -29, -8, -58, -91, 58, -71, 31, 70, -109, 96, -75, 33, -68, 7,
            -110, 43, 24, -59, -98, -40, -41, 49, 126, -70, 88, -18, -23, 86, -89, -49, 20, -106, -29,
            38, -96, 68, 82, 8,
        )

    private val aliceSignatureBobIdentity: ByteArray =
        byteArrayOf(
            -86, 64, -97, 119, 20, 17, -126, 46, 124, 70, -102, 47, 90, 7, 116, -52, -1, -58, 56, 60,
            24, 112, -42, -68, -44, 64, -46, 117, -28, -111, 111, -6, 84, 20, -40, -34, 21, 82, -43,
            -31, 31, 28, -104, -45, 16, 82, -125, 7, -8, -70, -1, -72, 35, -51, -73, -89, -118, -77,
            -39, -121, -93, 124, 13, 5,
        )

    private val bobSignatureAliceData: ByteArray =
        byteArrayOf(
            17, -27, -9, -36, -118, -95, 5, -32, -109, -78, -26, -88, -124, -92, 94, 3, 119, 118, 16,
            -93, -34, 85, 3, -96, 88, -34, -46, -116, -34, -98, -2, -25, -74, -24, 78, -45, -106, -110,
            127, -92, -18, -35, 119, 12, -26, 54, 49, 103, -79, 72, 126, -31, -42, 41, 80, -42, -9,
            95, 23, -111, -29, 87, -84, 4,
        )

    private val bobSignatureAliceIdentity: ByteArray =
        byteArrayOf(
            -70, 27, -61, -97, -106, 127, 96, 11, 25, -32, 30, -111, 56, -62, -118, -92, 70, 54, -13, -43,
            -27, -53, -77, -38, -49, -43, -88, -96, 56, 32, -92, -11, 49, 102, -56, 36, -84, -104, 113,
            5, 82, -60, -102, 90, 20, 27, -76, 61, -67, -85, 20, -62, -91, -91, 65, -78, -66, 16, 44,
            82, -99, 68, 102, 13,
        )

    private val charlieIdentityKey: ByteArray =
        byteArrayOf(
            -127, -128, 10, 70, -82, -33, -81, 90, 43, 37, -108, 125, -68, -93, 110, -120,
            15, -10, -64, 76, -89, 8, 26, -107, -37, -33, 83, 47, -63, -97, 6, 3,
        )

    private val charlieSignatureAliceData: ByteArray =
        byteArrayOf(
            -25, 126, -118, 39, -111, 83, -126, -13, 2, 56, 53, -71, -57, -14, -39, -17,
            118, -48, -84, 6, -55, -124, 94, -77, 57, 59, -96, 23, -106, -35, 67, 122,
            -80, 56, -96, 63, 7, -95, -87, 101, -16, 97, 108, -119, -114, 99, -59, 44,
            -77, -114, 37, 4, -121, -94, 118, -96, 119, -11, -22, 39, 26, 75, 71, 6,
        )

    private val charlieSignatureAliceIdentity: ByteArray =
        byteArrayOf(
            -110, 120, -86, 85, 78, -69, -94, -13, -22, -107, -118, -55, 18, -124, -69, -127,
            45, 53, 116, -29, -78, -47, -56, -32, -107, 91, -90, 120, -53, 73, -118, -67,
            63, -25, -43, -79, -93, 114, 66, -105, 61, -3, 109, -6, -30, -116, -7, 3,
            -68, 44, 127, 108, -60, -125, -52, -40, 54, -17, -99, 49, 107, -54, 123, 9,
        )

    private val charlieSignatureBobData: ByteArray =
        byteArrayOf(
            -121, -7, 64, -42, -16, -110, -83, -115, 97, 18, 16, 47, 83, 125, 13, -90, -87, 96, 99, 21,
            -41, -39, -20, -83, 120, 50, -113, -5, -28, 76, -61, 8, -8, -123, -86, 103, 122, -87, -66,
            57, 51, 14, -85, -57, -27, 55, 55, -61, 53, -54, -117, 118, 93, 68, -125, 96, -81, 50, 31,
            -13, -86, 34, 102, 1,
        )

    private val charlieSignatureBobIdentity: ByteArray =
        byteArrayOf(
            -58, 41, 56, -67, 24, 9, 75, 102, -28, 51, -63, 102, 25, 51, 92, 1, -64, -37, 16, 17, 22,
            28, 22, 16, -58, 67, -8, 16, 98, -92, 99, -13, -2, 45, 69, -100, 50, 115, -51, 43, -101,
            -14, 78, 64, -51, -38, 80, -85, 34, -128, -1, 51, -19, 60, 37, -32, -24, -107, -103, -43,
            -52, 93, 26, 7,
        )

    private val data: ByteArray = byteArrayOf(72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100)

    private val safetyNumber: ByteArray =
        byteArrayOf(
            0, 0, 126, -39, 0, 0, -38, -76, 0, 1, 102, -94, 0, 0, 41, 97, 0, 0, 40, -11, 0, 1, 15, -38,
            0, 0, 12, 28, 0, 0, 98, 95, 0, 0, 96, -32, 0, 0, 16, -109, 0, 1, 74, 101, 0, 1, 33, 26, 0,
            0, -22, 68, 0, 0, -66, -44, 0, 1, 96, -94, 0, 0, 48, -30,
        )

    private val aliceIdentityKeyPair: ByteArray =
        byteArrayOf(
            118, -92, 17, -16, -109, 79, -66, 38, 66, 93, -2, -18, 125, -54, -59, 2, 56, -4, 122, -79,
            18, -69, -7, -48, 29, -107, 122, 103, 57, -57, 19, 17, -43, -103, 88, 124, 93, -120, 104,
            111, -60, -48, -101, -100, -91, 31, 120, -70, 79, -51, -9, -81, -13, -72, 114, 80, -104, -13,
            24, -31, 91, -36, -115, -106,
        )

    private val bobIdentityKeyPair: ByteArray =
        byteArrayOf(
            52, 0, -106, -30, -118, -64, -7, -25, 126, -57, 95, -16, 106, 17, -106, 95, -35, -9, 33,
            -55, 19, 62, 4, -121, -87, 104, -128, -38, -6, -5, -13, -66, -79, 67, 45, 125, -98, -66,
            -75, -34, 101, -107, -32, -56, -33, -21, -34, 110, 67, 61, -56, 62, 29, 37, -106, -28, -119,
            114, -113, 77, 115, -121, -113, 103,
        )

    private lateinit var aliceState: ByteArray
    private lateinit var bobState: ByteArray
    private lateinit var a: Channel
    private lateinit var b: Channel

    @Before
    fun setUpChannels() {
        aliceState = Channel.createState()
        bobState = Channel.createState()
        a = Channel(aliceState)
        b = Channel(bobState)
        val aliceEphemeralKeyPair: ByteArray =
            byteArrayOf(
                -55, -114, 54, -8, -105, -106, -32, 79, 30, 126, -49, -99, 118, 85, 9, -44,
                -108, -100, 73, -80, 107, 107, 47, 111, 95, 98, 33, -64, 80, -33, 48, -35,
                35, 16, 23, 37, -51, -125, -90, 97, 13, 81, -120, -10, -63, -3, -117, -63, -26,
                -101, -34, -35, 37, 114, -66, 87, 104, 44, -46, -112, 127, -80, -58, 45,
            )
        val bobEphemeralKeyPair: ByteArray =
            byteArrayOf(
                74, -23, 106, -104, 76, -44, -75, -112, -124, -19, -33, 58, 122, -83, 99, 100,
                -104, -37, -42, -46, -43, 72, -85, 73, -89, 92, -57, -60, -80, 66, -43, -48,
                88, 115, -85, 4, 34, -75, 120, 21, 10, 39, -52, -41, -98, -46, -79, -13, 28,
                -118, 52, 91, -20, 55, 30, 117, 10, 125, 87, -24, 80, 6, -24, 93,
            )
        val aliceHello = a.useKeyPairs(aliceIdentityKeyPair, aliceEphemeralKeyPair)
        val bobHello = b.useKeyPairs(bobIdentityKeyPair, bobEphemeralKeyPair)
        a.usePublicKeys(bobHello)
        b.usePublicKeys(aliceHello)
        val handshakeAlice = a.keyExchange(true)
        val handshakeBob = b.keyExchange(false)
        a.verifyKeyExchange(handshakeBob)
        b.verifyKeyExchange(handshakeAlice)
        assertArrayEquals(handshakeAlice, aliceHandshake)
        assertArrayEquals(handshakeBob, bobHandshake)
    }

    @Test
    fun testAuthenticate() {
        val aliceSafetyNumber = a.authenticate()
        val bobSafetyNumber = b.authenticate()
        assertArrayEquals(aliceSafetyNumber, safetyNumber)
        assertArrayEquals(bobSafetyNumber, safetyNumber)
    }

    @Test
    fun testAliceMessageToBob() {
        val (encryptIndex, message) = a.encrypt(data)
        val (decryptIndex, plaintext) = b.decrypt(message)
        assertEquals(encryptIndex, 1)
        assertEquals(decryptIndex, 1)
        assertArrayEquals(plaintext, data)
        assertArrayEquals(message, aliceMessage)
    }

    @Test
    fun testBobMessageToAlice() {
        val (encryptIndex, message) = b.encrypt(data)
        val (decryptIndex, plaintext) = a.decrypt(message)
        assertArrayEquals(plaintext, data)
        assertArrayEquals(message, bobMessage)
    }

    @Test
    fun testBobCertifyAliceData() {
        val signature = b.certifyData(data)
        assertArrayEquals(signature, bobSignatureAliceData)
    }

    @Test
    fun testAliceCertifyBobData() {
        val signature = a.certifyData(data)
        assertArrayEquals(signature, aliceSignatureBobData)
    }

    @Test
    fun testBobCertifyAliceIdentity() {
        val signature = b.certifyIdentity()
        assertArrayEquals(signature, bobSignatureAliceIdentity)
    }

    @Test
    fun testAliceCertifyBobIdentity() {
        val signature = a.certifyIdentity()
        assertArrayEquals(signature, aliceSignatureBobIdentity)
    }

    @Test
    fun testBobVerifyAliceData() {
        val verified = b.verifyData(data, charlieIdentityKey, charlieSignatureAliceData)
        assertTrue(verified)
    }

    @Test
    fun testAliceVerifyBobData() {
        val verified = a.verifyData(data, charlieIdentityKey, charlieSignatureBobData)
        assertTrue(verified)
    }

    @Test
    fun testBobVerifyAliceIdentity() {
        val verified = b.verifyIdentity(charlieIdentityKey, charlieSignatureAliceIdentity)
        assertTrue(verified)
    }

    @Test
    fun testAliceVerifyBobIdentity() {
        val verified = a.verifyIdentity(charlieIdentityKey, charlieSignatureBobIdentity)
        assertTrue(verified)
    }

    @Test
    fun testOutOfOrderMessages() {
        val data1 = byteArrayOf(1, 2, 3)
        val data2 = byteArrayOf(4, 5, 6)
        val data3 = byteArrayOf(7, 8, 9)
        val data4 = byteArrayOf(10, 11, 12)
        val (encryptIndex1, message1) = a.encrypt(data1)
        val (encryptIndex2, message2) = a.encrypt(data2)
        val (encryptIndex3, message3) = a.encrypt(data3)
        val (encryptIndex4, message4) = a.encrypt(data4)
        val (decryptIndex4, plaintext4) = b.decrypt(message4)
        val (decryptIndex2, plaintext2) = b.decrypt(message2)
        val (decryptIndex3, plaintext3) = b.decrypt(message3)
        val (decryptIndex1, plaintext1) = b.decrypt(message1)
        assertEquals(decryptIndex1, 1)
        assertEquals(decryptIndex2, 2)
        assertEquals(decryptIndex3, 3)
        assertEquals(decryptIndex4, 4)
        assertArrayEquals(plaintext1, data1)
        assertArrayEquals(plaintext2, data2)
        assertArrayEquals(plaintext3, data3)
        assertArrayEquals(plaintext4, data4)
    }

    @Test
    fun testSession() {
        val (key, ciphertext) = a.close()
        b.open(key, ciphertext)
        val signature = b.certifyIdentity()
        assertArrayEquals(signature, aliceSignatureBobIdentity)
    }
}
