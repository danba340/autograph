package sh.autograph

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeyPairTest {
    @Test
    fun testGenerateKeyPair() {
        val keyPair = KeyPair.generateKeyPair()
        assertEquals(keyPair.size, 64)
        assertFalse(keyPair.all { it == 0.toByte() })
    }

    @Test
    fun testGenerateIdentityKeyPair() {
        val keyPair = KeyPair.generateIdentityKeyPair()
        assertEquals(keyPair.size, 64)
        assertFalse(keyPair.all { it == 0.toByte() })
    }
}
