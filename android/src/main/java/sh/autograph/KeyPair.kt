package sh.autograph

class KeyPair {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private fun createKeyPair(): ByteArray = ByteArray(64)
    }

    private external fun autographEphemeralKeyPair(keyPair: ByteArray): Boolean

    private external fun autographIdentityKeyPair(keyPair: ByteArray): Boolean

    fun generateKeyPair(): ByteArray {
        val keyPair = createKeyPair()
        val success = autographEphemeralKeyPair(keyPair)
        if (!success) {
            throw RuntimeException("Key generation failed")
        }
        return keyPair
    }

    fun generateIdentityKeyPair(): ByteArray {
        val keyPair = createKeyPair()
        val success = autographIdentityKeyPair(keyPair)
        if (!success) {
            throw RuntimeException("Key generation failed")
        }
        return keyPair
    }
}
