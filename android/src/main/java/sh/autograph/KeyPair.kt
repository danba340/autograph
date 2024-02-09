package sh.autograph

class KeyPair {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographKeyPairSize(): Int

        private external fun autographEphemeralKeyPair(keyPair: ByteArray): Boolean

        private external fun autographIdentityKeyPair(keyPair: ByteArray): Boolean

        private fun createKeyPair(): ByteArray = ByteArray(autographKeyPairSize())

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
}
