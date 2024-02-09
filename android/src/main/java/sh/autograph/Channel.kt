package sh.autograph

class Channel(private val state: ByteArray = createState()) {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographStateSize(): Int

        private external fun autographHelloSize(): Int

        private external fun autographSafetyNumberSize(): Int

        private external fun autographSecretKeySize(): Int

        private external fun autographSignatureSize(): Int

        private external fun autographIndexSize(): Int

        private external fun autographSizeSize(): Int

        private external fun autographCiphertextSize(plaintextSize: Int): Int

        private external fun autographPlaintextSize(ciphertextSize: Int): Int

        private external fun autographSessionSize(state: ByteArray): Int

        private external fun autographReadIndex(index: ByteArray): Int

        private external fun autographReadSize(size: ByteArray): Int

        private external fun autographUseKeyPairs(
            publicKeys: ByteArray,
            state: ByteArray,
            identityKeyPair: ByteArray,
            ephemeralKeyPair: ByteArray,
        ): Boolean

        private external fun autographUsePublicKeys(
            state: ByteArray,
            publicKeys: ByteArray,
        )

        private external fun autographAuthenticate(
            safetyNumber: ByteArray,
            state: ByteArray,
        ): Boolean

        private external fun autographKeyExchange(
            signature: ByteArray,
            state: ByteArray,
            isInitiator: Boolean,
        ): Boolean

        private external fun autographVerifyKeyExchange(
            state: ByteArray,
            signature: ByteArray,
        ): Boolean

        private external fun autographEncryptMessage(
            ciphertext: ByteArray,
            index: ByteArray,
            state: ByteArray,
            plaintext: ByteArray,
        ): Boolean

        private external fun autographDecryptMessage(
            plaintext: ByteArray,
            size: ByteArray,
            index: ByteArray,
            state: ByteArray,
            ciphertext: ByteArray,
        ): Boolean

        private external fun autographCertifyData(
            signature: ByteArray,
            state: ByteArray,
            data: ByteArray,
        ): Boolean

        private external fun autographCertifyIdentity(
            signature: ByteArray,
            state: ByteArray,
        ): Boolean

        private external fun autographVerifyData(
            state: ByteArray,
            data: ByteArray,
            publicKey: ByteArray,
            signature: ByteArray,
        ): Boolean

        private external fun autographVerifyIdentity(
            state: ByteArray,
            publicKey: ByteArray,
            signature: ByteArray,
        ): Boolean

        private external fun autographCloseSession(
            key: ByteArray,
            ciphertext: ByteArray,
            state: ByteArray,
        ): Boolean

        private external fun autographOpenSession(
            state: ByteArray,
            key: ByteArray,
            ciphertext: ByteArray,
        ): Boolean

        fun createState(): ByteArray = ByteArray(autographStateSize())

        private fun createHello(): ByteArray = ByteArray(autographHelloSize())

        private fun createSafetyNumber(): ByteArray = ByteArray(autographSafetyNumberSize())

        private fun createSecretKey(): ByteArray = ByteArray(autographSecretKeySize())

        private fun createSignature(): ByteArray = ByteArray(autographSignatureSize())

        private fun createIndex(): ByteArray = ByteArray(autographIndexSize())

        private fun createSize(): ByteArray = ByteArray(autographSizeSize())

        private fun createCiphertext(plaintext: ByteArray): ByteArray {
            val size = autographCiphertextSize(plaintext.size)
            return ByteArray(size)
        }

        private fun createPlaintext(ciphertext: ByteArray): ByteArray {
            val size = autographPlaintextSize(ciphertext.size)
            return ByteArray(size)
        }

        private fun createSessionCiphertext(state: ByteArray): ByteArray {
            val sessionSize = autographSessionSize(state)
            val size = autographCiphertextSize(sessionSize)
            return ByteArray(size)
        }

        private fun readIndex(index: ByteArray): Int {
            return autographReadIndex(index)
        }

        private fun resizePlaintext(
            plaintext: ByteArray,
            plaintextSize: ByteArray,
        ): ByteArray {
            val size = autographReadSize(plaintextSize)
            val bytes = ByteArray(size)
            plaintext.copyInto(bytes, 0, 0, size)
            return bytes
        }
    }

    fun useKeyPairs(
        identityKeyPair: ByteArray,
        ephemeralKeyPair: ByteArray,
    ): ByteArray {
        val publicKeys = createHello()
        val success = autographUseKeyPairs(publicKeys, state, identityKeyPair, ephemeralKeyPair)
        if (!success) {
            throw RuntimeException("Initialization failed")
        }
        return publicKeys
    }

    fun usePublicKeys(publicKeys: ByteArray) {
        autographUsePublicKeys(state, publicKeys)
    }

    fun authenticate(): ByteArray {
        val safetyNumber = createSafetyNumber()
        val success = autographAuthenticate(safetyNumber, state)
        if (!success) {
            throw RuntimeException("Authentication failed")
        }
        return safetyNumber
    }

    fun keyExchange(isInitiator: Boolean): ByteArray {
        val signature = createSignature()
        val success = autographKeyExchange(signature, state, isInitiator)
        if (!success) {
            throw RuntimeException("Key exchange failed")
        }
        return signature
    }

    fun verifyKeyExchange(signature: ByteArray) {
        val success = autographVerifyKeyExchange(state, signature)
        if (!success) {
            throw RuntimeException("Key exchange verification failed")
        }
    }

    fun encrypt(plaintext: ByteArray): Pair<Int, ByteArray> {
        val ciphertext = createCiphertext(plaintext)
        val index = createIndex()
        val success = autographEncryptMessage(ciphertext, index, state, plaintext)
        if (!success) {
            throw RuntimeException("Encryption failed")
        }
        return Pair(readIndex(index), ciphertext)
    }

    fun decrypt(ciphertext: ByteArray): Pair<Int, ByteArray> {
        val plaintext = createPlaintext(ciphertext)
        val size = createSize()
        val index = createIndex()
        val success = autographDecryptMessage(plaintext, size, index, state, ciphertext)
        if (!success) {
            throw RuntimeException("Decryption failed")
        }
        return Pair(readIndex(index), resizePlaintext(plaintext, size))
    }

    fun certifyData(data: ByteArray): ByteArray {
        val signature = createSignature()
        val success = autographCertifyData(signature, state, data)
        if (!success) {
            throw RuntimeException("Certification failed")
        }
        return signature
    }

    fun certifyIdentity(): ByteArray {
        val signature = createSignature()
        val success = autographCertifyIdentity(signature, state)
        if (!success) {
            throw RuntimeException("Certification failed")
        }
        return signature
    }

    fun verifyData(
        data: ByteArray,
        publicKey: ByteArray,
        signature: ByteArray,
    ): Boolean {
        return autographVerifyData(state, data, publicKey, signature)
    }

    fun verifyIdentity(
        publicKey: ByteArray,
        signature: ByteArray,
    ): Boolean {
        return autographVerifyIdentity(state, publicKey, signature)
    }

    fun close(): Pair<ByteArray, ByteArray> {
        val key = createSecretKey()
        val ciphertext = createSessionCiphertext(state)
        val success = autographCloseSession(key, ciphertext, state)
        if (!success) {
            throw RuntimeException("Failed to close session")
        }
        return Pair(key, ciphertext)
    }

    fun open(
        key: ByteArray,
        ciphertext: ByteArray,
    ) {
        val success = autographOpenSession(state, key, ciphertext)
        if (!success) {
            throw RuntimeException("Failed to open session")
        }
    }
}
