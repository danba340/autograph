extern "C" {
    pub fn autograph_certify_data(
        signature: *mut u8,
        state: *const u8,
        data: *const u8,
        data_size: u32,
    ) -> u8;

    pub fn autograph_certify_identity(signature: *mut u8, state: *const u8) -> u8;

    pub fn autograph_ciphertext_size(plaintext_size: u32) -> u32;

    pub fn autograph_close_session(secret_key: *mut u8, ciphertext: *mut u8, state: *mut u8) -> u8;

    pub fn autograph_decrypt_message(
        plaintext: *mut u8,
        plaintext_size: *mut u8,
        index: *mut u8,
        state: *mut u8,
        ciphertext: *const u8,
        ciphertext_size: u32,
    ) -> u8;

    pub fn autograph_encrypt_message(
        ciphertext: *mut u8,
        index: *mut u8,
        state: *mut u8,
        plaintext: *const u8,
        plaintext_size: u32,
    ) -> u8;

    pub fn autograph_ephemeral_key_pair(private_key: *mut u8, public_key: *mut u8) -> u8;

    pub fn autograph_identity_key_pair(private_key: *mut u8, public_key: *mut u8) -> u8;

    pub fn autograph_key_exchange(
        our_handshake: *mut u8,
        state: *mut u8,
        is_initiator: u8,
        our_identity_private_key: *const u8,
        our_identity_public_key: *const u8,
        our_ephemeral_private_key: *mut u8,
        our_ephemeral_public_key: *const u8,
        their_identity_public_key: *const u8,
        their_ephemeral_public_key: *const u8,
    ) -> u8;

    pub fn autograph_open_session(
        state: *mut u8,
        secret_key: *mut u8,
        ciphertext: *const u8,
        ciphertext_size: u32,
    ) -> u8;

    pub fn autograph_plaintext_size(ciphertext_size: u32) -> u32;

    pub fn autograph_read_index(bytes: *const u8) -> u32;

    pub fn autograph_read_size(bytes: *const u8) -> u32;

    pub fn autograph_safety_number(safety_number: *mut u8, state: *const u8) -> u8;

    pub fn autograph_session_size(state: *const u8) -> u16;

    pub fn autograph_verify_data(
        state: *const u8,
        data: *const u8,
        data_size: u32,
        public_key: *const u8,
        signature: *const u8,
    ) -> u8;

    pub fn autograph_verify_identity(
        state: *const u8,
        public_key: *const u8,
        signature: *const u8,
    ) -> u8;

    pub fn autograph_verify_key_exchange(
        state: *mut u8,
        our_ephemeral_public_key: *const u8,
        their_handshake: *const u8,
    ) -> u8;
}
