use alloc::vec;

use crate::{
    auth::authenticate,
    cert::{
        certify_data_ownership, certify_identity_ownership, verify_data_ownership,
        verify_identity_ownership,
    },
    constants::{
        HELLO_SIZE, INDEX_SIZE, NONCE_SIZE, OKM_SIZE, PADDING_BLOCK_SIZE, PADDING_BYTE,
        PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SAFETY_NUMBER_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE,
        SIZE_SIZE, STATE_SIZE, TAG_SIZE,
    },
    error::Error,
    external::{decrypt, encrypt, init, zeroize},
    kdf::kdf,
    key_exchange::{key_exchange, verify_key_exchange},
    numbers::{read_index, read_size, set_size},
    state::{
        delete_skipped_index, get_receiving_index, get_receiving_key, get_receiving_nonce,
        get_sending_index, get_sending_key, get_sending_nonce, get_session, get_skipped_index,
        get_their_identity_key, increment_receiving_index, increment_sending_index,
        set_ephemeral_key_pair, set_identity_key_pair, set_their_ephemeral_key,
        set_their_identity_key, skip_index,
    },
    types::{
        Bytes, Hello, Index, KeyPair, Nonce, Okm, PublicKey, SafetyNumber, SecretKey, Signature,
        Size, State,
    },
};

fn use_key_pairs(
    public_keys: &mut Hello,
    state: &mut State,
    mut identity_key_pair: KeyPair,
    mut ephemeral_key_pair: KeyPair,
) -> bool {
    zeroize(state);
    if !init() {
        return false;
    }
    set_identity_key_pair(state, &identity_key_pair);
    set_ephemeral_key_pair(state, &ephemeral_key_pair);
    public_keys[..PUBLIC_KEY_SIZE].copy_from_slice(&identity_key_pair[PRIVATE_KEY_SIZE..]);
    public_keys[PUBLIC_KEY_SIZE..].copy_from_slice(&ephemeral_key_pair[PRIVATE_KEY_SIZE..]);
    zeroize(&mut identity_key_pair);
    zeroize(&mut ephemeral_key_pair);
    true
}

fn use_public_keys(state: &mut State, public_keys: Hello) {
    set_their_identity_key(
        state,
        &public_keys[..PUBLIC_KEY_SIZE]
            .try_into()
            .unwrap_or([0; PUBLIC_KEY_SIZE]),
    );
    set_their_ephemeral_key(
        state,
        &public_keys[PUBLIC_KEY_SIZE..]
            .try_into()
            .unwrap_or([0; PUBLIC_KEY_SIZE]),
    );
}

fn calculate_padded_size(plaintext: &[u8]) -> usize {
    let size = plaintext.len();
    size + PADDING_BLOCK_SIZE - (size % PADDING_BLOCK_SIZE)
}

fn pad(plaintext: &[u8]) -> Bytes {
    let mut padded = plaintext.to_vec();
    padded.resize(calculate_padded_size(plaintext), 0);
    padded[plaintext.len()] = PADDING_BYTE;
    padded
}

fn encrypt_plaintext(
    ciphertext: &mut [u8],
    key: &SecretKey,
    nonce: &Nonce,
    plaintext: &[u8],
) -> bool {
    let padded = pad(plaintext);
    encrypt(ciphertext, key, nonce, &padded)
}

pub fn encrypt_message(
    ciphertext: &mut [u8],
    index: &mut Index,
    state: &mut State,
    plaintext: &[u8],
) -> bool {
    if !increment_sending_index(state) {
        zeroize(state);
        return false;
    }
    if !encrypt_plaintext(
        ciphertext,
        get_sending_key(state),
        get_sending_nonce(state),
        plaintext,
    ) {
        zeroize(state);
        return false;
    }
    index.copy_from_slice(get_sending_index(state));
    true
}

fn calculate_unpadded_size(padded: &[u8]) -> usize {
    let size = padded.len();
    if size == 0 || (size % PADDING_BLOCK_SIZE) > 0 {
        return 0;
    }
    for i in (size - PADDING_BLOCK_SIZE..size).rev() {
        let byte = padded[i];
        if byte == PADDING_BYTE {
            return i;
        }
        if byte != 0 {
            return 0;
        }
    }
    0
}

fn unpad(unpadded_size: &mut Size, padded: &[u8]) -> bool {
    let size = calculate_unpadded_size(padded);
    if size == 0 {
        return false;
    }
    set_size(unpadded_size, size);
    true
}

fn decrypt_ciphertext(
    plaintext: &mut [u8],
    plaintext_size: &mut Size,
    key: &SecretKey,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> bool {
    if decrypt(plaintext, key, nonce, ciphertext) {
        unpad(plaintext_size, plaintext)
    } else {
        false
    }
}

fn decrypt_current(
    plaintext: &mut [u8],
    plaintext_size: &mut Size,
    state: &mut State,
    ciphertext: &[u8],
) -> bool {
    decrypt_ciphertext(
        plaintext,
        plaintext_size,
        get_receiving_key(state),
        get_receiving_nonce(state),
        ciphertext,
    )
}

fn decrypt_skipped(
    plaintext: &mut [u8],
    plaintext_size: &mut Size,
    index: &mut Index,
    state: &mut State,
    ciphertext: &[u8],
) -> bool {
    let key = get_receiving_key(state);
    let mut nonce: Nonce = [0; NONCE_SIZE];
    let mut offset = get_skipped_index(index, &mut nonce, state, 0);
    while offset > 0 {
        if decrypt_ciphertext(plaintext, plaintext_size, key, &nonce, ciphertext) {
            delete_skipped_index(state, offset);
            return true;
        }
        offset = get_skipped_index(index, &mut nonce, state, offset);
    }
    false
}

pub fn decrypt_message(
    plaintext: &mut [u8],
    plaintext_size: &mut Size,
    index: &mut Index,
    state: &mut State,
    ciphertext: &[u8],
) -> bool {
    let mut success = decrypt_skipped(plaintext, plaintext_size, index, state, ciphertext);
    while !success {
        if !increment_receiving_index(state) {
            zeroize(state);
            return false;
        }
        success = decrypt_current(plaintext, plaintext_size, state, ciphertext);
        if success {
            index.copy_from_slice(get_receiving_index(state));
        } else if !skip_index(state) {
            zeroize(state);
            return false;
        }
    }
    true
}

pub fn certify_data(signature: &mut Signature, state: &State, data: &[u8]) -> bool {
    certify_data_ownership(signature, state, get_their_identity_key(state), data)
}

pub fn certify_identity(signature: &mut Signature, state: &State) -> bool {
    certify_identity_ownership(signature, state, get_their_identity_key(state))
}

pub fn verify_data(
    state: &State,
    data: &[u8],
    public_key: &PublicKey,
    signature: &Signature,
) -> bool {
    verify_data_ownership(get_their_identity_key(state), data, public_key, signature)
}

pub fn verify_identity(state: &State, public_key: &PublicKey, signature: &Signature) -> bool {
    verify_identity_ownership(get_their_identity_key(state), public_key, signature)
}

fn create_ciphertext(plaintext: &[u8]) -> Bytes {
    vec![0; calculate_padded_size(plaintext) + TAG_SIZE]
}

fn create_plaintext(ciphertext: &[u8]) -> Bytes {
    vec![0; ciphertext.len() - TAG_SIZE]
}

fn derive_session_key(key: &mut SecretKey, state: &mut State) -> bool {
    let mut okm: Okm = [0; OKM_SIZE];
    let success = kdf(&mut okm, get_sending_key(state));
    if success {
        key.copy_from_slice(&okm[..SECRET_KEY_SIZE]);
    }
    zeroize(&mut okm);
    success
}

pub fn close_session(key: &mut SecretKey, ciphertext: &mut [u8], state: &mut State) -> bool {
    if !derive_session_key(key, state) {
        zeroize(state);
        return false;
    }
    let mut plaintext = get_session(state).to_vec();
    let nonce: Nonce = [0; NONCE_SIZE];
    let success = encrypt_plaintext(ciphertext, key, &nonce, &plaintext);
    zeroize(state);
    zeroize(&mut plaintext);
    success
}

pub fn open_session(state: &mut State, key: &mut SecretKey, ciphertext: &[u8]) -> bool {
    let mut plaintext = create_plaintext(ciphertext);
    let mut plaintext_size: Size = [0; SIZE_SIZE];
    let nonce: Nonce = [0; NONCE_SIZE];
    let success = decrypt_ciphertext(&mut plaintext, &mut plaintext_size, key, &nonce, ciphertext);
    zeroize(key);
    if success {
        let size = read_size(plaintext_size);
        state[..size].copy_from_slice(&plaintext[..size]);
    }
    success
}

fn resize_plaintext(mut plaintext: Bytes, plaintext_size: Size) -> Bytes {
    plaintext.resize(read_size(plaintext_size), 0);
    plaintext
}

pub fn create_state() -> State {
    [0; STATE_SIZE]
}

pub struct Channel<'a> {
    pub state: &'a mut State,
}

impl<'a> Channel<'a> {
    pub fn new(state: &'a mut State) -> Self {
        Self { state }
    }

    pub fn use_key_pairs(
        &mut self,
        identity_key_pair: KeyPair,
        ephemeral_key_pair: KeyPair,
    ) -> Result<Hello, Error> {
        let mut public_keys: Hello = [0; HELLO_SIZE];
        let success = use_key_pairs(
            &mut public_keys,
            self.state,
            identity_key_pair,
            ephemeral_key_pair,
        );
        if !success {
            Err(Error::Initialization)
        } else {
            Ok(public_keys)
        }
    }

    pub fn use_public_keys(&mut self, public_keys: Hello) {
        use_public_keys(self.state, public_keys)
    }

    pub fn authenticate(&self) -> Result<SafetyNumber, Error> {
        let mut safety_number: SafetyNumber = [0; SAFETY_NUMBER_SIZE];
        let success = authenticate(&mut safety_number, self.state);
        if !success {
            Err(Error::Authentication)
        } else {
            Ok(safety_number)
        }
    }

    pub fn key_exchange(&mut self, is_initiator: bool) -> Result<Signature, Error> {
        let mut signature: Signature = [0; SIGNATURE_SIZE];
        let success = key_exchange(&mut signature, self.state, is_initiator);
        if !success {
            Err(Error::KeyExchange)
        } else {
            Ok(signature)
        }
    }

    pub fn verify_key_exchange(&mut self, signature: Signature) -> Result<(), Error> {
        let verified = verify_key_exchange(self.state, signature);
        if !verified {
            Err(Error::KeyExchange)
        } else {
            Ok(())
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u32, Bytes), Error> {
        let mut ciphertext = create_ciphertext(plaintext);
        let mut index: Index = [0; INDEX_SIZE];
        let success = encrypt_message(&mut ciphertext, &mut index, self.state, plaintext);
        if !success {
            Err(Error::Encryption)
        } else {
            Ok((read_index(index), ciphertext))
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(u32, Bytes), Error> {
        let mut plaintext = create_plaintext(ciphertext);
        let mut size: Size = [0; SIZE_SIZE];
        let mut index: Index = [0; INDEX_SIZE];
        let success = decrypt_message(
            &mut plaintext,
            &mut size,
            &mut index,
            self.state,
            ciphertext,
        );
        if !success {
            Err(Error::Decryption)
        } else {
            Ok((read_index(index), resize_plaintext(plaintext, size)))
        }
    }

    pub fn certify_data(&self, data: &[u8]) -> Result<Signature, Error> {
        let mut signature: Signature = [0; SIGNATURE_SIZE];
        let success = certify_data(&mut signature, self.state, data);
        if !success {
            Err(Error::Certification)
        } else {
            Ok(signature)
        }
    }

    pub fn certify_identity(&self) -> Result<Signature, Error> {
        let mut signature: Signature = [0; SIGNATURE_SIZE];
        let success = certify_identity(&mut signature, self.state);
        if !success {
            Err(Error::Certification)
        } else {
            Ok(signature)
        }
    }

    pub fn verify_data(&self, data: &[u8], public_key: &PublicKey, signature: &Signature) -> bool {
        verify_data(self.state, data, public_key, signature)
    }

    pub fn verify_identity(&self, public_key: &PublicKey, signature: &Signature) -> bool {
        verify_identity(self.state, public_key, signature)
    }

    pub fn close(&mut self) -> Result<(SecretKey, Bytes), Error> {
        let mut key: SecretKey = [0; SECRET_KEY_SIZE];
        let mut ciphertext = create_ciphertext(get_session(self.state));
        let success = close_session(&mut key, &mut ciphertext, self.state);
        if !success {
            Err(Error::Session)
        } else {
            Ok((key, ciphertext))
        }
    }

    pub fn open(&mut self, key: &mut SecretKey, ciphertext: &[u8]) -> Result<(), Error> {
        let success = open_session(self.state, key, ciphertext);
        if !success {
            Err(Error::Session)
        } else {
            Ok(())
        }
    }
}
