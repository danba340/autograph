use crate::{
    bytes::{
        create_ciphertext, create_handshake, create_index, create_plaintext, create_safety_number,
        create_secret_key, create_session, create_signature, create_size, read_index, resize,
        Bytes,
    },
    clib::{
        autograph_certify_data, autograph_certify_identity, autograph_close_session,
        autograph_decrypt_message, autograph_encrypt_message, autograph_key_exchange,
        autograph_open_session, autograph_safety_number, autograph_verify_data,
        autograph_verify_identity, autograph_verify_key_exchange,
    },
    error::Error,
    key_pair::KeyPair,
};

pub struct Channel<'a> {
    state: &'a mut Bytes,
}

impl<'a> Channel<'a> {
    pub fn new(state: &'a mut Bytes) -> Self {
        Self { state }
    }

    pub fn calculate_safety_number(&self) -> Result<Bytes, Error> {
        let mut safety_number = create_safety_number();
        let success =
            unsafe { autograph_safety_number(safety_number.as_mut_ptr(), self.state.as_ptr()) }
                == 1;
        if !success {
            Err(Error::SafetyNumber)
        } else {
            Ok(safety_number)
        }
    }

    pub fn certify_data(&self, data: &Bytes) -> Result<Bytes, Error> {
        let mut signature = create_signature();
        let success = unsafe {
            autograph_certify_data(
                signature.as_mut_ptr(),
                self.state.as_ptr(),
                data.as_ptr(),
                data.len().try_into().unwrap(),
            )
        } == 1;
        if !success {
            Err(Error::Certification)
        } else {
            Ok(signature)
        }
    }

    pub fn certify_identity(&self) -> Result<Bytes, Error> {
        let mut signature = create_signature();
        let success =
            unsafe { autograph_certify_identity(signature.as_mut_ptr(), self.state.as_ptr()) } == 1;
        if !success {
            Err(Error::Certification)
        } else {
            Ok(signature)
        }
    }

    pub fn close(&mut self) -> Result<(Bytes, Bytes), Error> {
        let mut key = create_secret_key();
        let mut ciphertext = create_session(self.state);
        let success = unsafe {
            autograph_close_session(
                key.as_mut_ptr(),
                ciphertext.as_mut_ptr(),
                self.state.as_mut_ptr(),
            )
        } == 1;
        if !success {
            Err(Error::Session)
        } else {
            Ok((key, ciphertext))
        }
    }

    pub fn decrypt(&mut self, message: &Bytes) -> Result<(u32, Bytes), Error> {
        let mut plaintext = create_plaintext(message);
        let mut index = create_index();
        let mut size = create_size();
        let success = unsafe {
            autograph_decrypt_message(
                plaintext.as_mut_ptr(),
                size.as_mut_ptr(),
                index.as_mut_ptr(),
                self.state.as_mut_ptr(),
                message.as_ptr(),
                message.len().try_into().unwrap(),
            )
        } == 1;
        if !success {
            Err(Error::Decryption)
        } else {
            resize(&mut plaintext, &size);
            Ok((read_index(&index), plaintext))
        }
    }

    pub fn encrypt(&mut self, plaintext: &Bytes) -> Result<(u32, Bytes), Error> {
        let mut ciphertext = create_ciphertext(plaintext);
        let mut index = create_index();
        let success = unsafe {
            autograph_encrypt_message(
                ciphertext.as_mut_ptr(),
                index.as_mut_ptr(),
                self.state.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len().try_into().unwrap(),
            )
        } == 1;
        if !success {
            Err(Error::Encryption)
        } else {
            Ok((read_index(&index), ciphertext))
        }
    }

    pub fn open(&mut self, secret_key: &mut Bytes, ciphertext: &Bytes) -> bool {
        let result = unsafe {
            autograph_open_session(
                self.state.as_mut_ptr(),
                secret_key.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len().try_into().unwrap(),
            )
        };
        result == 1
    }

    pub fn perform_key_exchange(
        &mut self,
        is_initiator: bool,
        our_identity_key_pair: &KeyPair,
        our_ephemeral_key_pair: &mut KeyPair,
        their_identity_key: &Bytes,
        their_ephemeral_key: &Bytes,
    ) -> Result<Bytes, Error> {
        let mut handshake = create_handshake();
        let success = unsafe {
            autograph_key_exchange(
                handshake.as_mut_ptr(),
                self.state.as_mut_ptr(),
                if is_initiator { 1 } else { 0 },
                our_identity_key_pair.private_key.as_ptr(),
                our_identity_key_pair.public_key.as_ptr(),
                our_ephemeral_key_pair.private_key.as_mut_ptr(),
                our_ephemeral_key_pair.public_key.as_ptr(),
                their_identity_key.as_ptr(),
                their_ephemeral_key.as_ptr(),
            )
        } == 1;
        if !success {
            Err(Error::KeyExchange)
        } else {
            Ok(handshake)
        }
    }

    pub fn verify_data(&self, data: &Bytes, public_key: &Bytes, signature: &Bytes) -> bool {
        let result = unsafe {
            autograph_verify_data(
                self.state.as_ptr(),
                data.as_ptr(),
                data.len().try_into().unwrap(),
                public_key.as_ptr(),
                signature.as_ptr(),
            )
        };
        result == 1
    }

    pub fn verify_identity(&self, public_key: &Bytes, signature: &Bytes) -> bool {
        let result = unsafe {
            autograph_verify_identity(self.state.as_ptr(), public_key.as_ptr(), signature.as_ptr())
        };
        result == 1
    }

    pub fn verify_key_exchange(
        &mut self,
        our_ephemeral_public_key: &Bytes,
        their_handshake: &Bytes,
    ) -> bool {
        let result = unsafe {
            autograph_verify_key_exchange(
                self.state.as_mut_ptr(),
                our_ephemeral_public_key.as_ptr(),
                their_handshake.as_ptr(),
            )
        };
        result == 1
    }
}
