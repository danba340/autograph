use crate::bytes::{create_private_key, create_public_key, Bytes};
use crate::clib::{autograph_ephemeral_key_pair, autograph_identity_key_pair};
use crate::error::Error;

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub private_key: Bytes,
    pub public_key: Bytes,
}

fn create_key_pair() -> KeyPair {
    KeyPair {
        private_key: create_private_key(),
        public_key: create_public_key(),
    }
}

pub fn generate_ephemeral_key_pair() -> Result<KeyPair, Error> {
    let mut key_pair = create_key_pair();
    let success = unsafe {
        autograph_ephemeral_key_pair(
            key_pair.private_key.as_mut_ptr(),
            key_pair.public_key.as_mut_ptr(),
        )
    } == 1;
    if !success {
        Err(Error::KeyPair)
    } else {
        Ok(key_pair)
    }
}

pub fn generate_identity_key_pair() -> Result<KeyPair, Error> {
    let mut key_pair = create_key_pair();
    let success = unsafe {
        autograph_identity_key_pair(
            key_pair.private_key.as_mut_ptr(),
            key_pair.public_key.as_mut_ptr(),
        )
    } == 1;
    if !success {
        Err(Error::KeyPair)
    } else {
        Ok(key_pair)
    }
}
