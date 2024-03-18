use rand_core::{CryptoRng, RngCore};

use crate::{
    constants::KEY_PAIR_SIZE,
    error::Error,
    external::{init, key_pair_ephemeral, key_pair_identity},
    types::KeyPair,
};

fn ephemeral_key_pair<T: RngCore + CryptoRng>(csprng: T, key_pair: &mut KeyPair) -> bool {
    if !init() {
        return false;
    }
    key_pair_ephemeral(csprng, key_pair)
}

fn identity_key_pair<T: RngCore + CryptoRng>(csprng: T, key_pair: &mut KeyPair) -> bool {
    if !init() {
        return false;
    }
    key_pair_identity(csprng, key_pair)
}

pub fn generate_key_pair<T: RngCore + CryptoRng>(csprng: T) -> Result<KeyPair, Error> {
    let mut key_pair: KeyPair = [0; KEY_PAIR_SIZE];
    let success = ephemeral_key_pair(csprng, &mut key_pair);
    if !success {
        Err(Error::KeyPair)
    } else {
        Ok(key_pair)
    }
}

pub fn generate_identity_key_pair<T: RngCore + CryptoRng>(csprng: T) -> Result<KeyPair, Error> {
    let mut key_pair: KeyPair = [0; KEY_PAIR_SIZE];
    let success = identity_key_pair(csprng, &mut key_pair);
    if !success {
        Err(Error::KeyPair)
    } else {
        Ok(key_pair)
    }
}
