use alloc::{vec, vec::Vec};

use crate::{
    constants::PUBLIC_KEY_SIZE,
    external::{sign, verify},
    state::get_identity_key_pair,
    types::{PublicKey, Signature, State},
};

fn create_subject(data: &[u8]) -> Vec<u8> {
    let max_size = (u32::MAX as usize) - PUBLIC_KEY_SIZE;
    let data_size = if data.len() > max_size {
        max_size
    } else {
        data.len()
    };
    vec![0; data_size + PUBLIC_KEY_SIZE]
}

fn calculate_subject(public_key: &PublicKey, data: &[u8]) -> Vec<u8> {
    let mut subject = create_subject(data);
    let key_offset = subject.len() - PUBLIC_KEY_SIZE;
    subject[..key_offset].copy_from_slice(&data[..key_offset]);
    subject[key_offset..].copy_from_slice(public_key);
    subject
}

fn sign_subject(signature: &mut Signature, state: &State, subject: &[u8]) -> bool {
    sign(signature, get_identity_key_pair(state), subject)
}

pub fn certify_data_ownership(
    signature: &mut Signature,
    state: &State,
    owner_public_key: &PublicKey,
    data: &[u8],
) -> bool {
    let subject = calculate_subject(owner_public_key, data);
    sign_subject(signature, state, &subject)
}

pub fn certify_identity_ownership(
    signature: &mut Signature,
    state: &State,
    owner_public_key: &PublicKey,
) -> bool {
    sign_subject(signature, state, owner_public_key)
}

pub fn verify_data_ownership(
    owner_public_key: &PublicKey,
    data: &[u8],
    certifier_public_key: &PublicKey,
    signature: &Signature,
) -> bool {
    let subject = calculate_subject(owner_public_key, data);
    verify(certifier_public_key, signature, &subject)
}

pub fn verify_identity_ownership(
    owner_public_key: &PublicKey,
    certifier_public_key: &PublicKey,
    signature: &Signature,
) -> bool {
    verify(certifier_public_key, signature, owner_public_key)
}
