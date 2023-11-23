use alloc::vec;
use alloc::vec::Vec;

use crate::clib::{autograph_ciphertext_size, autograph_plaintext_size, autograph_subject_size};

pub static HANDSHAKE_SIZE: usize = 96;
pub static INDEX_SIZE: usize = 8;
pub static PRIVATE_KEY_SIZE: usize = 32;
pub static PUBLIC_KEY_SIZE: usize = 32;
pub static SAFETY_NUMBER_SIZE: usize = 60;
pub static SECRET_KEY_SIZE: usize = 32;
pub static SIGNATURE_SIZE: usize = 64;
pub static SIZE_SIZE: usize = 4;
pub static SKIPPED_KEYS_SIZE: usize = 40002;
pub static TRANSCRIPT_SIZE: usize = 128;

fn create_bytes(size: usize) -> Vec<u8> {
    vec![0; size]
}

pub fn create_ciphertext_bytes(size: usize) -> Vec<u8> {
    let ciphertext_size = unsafe { autograph_ciphertext_size(size as u32) as usize };
    create_bytes(ciphertext_size)
}

pub fn create_handshake_bytes() -> Vec<u8> {
    create_bytes(HANDSHAKE_SIZE)
}

pub fn create_index_bytes() -> Vec<u8> {
    create_bytes(INDEX_SIZE)
}

pub fn create_plaintext_bytes(size: usize) -> Vec<u8> {
    let plaintext_size = unsafe { autograph_plaintext_size(size as u32) as usize };
    create_bytes(plaintext_size)
}

pub fn create_private_key_bytes() -> Vec<u8> {
    create_bytes(PRIVATE_KEY_SIZE)
}

pub fn create_public_key_bytes() -> Vec<u8> {
    create_bytes(PUBLIC_KEY_SIZE)
}

pub fn create_safety_number_bytes() -> Vec<u8> {
    create_bytes(SAFETY_NUMBER_SIZE)
}

pub fn create_secret_key_bytes() -> Vec<u8> {
    create_bytes(SECRET_KEY_SIZE)
}

pub fn create_signature_bytes() -> Vec<u8> {
    create_bytes(SIGNATURE_SIZE)
}

pub fn create_size_bytes() -> Vec<u8> {
    create_bytes(SIZE_SIZE)
}

pub fn create_skipped_keys_bytes() -> Vec<u8> {
    create_bytes(SKIPPED_KEYS_SIZE)
}

pub fn create_subject_bytes(size: usize) -> Vec<u8> {
    let subject_size = unsafe { autograph_subject_size(size as u32) as usize };
    create_bytes(subject_size)
}

pub fn create_transcript_bytes() -> Vec<u8> {
    create_bytes(TRANSCRIPT_SIZE)
}
