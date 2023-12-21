use alloc::vec;
use alloc::vec::Vec;

use crate::clib::{
    autograph_ciphertext_size, autograph_plaintext_size, autograph_read_index, autograph_read_size,
    autograph_session_size,
};

pub type Bytes = Vec<u8>;

fn create_bytes(size: u32) -> Bytes {
    vec![0; size.try_into().unwrap()]
}

pub fn create_ciphertext(plaintext: &Bytes) -> Bytes {
    let size = unsafe { autograph_ciphertext_size(plaintext.len().try_into().unwrap()) };
    create_bytes(size)
}

pub fn create_handshake() -> Bytes {
    create_bytes(80)
}

pub fn create_index() -> Bytes {
    create_bytes(4)
}

pub fn create_plaintext(ciphertext: &Bytes) -> Bytes {
    let size = unsafe { autograph_plaintext_size(ciphertext.len().try_into().unwrap()) };
    create_bytes(size)
}

pub fn create_private_key() -> Bytes {
    create_bytes(32)
}

pub fn create_public_key() -> Bytes {
    create_bytes(32)
}

pub fn create_safety_number() -> Bytes {
    create_bytes(64)
}

pub fn create_secret_key() -> Bytes {
    create_bytes(32)
}

pub fn create_session(state: &Bytes) -> Bytes {
    let size = unsafe { autograph_session_size(state.as_ptr()) };
    create_bytes(size.into())
}

pub fn create_signature() -> Bytes {
    create_bytes(64)
}

pub fn create_size() -> Bytes {
    create_bytes(4)
}

pub fn create_state() -> Bytes {
    create_bytes(9348)
}

pub fn read_index(bytes: &Bytes) -> u32 {
    unsafe { autograph_read_index(bytes.as_ptr()) }
}

pub fn resize(bytes: &mut Bytes, size_bytes: &Bytes) {
    let size = unsafe { autograph_read_size(size_bytes.as_ptr()) };
    bytes.resize(size.try_into().unwrap(), 0)
}
