#![no_std]

extern crate alloc;
extern crate chacha20poly1305;
extern crate ed25519_dalek;
extern crate hkdf;
extern crate rand_core;
extern crate sha2;
extern crate x25519_dalek;
extern crate zeroize;

mod auth;
mod cert;
mod channel;
mod constants;
mod error;
mod external;
mod kdf;
mod key_exchange;
mod key_pair;
mod numbers;
mod state;
mod types;

pub use channel::{create_state, Channel};
pub use constants::{
    HELLO_SIZE, KEY_PAIR_SIZE, PUBLIC_KEY_SIZE, SAFETY_NUMBER_SIZE, SECRET_KEY_SIZE,
    SIGNATURE_SIZE, STATE_SIZE,
};
pub use key_pair::{generate_identity_key_pair, generate_key_pair};
pub use types::{Bytes, Hello, KeyPair, PublicKey, SafetyNumber, SecretKey, Signature, State};
