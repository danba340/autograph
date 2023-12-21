#![no_std]

extern crate alloc;

mod bytes;
mod channel;
mod clib;
mod error;
mod key_pair;

pub use bytes::create_state;
pub use channel::Channel;
pub use error::Error;
pub use key_pair::{generate_ephemeral_key_pair, generate_identity_key_pair, KeyPair};
