use rand::rngs::OsRng;

use autograph::{generate_identity_key_pair, generate_key_pair, KEY_PAIR_SIZE};

#[test]
fn test_generate_ephemeral_key_pair() {
    let key_pair = generate_key_pair(OsRng).unwrap();
    assert_ne!(key_pair, [0; KEY_PAIR_SIZE]);
}

#[test]
fn test_generate_identity_key_pair() {
    let key_pair = generate_identity_key_pair(OsRng).unwrap();
    assert_ne!(key_pair, [0; KEY_PAIR_SIZE]);
}
