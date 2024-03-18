use crate::{
    constants::{DIGEST_SIZE, FINGERPRINT_DIVISOR, FINGERPRINT_ITERATIONS, FINGERPRINT_SIZE},
    external::hash,
    numbers::{get_uint32, set_uint32},
    state::{get_identity_public_key, get_their_identity_key},
    types::{Digest, Fingerprint, PublicKey, SafetyNumber, State},
};

fn encode_fingerprint(fingerprint: &mut Fingerprint, digest: &Digest) {
    for i in (0..FINGERPRINT_SIZE).step_by(4) {
        let n = get_uint32(digest, i);
        set_uint32(fingerprint, i, n % FINGERPRINT_DIVISOR);
    }
}

fn calculate_fingerprint(fingerprint: &mut Fingerprint, public_key: &PublicKey) -> bool {
    let mut a = [0; DIGEST_SIZE];
    let mut b = [0; DIGEST_SIZE];
    if !hash(&mut a, public_key) {
        return false;
    }
    for _ in 1..FINGERPRINT_ITERATIONS {
        if !hash(&mut b, &a) {
            return false;
        }
        a.copy_from_slice(&b);
    }
    encode_fingerprint(fingerprint, &a);
    true
}

fn set_safety_number(safety_number: &mut SafetyNumber, a: &Fingerprint, b: &Fingerprint) {
    safety_number[..FINGERPRINT_SIZE].copy_from_slice(a);
    safety_number[FINGERPRINT_SIZE..].copy_from_slice(b);
}

pub fn authenticate(safety_number: &mut SafetyNumber, state: &State) -> bool {
    let mut our_fingerprint = [0; FINGERPRINT_SIZE];
    let mut their_fingerprint = [0; FINGERPRINT_SIZE];
    if !calculate_fingerprint(&mut our_fingerprint, get_identity_public_key(state)) {
        return false;
    }
    if !calculate_fingerprint(&mut their_fingerprint, get_their_identity_key(state)) {
        return false;
    }
    if their_fingerprint > our_fingerprint {
        set_safety_number(safety_number, &their_fingerprint, &our_fingerprint);
    } else {
        set_safety_number(safety_number, &our_fingerprint, &their_fingerprint);
    }
    true
}
