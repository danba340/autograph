use crate::{
    cert::{certify_data_ownership, verify_data_ownership},
    constants::{OKM_SIZE, SHARED_SECRET_SIZE},
    external::{diffie_hellman, zeroize},
    kdf::kdf,
    state::{
        delete_ephemeral_private_key, get_ephemeral_private_key, get_identity_public_key,
        get_their_ephemeral_key, get_their_identity_key, get_transcript, set_secret_keys,
        set_transcript, zeroize_skipped_indexes,
    },
    types::{Okm, SharedSecret, Signature, State},
};

fn derive_secret_keys(state: &mut State, is_initiator: bool) -> bool {
    let mut shared_secret: SharedSecret = [0; SHARED_SECRET_SIZE];
    let mut okm: Okm = [0; OKM_SIZE];
    let dh_success = diffie_hellman(
        &mut shared_secret,
        get_ephemeral_private_key(state),
        get_their_ephemeral_key(state),
    );
    let kdf_success = kdf(&mut okm, &shared_secret);
    set_secret_keys(state, is_initiator, &okm);
    zeroize(&mut shared_secret);
    zeroize(&mut okm);
    dh_success && kdf_success
}

pub fn key_exchange(our_signature: &mut Signature, state: &mut State, is_initiator: bool) -> bool {
    set_transcript(state, is_initiator);
    let key_success = derive_secret_keys(state, is_initiator);
    delete_ephemeral_private_key(state);
    let certify_success = certify_data_ownership(
        our_signature,
        state,
        get_their_identity_key(state),
        get_transcript(state),
    );
    if !certify_success || !key_success {
        zeroize(state);
        return false;
    }
    true
}

pub fn verify_key_exchange(state: &mut State, their_signature: Signature) -> bool {
    if !verify_data_ownership(
        get_identity_public_key(state),
        get_transcript(state),
        get_their_identity_key(state),
        &their_signature,
    ) {
        zeroize(state);
        return false;
    }
    zeroize_skipped_indexes(state);
    true
}
