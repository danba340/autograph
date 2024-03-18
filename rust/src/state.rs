use crate::{
    constants::{
        EPHEMERAL_KEY_PAIR_OFFSET, EPHEMERAL_PUBLIC_KEY_OFFSET, IDENTITY_KEY_PAIR_OFFSET,
        IDENTITY_PUBLIC_KEY_OFFSET, INDEX_SIZE, KEY_PAIR_SIZE, NONCE_SIZE, PRIVATE_KEY_SIZE,
        PUBLIC_KEY_SIZE, RECEIVING_INDEX_OFFSET, RECEIVING_KEY_OFFSET, RECEIVING_NONCE_OFFSET,
        SECRET_KEY_SIZE, SENDING_INDEX_OFFSET, SENDING_KEY_OFFSET, SENDING_NONCE_OFFSET,
        SKIPPED_INDEXES_MAX_OFFSET, SKIPPED_INDEXES_MIN_OFFSET, STATE_SIZE,
        THEIR_EPHEMERAL_KEY_OFFSET, THEIR_IDENTITY_KEY_OFFSET, TRANSCRIPT_OFFSET, TRANSCRIPT_SIZE,
    },
    external::zeroize,
    numbers::{get_uint32, set_uint32},
    types::{Index, KeyPair, Nonce, Okm, PrivateKey, PublicKey, SecretKey, State, Transcript},
};

pub fn set_identity_key_pair(state: &mut State, key_pair: &KeyPair) {
    state[IDENTITY_KEY_PAIR_OFFSET..IDENTITY_KEY_PAIR_OFFSET + KEY_PAIR_SIZE]
        .copy_from_slice(key_pair);
}

pub fn get_identity_key_pair(state: &State) -> &KeyPair {
    state[IDENTITY_KEY_PAIR_OFFSET..IDENTITY_KEY_PAIR_OFFSET + KEY_PAIR_SIZE]
        .try_into()
        .unwrap_or(&[0; KEY_PAIR_SIZE])
}

pub fn get_identity_public_key(state: &State) -> &PublicKey {
    state[IDENTITY_PUBLIC_KEY_OFFSET..IDENTITY_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE]
        .try_into()
        .unwrap_or(&[0; PUBLIC_KEY_SIZE])
}

pub fn get_their_identity_key(state: &State) -> &PublicKey {
    state[THEIR_IDENTITY_KEY_OFFSET..THEIR_IDENTITY_KEY_OFFSET + PUBLIC_KEY_SIZE]
        .try_into()
        .unwrap_or(&[0; PUBLIC_KEY_SIZE])
}

pub fn set_their_identity_key(state: &mut State, public_key: &PublicKey) {
    state[THEIR_IDENTITY_KEY_OFFSET..THEIR_IDENTITY_KEY_OFFSET + PUBLIC_KEY_SIZE]
        .copy_from_slice(public_key);
}

pub fn get_sending_nonce(state: &State) -> &Nonce {
    state[SENDING_NONCE_OFFSET..SENDING_NONCE_OFFSET + NONCE_SIZE]
        .try_into()
        .unwrap_or(&[0; NONCE_SIZE])
}

pub fn get_sending_index(state: &State) -> &Index {
    state[SENDING_INDEX_OFFSET..SENDING_INDEX_OFFSET + INDEX_SIZE]
        .try_into()
        .unwrap_or(&[0; INDEX_SIZE])
}

pub fn get_sending_key(state: &State) -> &SecretKey {
    state[SENDING_KEY_OFFSET..SENDING_KEY_OFFSET + SECRET_KEY_SIZE]
        .try_into()
        .unwrap_or(&[0; SECRET_KEY_SIZE])
}

pub fn get_receiving_nonce(state: &State) -> &Nonce {
    state[RECEIVING_NONCE_OFFSET..RECEIVING_NONCE_OFFSET + NONCE_SIZE]
        .try_into()
        .unwrap_or(&[0; NONCE_SIZE])
}

pub fn get_receiving_index(state: &State) -> &Index {
    state[RECEIVING_INDEX_OFFSET..RECEIVING_INDEX_OFFSET + INDEX_SIZE]
        .try_into()
        .unwrap_or(&[0; INDEX_SIZE])
}

pub fn get_receiving_key(state: &State) -> &SecretKey {
    state[RECEIVING_KEY_OFFSET..RECEIVING_KEY_OFFSET + SECRET_KEY_SIZE]
        .try_into()
        .unwrap_or(&[0; SECRET_KEY_SIZE])
}

pub fn set_secret_keys(state: &mut State, is_initiator: bool, okm: &Okm) {
    if is_initiator {
        state[SENDING_KEY_OFFSET..SENDING_KEY_OFFSET + SECRET_KEY_SIZE]
            .copy_from_slice(&okm[..SECRET_KEY_SIZE]);
        state[RECEIVING_KEY_OFFSET..RECEIVING_KEY_OFFSET + SECRET_KEY_SIZE]
            .copy_from_slice(&okm[SECRET_KEY_SIZE..]);
    } else {
        state[SENDING_KEY_OFFSET..SENDING_KEY_OFFSET + SECRET_KEY_SIZE]
            .copy_from_slice(&okm[SECRET_KEY_SIZE..]);
        state[RECEIVING_KEY_OFFSET..RECEIVING_KEY_OFFSET + SECRET_KEY_SIZE]
            .copy_from_slice(&okm[..SECRET_KEY_SIZE]);
    }
}

fn increment_index(state: &mut State, offset: usize) -> bool {
    let index = get_uint32(state, offset);
    if index == u32::MAX {
        return false;
    }
    set_uint32(state, offset, index + 1);
    true
}

pub fn increment_sending_index(state: &mut State) -> bool {
    increment_index(state, SENDING_INDEX_OFFSET)
}

pub fn increment_receiving_index(state: &mut State) -> bool {
    increment_index(state, RECEIVING_INDEX_OFFSET)
}

pub fn set_ephemeral_key_pair(state: &mut State, key_pair: &KeyPair) {
    state[EPHEMERAL_KEY_PAIR_OFFSET..EPHEMERAL_KEY_PAIR_OFFSET + KEY_PAIR_SIZE]
        .copy_from_slice(key_pair);
}

pub fn get_ephemeral_private_key(state: &State) -> &PrivateKey {
    state[EPHEMERAL_KEY_PAIR_OFFSET..EPHEMERAL_KEY_PAIR_OFFSET + PRIVATE_KEY_SIZE]
        .try_into()
        .unwrap_or(&[0; PRIVATE_KEY_SIZE])
}

pub fn delete_ephemeral_private_key(state: &mut State) {
    zeroize(&mut state[EPHEMERAL_KEY_PAIR_OFFSET..EPHEMERAL_KEY_PAIR_OFFSET + PRIVATE_KEY_SIZE]);
}

pub fn get_their_ephemeral_key(state: &State) -> &PublicKey {
    state[THEIR_EPHEMERAL_KEY_OFFSET..THEIR_EPHEMERAL_KEY_OFFSET + PUBLIC_KEY_SIZE]
        .try_into()
        .unwrap_or(&[0; PUBLIC_KEY_SIZE])
}

pub fn set_their_ephemeral_key(state: &mut State, public_key: &PublicKey) {
    state[THEIR_EPHEMERAL_KEY_OFFSET..THEIR_EPHEMERAL_KEY_OFFSET + PUBLIC_KEY_SIZE]
        .copy_from_slice(public_key);
}

pub fn set_transcript(state: &mut State, is_initiator: bool) {
    if is_initiator {
        state.copy_within(
            EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE,
            TRANSCRIPT_OFFSET,
        );
        state.copy_within(
            THEIR_EPHEMERAL_KEY_OFFSET..THEIR_EPHEMERAL_KEY_OFFSET + PUBLIC_KEY_SIZE,
            TRANSCRIPT_OFFSET + PUBLIC_KEY_SIZE,
        );
    } else {
        state.copy_within(
            THEIR_EPHEMERAL_KEY_OFFSET..THEIR_EPHEMERAL_KEY_OFFSET + PUBLIC_KEY_SIZE,
            TRANSCRIPT_OFFSET,
        );
        state.copy_within(
            EPHEMERAL_PUBLIC_KEY_OFFSET..EPHEMERAL_PUBLIC_KEY_OFFSET + PUBLIC_KEY_SIZE,
            TRANSCRIPT_OFFSET + PUBLIC_KEY_SIZE,
        );
    }
}

pub fn get_transcript(state: &State) -> &Transcript {
    state[TRANSCRIPT_OFFSET..TRANSCRIPT_OFFSET + TRANSCRIPT_SIZE]
        .try_into()
        .unwrap_or(&[0; TRANSCRIPT_SIZE])
}

pub fn zeroize_skipped_indexes(state: &mut State) {
    zeroize(&mut state[SKIPPED_INDEXES_MIN_OFFSET..STATE_SIZE]);
}

pub fn calculate_state_size(state: &State) -> usize {
    if get_uint32(state, SKIPPED_INDEXES_MAX_OFFSET) > 0 {
        return STATE_SIZE;
    }
    let mut offset = SKIPPED_INDEXES_MIN_OFFSET;
    while offset < SKIPPED_INDEXES_MAX_OFFSET {
        if get_uint32(state, offset) == 0 {
            return offset;
        }
        offset += INDEX_SIZE;
    }
    STATE_SIZE
}

pub fn skip_index(state: &mut State) -> bool {
    let offset = calculate_state_size(state);
    if offset > SKIPPED_INDEXES_MAX_OFFSET {
        return false;
    }
    state.copy_within(
        RECEIVING_INDEX_OFFSET..RECEIVING_INDEX_OFFSET + INDEX_SIZE,
        offset,
    );
    true
}

pub fn get_skipped_index(
    index: &mut Index,
    nonce: &mut Nonce,
    state: &State,
    offset: usize,
) -> usize {
    let o = if offset == 0 {
        SKIPPED_INDEXES_MIN_OFFSET
    } else {
        offset
    };
    if o > SKIPPED_INDEXES_MAX_OFFSET {
        return 0;
    }
    let next_offset = o + INDEX_SIZE;
    let slice = &state[o..next_offset];
    index.copy_from_slice(slice);
    nonce[NONCE_SIZE - INDEX_SIZE..].copy_from_slice(slice);
    next_offset
}

pub fn delete_skipped_index(state: &mut State, next_offset: usize) {
    let session_size = calculate_state_size(state);
    let offset = next_offset - INDEX_SIZE;
    let last_offset = session_size - INDEX_SIZE;
    if offset != last_offset {
        state.copy_within(last_offset..session_size, offset);
    }
    zeroize(&mut state[last_offset..]);
}

pub fn get_state(state: &State) -> &[u8] {
    &state[..calculate_state_size(state)]
}
