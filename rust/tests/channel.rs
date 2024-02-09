use autograph_protocol::{
    Bytes, Channel, KeyPair, PublicKey, SafetyNumber, Signature, State, SECRET_KEY_SIZE, STATE_SIZE,
};

#[test]
fn test_channel() {
    let alice_handshake: Signature = [
        19, 133, 19, 97, 135, 34, 43, 49, 100, 198, 150, 205, 26, 151, 20, 127, 115, 193, 120, 209,
        25, 46, 221, 194, 223, 118, 62, 0, 135, 6, 112, 250, 198, 247, 231, 85, 152, 245, 201, 47,
        180, 83, 200, 165, 154, 43, 133, 97, 27, 25, 35, 233, 170, 220, 170, 38, 185, 233, 61, 160,
        12, 117, 73, 8,
    ];

    let bob_handshake: Signature = [
        89, 193, 59, 76, 215, 36, 171, 145, 63, 32, 134, 60, 225, 112, 136, 191, 176, 64, 42, 18,
        210, 2, 33, 212, 243, 245, 230, 147, 182, 20, 81, 101, 170, 221, 69, 164, 224, 166, 188,
        170, 197, 114, 55, 218, 48, 218, 29, 56, 98, 91, 236, 12, 10, 64, 82, 140, 15, 76, 243,
        188, 24, 236, 62, 5,
    ];

    let alice_message = vec![
        51, 243, 8, 165, 206, 25, 129, 63, 124, 51, 176, 40, 21, 4, 178, 3, 128, 195, 26, 68, 65,
        200, 192, 212, 63, 10, 201, 247, 177, 3, 137, 113,
    ];

    let bob_message = vec![
        253, 199, 105, 203, 139, 136, 132, 228, 198, 157, 65, 140, 116, 90, 212, 112, 55, 190, 186,
        221, 205, 80, 46, 24, 161, 117, 201, 113, 133, 213, 29, 105,
    ];

    let alice_signature_bob_data: Signature = [
        198, 235, 143, 145, 121, 29, 143, 128, 167, 118, 33, 71, 38, 209, 169, 2, 134, 90, 203, 72,
        171, 252, 236, 237, 55, 41, 227, 248, 198, 165, 58, 185, 31, 70, 147, 96, 181, 33, 188, 7,
        146, 43, 24, 197, 158, 216, 215, 49, 126, 186, 88, 238, 233, 86, 167, 207, 20, 150, 227,
        38, 160, 68, 82, 8,
    ];

    let alice_signature_bob_identity: Signature = [
        170, 64, 159, 119, 20, 17, 130, 46, 124, 70, 154, 47, 90, 7, 116, 204, 255, 198, 56, 60,
        24, 112, 214, 188, 212, 64, 210, 117, 228, 145, 111, 250, 84, 20, 216, 222, 21, 82, 213,
        225, 31, 28, 152, 211, 16, 82, 131, 7, 248, 186, 255, 184, 35, 205, 183, 167, 138, 179,
        217, 135, 163, 124, 13, 5,
    ];

    let bob_signature_alice_data: Signature = [
        17, 229, 247, 220, 138, 161, 5, 224, 147, 178, 230, 168, 132, 164, 94, 3, 119, 118, 16,
        163, 222, 85, 3, 160, 88, 222, 210, 140, 222, 158, 254, 231, 182, 232, 78, 211, 150, 146,
        127, 164, 238, 221, 119, 12, 230, 54, 49, 103, 177, 72, 126, 225, 214, 41, 80, 214, 247,
        95, 23, 145, 227, 87, 172, 4,
    ];

    let bob_signature_alice_identity: Signature = [
        186, 27, 195, 159, 150, 127, 96, 11, 25, 224, 30, 145, 56, 194, 138, 164, 70, 54, 243, 213,
        229, 203, 179, 218, 207, 213, 168, 160, 56, 32, 164, 245, 49, 102, 200, 36, 172, 152, 113,
        5, 82, 196, 154, 90, 20, 27, 180, 61, 189, 171, 20, 194, 165, 165, 65, 178, 190, 16, 44,
        82, 157, 68, 102, 13,
    ];

    let charlie_identity_key: PublicKey = [
        129, 128, 10, 70, 174, 223, 175, 90, 43, 37, 148, 125, 188, 163, 110, 136, 15, 246, 192,
        76, 167, 8, 26, 149, 219, 223, 83, 47, 193, 159, 6, 3,
    ];

    let charlie_signature_alice_data: Signature = [
        231, 126, 138, 39, 145, 83, 130, 243, 2, 56, 53, 185, 199, 242, 217, 239, 118, 208, 172, 6,
        201, 132, 94, 179, 57, 59, 160, 23, 150, 221, 67, 122, 176, 56, 160, 63, 7, 161, 169, 101,
        240, 97, 108, 137, 142, 99, 197, 44, 179, 142, 37, 4, 135, 162, 118, 160, 119, 245, 234,
        39, 26, 75, 71, 6,
    ];

    let charlie_signature_alice_identity: Signature = [
        146, 120, 170, 85, 78, 187, 162, 243, 234, 149, 138, 201, 18, 132, 187, 129, 45, 53, 116,
        227, 178, 209, 200, 224, 149, 91, 166, 120, 203, 73, 138, 189, 63, 231, 213, 177, 163, 114,
        66, 151, 61, 253, 109, 250, 226, 140, 249, 3, 188, 44, 127, 108, 196, 131, 204, 216, 54,
        239, 157, 49, 107, 202, 123, 9,
    ];

    let charlie_signature_bob_data: Signature = [
        135, 249, 64, 214, 240, 146, 173, 141, 97, 18, 16, 47, 83, 125, 13, 166, 169, 96, 99, 21,
        215, 217, 236, 173, 120, 50, 143, 251, 228, 76, 195, 8, 248, 133, 170, 103, 122, 169, 190,
        57, 51, 14, 171, 199, 229, 55, 55, 195, 53, 202, 139, 118, 93, 68, 131, 96, 175, 50, 31,
        243, 170, 34, 102, 1,
    ];

    let charlie_signature_bob_identity: Signature = [
        198, 41, 56, 189, 24, 9, 75, 102, 228, 51, 193, 102, 25, 51, 92, 1, 192, 219, 16, 17, 22,
        28, 22, 16, 198, 67, 248, 16, 98, 164, 99, 243, 254, 45, 69, 156, 50, 115, 205, 43, 155,
        242, 78, 64, 205, 218, 80, 171, 34, 128, 255, 51, 237, 60, 37, 224, 232, 149, 153, 213,
        204, 93, 26, 7,
    ];

    let data = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

    let safety_number: SafetyNumber = [
        0, 0, 126, 217, 0, 0, 218, 180, 0, 1, 102, 162, 0, 0, 41, 97, 0, 0, 40, 245, 0, 1, 15, 218,
        0, 0, 12, 28, 0, 0, 98, 95, 0, 0, 96, 224, 0, 0, 16, 147, 0, 1, 74, 101, 0, 1, 33, 26, 0,
        0, 234, 68, 0, 0, 190, 212, 0, 1, 96, 162, 0, 0, 48, 226,
    ];

    let alice_identity_key_pair: KeyPair = [
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88, 124, 93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243,
        24, 225, 91, 220, 141, 150,
    ];

    let bob_identity_key_pair: KeyPair = [
        52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17, 150, 95, 221, 247, 33,
        201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190, 177, 67, 45, 125, 158, 190,
        181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200, 62, 29, 37, 150, 228, 137,
        114, 143, 77, 115, 135, 143, 103,
    ];

    let alice_ephemeral_key_pair: KeyPair = [
        201, 142, 54, 248, 151, 150, 224, 79, 30, 126, 207, 157, 118, 85, 9, 212, 148, 156, 73,
        176, 107, 107, 47, 111, 95, 98, 33, 192, 80, 223, 48, 221, 35, 16, 23, 37, 205, 131, 166,
        97, 13, 81, 136, 246, 193, 253, 139, 193, 230, 155, 222, 221, 37, 114, 190, 87, 104, 44,
        210, 144, 127, 176, 198, 45,
    ];

    let bob_ephemeral_key_pair: KeyPair = [
        74, 233, 106, 152, 76, 212, 181, 144, 132, 237, 223, 58, 122, 173, 99, 100, 152, 219, 214,
        210, 213, 72, 171, 73, 167, 92, 199, 196, 176, 66, 213, 208, 88, 115, 171, 4, 34, 181, 120,
        21, 10, 39, 204, 215, 158, 210, 177, 243, 28, 138, 52, 91, 236, 55, 30, 117, 10, 125, 87,
        232, 80, 6, 232, 93,
    ];

    let mut alice_state: State = [0; STATE_SIZE];
    let mut bob_state: State = [0; STATE_SIZE];
    let mut a = Channel::new(&mut alice_state);
    let mut b = Channel::new(&mut bob_state);
    test_key_exchange(
        &mut a,
        &mut b,
        alice_identity_key_pair,
        alice_ephemeral_key_pair,
        bob_identity_key_pair,
        bob_ephemeral_key_pair,
        alice_handshake,
        bob_handshake,
    );
    test_authenticate(&a, &b, safety_number);
    test_alice_message_to_bob(&mut a, &mut b, &data, alice_message);
    test_bob_message_to_alice(&mut a, &mut b, &data, bob_message);
    test_bob_certify_alice_data(&b, &data, bob_signature_alice_data);
    test_alice_certify_bob_data(&a, &data, alice_signature_bob_data);
    test_bob_certify_alice_identity(&b, bob_signature_alice_identity);
    test_alice_certify_bob_identity(&a, alice_signature_bob_identity);
    test_bob_verify_alice_data(
        &b,
        &data,
        &charlie_identity_key,
        charlie_signature_alice_data,
    );
    test_alice_verify_bob_data(&a, &data, &charlie_identity_key, charlie_signature_bob_data);
    test_bob_verify_alice_identity(&b, &charlie_identity_key, charlie_signature_alice_identity);
    test_alice_verify_bob_identity(&a, &charlie_identity_key, charlie_signature_bob_identity);
    test_out_of_order_messages(&mut a, &mut b);
}

// Should allow Alice and Bob to perform a key exchange
#[allow(clippy::too_many_arguments)]
fn test_key_exchange(
    a: &mut Channel,
    b: &mut Channel,
    alice_identity_key_pair: KeyPair,
    alice_ephemeral_key_pair: KeyPair,
    bob_identity_key_pair: KeyPair,
    bob_ephemeral_key_pair: KeyPair,
    alice_handshake: Signature,
    bob_handshake: Signature,
) {
    let alice_hello = a
        .use_key_pairs(alice_identity_key_pair, alice_ephemeral_key_pair)
        .unwrap();
    let bob_hello = b
        .use_key_pairs(bob_identity_key_pair, bob_ephemeral_key_pair)
        .unwrap();
    a.use_public_keys(bob_hello);
    b.use_public_keys(alice_hello);
    let handshake_alice = a.key_exchange(true).unwrap();
    let handshake_bob = b.key_exchange(false).unwrap();
    a.verify_key_exchange(handshake_bob).unwrap();
    b.verify_key_exchange(handshake_alice).unwrap();
    assert_eq!(handshake_alice, alice_handshake);
    assert_eq!(handshake_bob, bob_handshake);
}

// Should calculate safety numbers correctly
fn test_authenticate(a: &Channel, b: &Channel, safety_number: SafetyNumber) {
    let alice_safety_number = a.authenticate().unwrap();
    let bob_safety_number = b.authenticate().unwrap();
    assert_eq!(alice_safety_number, safety_number);
    assert_eq!(bob_safety_number, safety_number);
}

// Should allow Alice to send encrypted data to Bob
fn test_alice_message_to_bob(a: &mut Channel, b: &mut Channel, data: &[u8], alice_message: Bytes) {
    let (encrypt_index, message) = a.encrypt(data).unwrap();
    let (decrypt_index, plaintext) = b.decrypt(&message).unwrap();
    assert_eq!(encrypt_index, 1);
    assert_eq!(decrypt_index, 1);
    assert_eq!(plaintext, data);
    assert_eq!(message, alice_message);
}

// Should allow Bob to send encrypted data to Alice
fn test_bob_message_to_alice(a: &mut Channel, b: &mut Channel, data: &[u8], bob_message: Bytes) {
    let (_, message) = b.encrypt(data).unwrap();
    let (_, plaintext) = a.decrypt(&message).unwrap();
    assert_eq!(plaintext, data);
    assert_eq!(message, bob_message);
}

// Should allow Bob to certify Alice's ownership of her identity key and data
fn test_bob_certify_alice_data(b: &Channel, data: &[u8], bob_signature_alice_data: Signature) {
    let signature = b.certify_data(data).unwrap();
    assert_eq!(signature, bob_signature_alice_data);
}

// Should allow Alice to certify Bob's ownership of his identity key and data
fn test_alice_certify_bob_data(a: &Channel, data: &[u8], alice_signature_bob_data: Signature) {
    let signature = a.certify_data(data).unwrap();
    assert_eq!(signature, alice_signature_bob_data);
}

// Should allow Bob to certify Alice's ownership of her identity key
fn test_bob_certify_alice_identity(b: &Channel, bob_signature_alice_identity: Signature) {
    let signature = b.certify_identity().unwrap();
    assert_eq!(signature, bob_signature_alice_identity);
}

// Should allow Alice to certify Bob's ownership of his identity key
fn test_alice_certify_bob_identity(a: &Channel, alice_signature_bob_identity: Signature) {
    let signature = a.certify_identity().unwrap();
    assert_eq!(signature, alice_signature_bob_identity);
}

// Should allow Bob to verify Alice's ownership of her identity key and data
// based on Charlie's public key and signature
fn test_bob_verify_alice_data(
    b: &Channel,
    data: &[u8],
    charlie_identity_key: &PublicKey,
    charlie_signature_alice_data: Signature,
) {
    let verified = b.verify_data(data, charlie_identity_key, &charlie_signature_alice_data);
    assert!(verified);
}

// Should allow Alice to verify Bob's ownership of his identity key and ddata
// based on Charlie's public key and signature
fn test_alice_verify_bob_data(
    a: &Channel,
    data: &[u8],
    charlie_identity_key: &PublicKey,
    charlie_signature_bob_data: Signature,
) {
    let verified = a.verify_data(data, charlie_identity_key, &charlie_signature_bob_data);
    assert!(verified);
}

// Should allow Bob to verify Alice's ownership of her identity key based on
// Charlie's public key and signature
fn test_bob_verify_alice_identity(
    b: &Channel,
    charlie_identity_key: &PublicKey,
    charlie_signature_alice_identity: Signature,
) {
    let verified = b.verify_identity(charlie_identity_key, &charlie_signature_alice_identity);
    assert!(verified);
}

// Should allow Alice to verify Bob's ownership of his identity key based on
// Charlie's public key and signature
fn test_alice_verify_bob_identity(
    a: &Channel,
    charlie_identity_key: &PublicKey,
    charlie_signature_bob_identity: Signature,
) {
    let verified = a.verify_identity(charlie_identity_key, &charlie_signature_bob_identity);
    assert!(verified);
}

// Should handle out of order messages correctly
fn test_out_of_order_messages(a: &mut Channel, b: &mut Channel) {
    let data1 = vec![1, 2, 3];
    let data2 = vec![4, 5, 6];
    let data3 = vec![7, 8, 9];
    let data4 = vec![10, 11, 12];
    let (_, message1) = a.encrypt(&data1).unwrap();
    let (_, message2) = a.encrypt(&data2).unwrap();
    let (_, message3) = a.encrypt(&data3).unwrap();
    let (_, message4) = a.encrypt(&data4).unwrap();
    let (index4, plaintext4) = b.decrypt(&message4).unwrap();
    let (index2, plaintext2) = b.decrypt(&message2).unwrap();
    let (index3, plaintext3) = b.decrypt(&message3).unwrap();
    let (index1, plaintext1) = b.decrypt(&message1).unwrap();
    // Index start at 2 since another test (test_alice_message_to_bob) that
    // uses the same channel ran before this test
    assert_eq!(index1, 2);
    assert_eq!(index2, 3);
    assert_eq!(index3, 4);
    assert_eq!(index4, 5);
    assert_eq!(plaintext1, data1);
    assert_eq!(plaintext2, data2);
    assert_eq!(plaintext3, data3);
    assert_eq!(plaintext4, data4);
}

// Should handle sessions correctly
#[test]
fn test_session() {
    let alice_signature_bob_identity: Signature = [
        170, 64, 159, 119, 20, 17, 130, 46, 124, 70, 154, 47, 90, 7, 116, 204, 255, 198, 56, 60,
        24, 112, 214, 188, 212, 64, 210, 117, 228, 145, 111, 250, 84, 20, 216, 222, 21, 82, 213,
        225, 31, 28, 152, 211, 16, 82, 131, 7, 248, 186, 255, 184, 35, 205, 183, 167, 138, 179,
        217, 135, 163, 124, 13, 5,
    ];

    let mut alice_state_init = vec![
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88, 124, 93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243,
        24, 225, 91, 220, 141, 150, 177, 67, 45, 125, 158, 190, 181, 222, 101, 149, 224, 200, 223,
        235, 222, 110, 67, 61, 200, 62, 29, 37, 150, 228, 137, 114, 143, 77, 115, 135, 143, 103, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 217, 155, 76, 165, 59, 188, 67, 41, 220, 168, 9, 28, 236,
        172, 159, 253, 132, 240, 104, 28, 183, 164, 95, 57, 132, 227, 32, 234, 84, 97, 192, 180, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 228, 80, 92, 70, 9, 154, 102, 79, 79, 238, 183, 1, 104,
        239, 123, 93, 228, 74, 44, 60, 147, 21, 105, 30, 217, 135, 107, 104, 104, 117, 50, 116,
    ];

    let mut bob_state_init = vec![
        52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17, 150, 95, 221, 247, 33,
        201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190, 177, 67, 45, 125, 158, 190,
        181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200, 62, 29, 37, 150, 228, 137,
        114, 143, 77, 115, 135, 143, 103, 213, 153, 88, 124, 93, 136, 104, 111, 196, 208, 155, 156,
        165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243, 24, 225, 91, 220, 141,
        150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 228, 80, 92, 70, 9, 154, 102, 79, 79, 238, 183, 1,
        104, 239, 123, 93, 228, 74, 44, 60, 147, 21, 105, 30, 217, 135, 107, 104, 104, 117, 50,
        116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 217, 155, 76, 165, 59, 188, 67, 41, 220, 168, 9,
        28, 236, 172, 159, 253, 132, 240, 104, 28, 183, 164, 95, 57, 132, 227, 32, 234, 84, 97,
        192, 180,
    ];

    alice_state_init.resize(STATE_SIZE, 0);
    bob_state_init.resize(STATE_SIZE, 0);
    let mut alice_state: State = alice_state_init.try_into().unwrap();
    let mut bob_state: State = bob_state_init.try_into().unwrap();
    let mut a = Channel::new(&mut alice_state);
    let mut b = Channel::new(&mut bob_state);
    let (mut key, ciphertext) = a.close().unwrap();
    assert_eq!(alice_state, [0; STATE_SIZE]);
    b.open(&mut key, &ciphertext).unwrap();
    let signature = b.certify_identity().unwrap();
    assert_eq!(signature, alice_signature_bob_identity);
    assert_eq!(key, [0; SECRET_KEY_SIZE])
}
