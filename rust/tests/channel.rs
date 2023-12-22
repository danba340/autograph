use autograph::{create_state, Channel, KeyPair};

#[test]
fn test_channel() {
    let alice_handshake: Vec<u8> = vec![
        159, 242, 216, 99, 227, 6, 170, 116, 241, 86, 48, 60, 160, 128, 234, 7, 118, 43, 226, 89,
        48, 56, 90, 4, 180, 141, 175, 112, 238, 107, 14, 181, 167, 246, 102, 132, 75, 13, 181, 5,
        47, 174, 244, 74, 94, 113, 56, 140, 85, 178, 112, 105, 108, 75, 154, 82, 191, 5, 197, 87,
        213, 162, 234, 108, 184, 11, 61, 242, 143, 198, 61, 43, 33, 37, 75, 135, 190, 41, 74, 208,
    ];

    let bob_handshake: Vec<u8> = vec![
        105, 178, 89, 152, 225, 150, 49, 251, 77, 155, 134, 254, 92, 168, 57, 159, 252, 72, 82,
        106, 91, 57, 65, 119, 0, 72, 102, 245, 247, 26, 62, 212, 237, 20, 252, 233, 27, 144, 35,
        93, 180, 235, 237, 96, 46, 167, 156, 114, 58, 12, 43, 214, 201, 79, 108, 134, 34, 34, 36,
        220, 228, 255, 233, 146, 248, 162, 157, 164, 237, 38, 77, 217, 133, 180, 27, 98, 3, 247,
        199, 24,
    ];

    let alice_message: Vec<u8> = vec![
        131, 234, 21, 146, 246, 197, 94, 148, 235, 8, 84, 219, 17, 162, 128, 103, 112, 25, 127, 50,
        73, 12, 174, 1, 124, 118, 175, 10, 130, 195, 225, 29,
    ];

    let bob_message: Vec<u8> = vec![
        129, 139, 133, 26, 75, 190, 117, 105, 17, 240, 174, 247, 25, 28, 206, 173, 50, 234, 25, 63,
        174, 147, 185, 113, 226, 164, 21, 197, 114, 198, 43, 8,
    ];

    let alice_signature_bob_data: Vec<u8> = vec![
        198, 235, 143, 145, 121, 29, 143, 128, 167, 118, 33, 71, 38, 209, 169, 2, 134, 90, 203, 72,
        171, 252, 236, 237, 55, 41, 227, 248, 198, 165, 58, 185, 31, 70, 147, 96, 181, 33, 188, 7,
        146, 43, 24, 197, 158, 216, 215, 49, 126, 186, 88, 238, 233, 86, 167, 207, 20, 150, 227,
        38, 160, 68, 82, 8,
    ];

    let alice_signature_bob_identity: Vec<u8> = vec![
        170, 64, 159, 119, 20, 17, 130, 46, 124, 70, 154, 47, 90, 7, 116, 204, 255, 198, 56, 60,
        24, 112, 214, 188, 212, 64, 210, 117, 228, 145, 111, 250, 84, 20, 216, 222, 21, 82, 213,
        225, 31, 28, 152, 211, 16, 82, 131, 7, 248, 186, 255, 184, 35, 205, 183, 167, 138, 179,
        217, 135, 163, 124, 13, 5,
    ];

    let bob_signature_alice_data: Vec<u8> = vec![
        17, 229, 247, 220, 138, 161, 5, 224, 147, 178, 230, 168, 132, 164, 94, 3, 119, 118, 16,
        163, 222, 85, 3, 160, 88, 222, 210, 140, 222, 158, 254, 231, 182, 232, 78, 211, 150, 146,
        127, 164, 238, 221, 119, 12, 230, 54, 49, 103, 177, 72, 126, 225, 214, 41, 80, 214, 247,
        95, 23, 145, 227, 87, 172, 4,
    ];

    let bob_signature_alice_identity: Vec<u8> = vec![
        186, 27, 195, 159, 150, 127, 96, 11, 25, 224, 30, 145, 56, 194, 138, 164, 70, 54, 243, 213,
        229, 203, 179, 218, 207, 213, 168, 160, 56, 32, 164, 245, 49, 102, 200, 36, 172, 152, 113,
        5, 82, 196, 154, 90, 20, 27, 180, 61, 189, 171, 20, 194, 165, 165, 65, 178, 190, 16, 44,
        82, 157, 68, 102, 13,
    ];

    let charlie_identity_key: Vec<u8> = vec![
        129, 128, 10, 70, 174, 223, 175, 90, 43, 37, 148, 125, 188, 163, 110, 136, 15, 246, 192,
        76, 167, 8, 26, 149, 219, 223, 83, 47, 193, 159, 6, 3,
    ];

    let charlie_signature_alice_data: Vec<u8> = vec![
        231, 126, 138, 39, 145, 83, 130, 243, 2, 56, 53, 185, 199, 242, 217, 239, 118, 208, 172, 6,
        201, 132, 94, 179, 57, 59, 160, 23, 150, 221, 67, 122, 176, 56, 160, 63, 7, 161, 169, 101,
        240, 97, 108, 137, 142, 99, 197, 44, 179, 142, 37, 4, 135, 162, 118, 160, 119, 245, 234,
        39, 26, 75, 71, 6,
    ];

    let charlie_signature_alice_identity: Vec<u8> = vec![
        146, 120, 170, 85, 78, 187, 162, 243, 234, 149, 138, 201, 18, 132, 187, 129, 45, 53, 116,
        227, 178, 209, 200, 224, 149, 91, 166, 120, 203, 73, 138, 189, 63, 231, 213, 177, 163, 114,
        66, 151, 61, 253, 109, 250, 226, 140, 249, 3, 188, 44, 127, 108, 196, 131, 204, 216, 54,
        239, 157, 49, 107, 202, 123, 9,
    ];

    let charlie_signature_bob_data: Vec<u8> = vec![
        135, 249, 64, 214, 240, 146, 173, 141, 97, 18, 16, 47, 83, 125, 13, 166, 169, 96, 99, 21,
        215, 217, 236, 173, 120, 50, 143, 251, 228, 76, 195, 8, 248, 133, 170, 103, 122, 169, 190,
        57, 51, 14, 171, 199, 229, 55, 55, 195, 53, 202, 139, 118, 93, 68, 131, 96, 175, 50, 31,
        243, 170, 34, 102, 1,
    ];

    let charlie_signature_bob_identity: Vec<u8> = vec![
        198, 41, 56, 189, 24, 9, 75, 102, 228, 51, 193, 102, 25, 51, 92, 1, 192, 219, 16, 17, 22,
        28, 22, 16, 198, 67, 248, 16, 98, 164, 99, 243, 254, 45, 69, 156, 50, 115, 205, 43, 155,
        242, 78, 64, 205, 218, 80, 171, 34, 128, 255, 51, 237, 60, 37, 224, 232, 149, 153, 213,
        204, 93, 26, 7,
    ];

    let data: Vec<u8> = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

    let safety_number: Vec<u8> = vec![
        0, 0, 126, 217, 0, 0, 218, 180, 0, 1, 102, 162, 0, 0, 41, 97, 0, 0, 40, 245, 0, 1, 15, 218,
        0, 0, 12, 28, 0, 0, 98, 95, 0, 0, 96, 224, 0, 0, 16, 147, 0, 1, 74, 101, 0, 1, 33, 26, 0,
        0, 234, 68, 0, 0, 190, 212, 0, 1, 96, 162, 0, 0, 48, 226,
    ];

    let alice_identity_key_pair = KeyPair {
        private_key: vec![
            118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122,
            177, 18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17,
        ],
        public_key: vec![
            213, 153, 88, 124, 93, 136, 104, 111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205,
            247, 175, 243, 184, 114, 80, 152, 243, 24, 225, 91, 220, 141, 150,
        ],
    };

    let bob_identity_key_pair = KeyPair {
        private_key: vec![
            52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17, 150, 95, 221, 247, 33,
            201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190,
        ],
        public_key: vec![
            177, 67, 45, 125, 158, 190, 181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61,
            200, 62, 29, 37, 150, 228, 137, 114, 143, 77, 115, 135, 143, 103,
        ],
    };

    let alice_ephemeral_key_pair = KeyPair {
        private_key: vec![
            201, 142, 54, 248, 151, 150, 224, 79, 30, 126, 207, 157, 118, 85, 9, 212, 148, 156, 73,
            176, 107, 107, 47, 111, 95, 98, 33, 192, 80, 223, 48, 221,
        ],
        public_key: vec![
            35, 16, 23, 37, 205, 131, 166, 97, 13, 81, 136, 246, 193, 253, 139, 193, 230, 155, 222,
            221, 37, 114, 190, 87, 104, 44, 210, 144, 127, 176, 198, 45,
        ],
    };

    let bob_ephemeral_key_pair = KeyPair {
        private_key: vec![
            74, 233, 106, 152, 76, 212, 181, 144, 132, 237, 223, 58, 122, 173, 99, 100, 152, 219,
            214, 210, 213, 72, 171, 73, 167, 92, 199, 196, 176, 66, 213, 208,
        ],
        public_key: vec![
            88, 115, 171, 4, 34, 181, 120, 21, 10, 39, 204, 215, 158, 210, 177, 243, 28, 138, 52,
            91, 236, 55, 30, 117, 10, 125, 87, 232, 80, 6, 232, 93,
        ],
    };

    let mut alice_state = create_state();
    let mut bob_state = create_state();
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
    test_safety_number(&a, &b, safety_number);
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
    mut alice_ephemeral_key_pair: KeyPair,
    bob_identity_key_pair: KeyPair,
    mut bob_ephemeral_key_pair: KeyPair,
    alice_handshake: Vec<u8>,
    bob_handshake: Vec<u8>,
) {
    let handshake_alice = a
        .perform_key_exchange(
            true,
            &alice_identity_key_pair,
            &mut alice_ephemeral_key_pair,
            &bob_identity_key_pair.public_key,
            &bob_ephemeral_key_pair.public_key,
        )
        .unwrap();
    let handshake_bob = b
        .perform_key_exchange(
            false,
            &bob_identity_key_pair,
            &mut bob_ephemeral_key_pair,
            &alice_identity_key_pair.public_key,
            &alice_ephemeral_key_pair.public_key,
        )
        .unwrap();
    let alice_verified =
        a.verify_key_exchange(&alice_ephemeral_key_pair.public_key, &handshake_bob);
    let bob_verified = b.verify_key_exchange(&bob_ephemeral_key_pair.public_key, &handshake_alice);
    assert_eq!(handshake_alice, alice_handshake);
    assert_eq!(handshake_bob, bob_handshake);
    assert!(alice_verified);
    assert!(bob_verified);
}

// Should calculate safety numbers correctly
fn test_safety_number(a: &Channel, b: &Channel, safety_number: Vec<u8>) {
    let alice_safety_number = a.calculate_safety_number().unwrap();
    let bob_safety_number = b.calculate_safety_number().unwrap();
    assert_eq!(alice_safety_number, safety_number);
    assert_eq!(bob_safety_number, safety_number);
}

// Should allow Alice to send encrypted data to Bob
fn test_alice_message_to_bob(
    a: &mut Channel,
    b: &mut Channel,
    data: &Vec<u8>,
    alice_message: Vec<u8>,
) {
    let (_, message) = a.encrypt(data).unwrap();
    let (_, plaintext) = b.decrypt(&message).unwrap();
    assert_eq!(plaintext, data.to_vec());
    assert_eq!(message, alice_message);
}

// Should allow Bob to send encrypted data to Alice
fn test_bob_message_to_alice(
    a: &mut Channel,
    b: &mut Channel,
    data: &Vec<u8>,
    bob_message: Vec<u8>,
) {
    let (_, message) = b.encrypt(data).unwrap();
    let (_, plaintext) = a.decrypt(&message).unwrap();
    assert_eq!(plaintext, data.to_vec());
    assert_eq!(message, bob_message);
}

// Should allow Bob to certify Alice's ownership of her identity key and data
fn test_bob_certify_alice_data(b: &Channel, data: &Vec<u8>, bob_signature_alice_data: Vec<u8>) {
    let signature = b.certify_data(data).unwrap();
    assert_eq!(signature, bob_signature_alice_data);
}

// Should allow Alice to certify Bob's ownership of his identity key and data
fn test_alice_certify_bob_data(a: &Channel, data: &Vec<u8>, alice_signature_bob_data: Vec<u8>) {
    let signature = a.certify_data(data).unwrap();
    assert_eq!(signature, alice_signature_bob_data);
}

// Should allow Bob to certify Alice's ownership of her identity key
fn test_bob_certify_alice_identity(b: &Channel, bob_signature_alice_identity: Vec<u8>) {
    let signature = b.certify_identity().unwrap();
    assert_eq!(signature, bob_signature_alice_identity);
}

// Should allow Alice to certify Bob's ownership of his identity key
fn test_alice_certify_bob_identity(a: &Channel, alice_signature_bob_identity: Vec<u8>) {
    let signature = a.certify_identity().unwrap();
    assert_eq!(signature, alice_signature_bob_identity);
}

// Should allow Bob to verify Alice's ownership of her identity key and data
// based on Charlie's public key and signature
fn test_bob_verify_alice_data(
    b: &Channel,
    data: &Vec<u8>,
    charlie_identity_key: &Vec<u8>,
    charlie_signature_alice_data: Vec<u8>,
) {
    let verified = b.verify_data(data, charlie_identity_key, &charlie_signature_alice_data);
    assert!(verified);
}

// Should allow Alice to verify Bob's ownership of his identity key and ddata
// based on Charlie's public key and signature
fn test_alice_verify_bob_data(
    a: &Channel,
    data: &Vec<u8>,
    charlie_identity_key: &Vec<u8>,
    charlie_signature_bob_data: Vec<u8>,
) {
    let verified = a.verify_data(data, charlie_identity_key, &charlie_signature_bob_data);
    assert!(verified);
}

// Should allow Bob to verify Alice's ownership of her identity key based on
// Charlie's public key and signature
fn test_bob_verify_alice_identity(
    b: &Channel,
    charlie_identity_key: &Vec<u8>,
    charlie_signature_alice_identity: Vec<u8>,
) {
    let verified = b.verify_identity(charlie_identity_key, &charlie_signature_alice_identity);
    assert!(verified);
}

// Should allow Alice to verify Bob's ownership of his identity key based on
// Charlie's public key and signature
fn test_alice_verify_bob_identity(
    a: &Channel,
    charlie_identity_key: &Vec<u8>,
    charlie_signature_bob_identity: Vec<u8>,
) {
    let verified = a.verify_identity(charlie_identity_key, &charlie_signature_bob_identity);
    assert!(verified);
}

// Should handle out of order messages correctly
fn test_out_of_order_messages(a: &mut Channel, b: &mut Channel) {
    let data1: Vec<u8> = vec![1, 2, 3];
    let data2: Vec<u8> = vec![4, 5, 6];
    let data3: Vec<u8> = vec![7, 8, 9];
    let data4: Vec<u8> = vec![10, 11, 12];
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
    let blank_state = create_state();
    let mut initial_state: Vec<u8> = vec![
        52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17, 150, 95, 221, 247, 33,
        201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190, 177, 67, 45, 125, 158, 190,
        181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200, 62, 29, 37, 150, 228, 137,
        114, 143, 77, 115, 135, 143, 103, 213, 153, 88, 124, 93, 136, 104, 111, 196, 208, 155, 156,
        165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243, 24, 225, 91, 220, 141,
        150, 0, 0, 0, 0, 19, 204, 155, 9, 177, 55, 134, 149, 159, 211, 24, 84, 231, 36, 192, 217,
        101, 73, 6, 231, 177, 120, 184, 52, 93, 155, 35, 35, 16, 40, 135, 52, 0, 0, 0, 0, 229, 152,
        150, 64, 86, 142, 184, 73, 69, 27, 43, 178, 92, 235, 209, 83, 247, 201, 107, 101, 30, 171,
        111, 124, 61, 79, 74, 85, 28, 31, 186, 140,
    ];
    initial_state.resize(9348, 0);
    let mut first_state = initial_state.clone();
    let mut second_state = create_state();
    let mut first = Channel::new(&mut first_state);
    let mut second = Channel::new(&mut second_state);
    let (mut key, ciphertext) = first.close().unwrap();
    assert_eq!(first_state, blank_state);
    let success = second.open(&mut key, &ciphertext);
    assert!(success);
    assert_eq!(second_state, initial_state)
}
