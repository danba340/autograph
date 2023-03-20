#pragma once

namespace autograph {
constexpr unsigned int PRIVATE_KEY_SIZE = 32;
constexpr unsigned int PUBLIC_KEY_SIZE = 32;
constexpr unsigned int SIGNATURE_SIZE = 64;

#include "autograph/types.h"
#include "sodium.h"

Party create_alice(const KeyPair &identity_key_pair);

Party create_bob(const KeyPair &identity_key_pair);

Party create_initiator(const KeyPair &identity_key_pair);

Party create_responder(const KeyPair &identity_key_pair);

KeyPair generate_key_pair();

void init();
}  // namespace autograph
