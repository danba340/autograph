#ifndef AUTOGRAPH_H
#define AUTOGRAPH_H

#ifdef __cplusplus
#include <functional>
#include <vector>

extern "C" {
#endif

int autograph_certify(unsigned char *signature,
                      const unsigned char *our_private_key,
                      const unsigned char *their_public_key,
                      const unsigned char *data,
                      const unsigned long long data_size);

int autograph_decrypt(unsigned char *plaintext, const unsigned char *key,
                      const unsigned char *message,
                      const unsigned long long message_size);

int autograph_encrypt(unsigned char *message, const unsigned char *key,
                      const unsigned int index, const unsigned char *plaintext,
                      const unsigned long long plaintext_size);

int autograph_handshake(unsigned char *transcript, unsigned char *message,
                        unsigned char *our_secret_key,
                        unsigned char *their_secret_key,
                        const unsigned int is_initiator,
                        const unsigned char *our_private_identity_key,
                        const unsigned char *our_public_identity_key,
                        unsigned char *our_private_ephemeral_key,
                        const unsigned char *our_public_ephemeral_key,
                        const unsigned char *their_public_identity_key,
                        const unsigned char *their_public_ephemeral_key);

unsigned int autograph_handshake_size();

int autograph_init();

int autograph_key_pair_ephemeral(unsigned char *private_key,
                                 unsigned char *public_key);

int autograph_key_pair_identity(unsigned char *private_key,
                                unsigned char *public_key);

unsigned int autograph_message_extra_size();

unsigned int autograph_private_key_size();

unsigned int autograph_public_key_size();

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key);

unsigned int autograph_safety_number_size();

unsigned int autograph_secret_key_size();

unsigned int autograph_signature_size();

int autograph_session(const unsigned char *transcript,
                      const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *ciphertext);

unsigned int autograph_transcript_size();

int autograph_verify(const unsigned char *their_public_key,              
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *data,
                     const unsigned long long data_size);

#ifdef __cplusplus
}  // extern "C"

namespace autograph {

using Bytes = std::vector<unsigned char>;

struct KeyPair {
  Bytes private_key;
  Bytes public_key;
};

using CertifyFunction = std::function<Bytes(const Bytes)>;

using DecryptFunction = std::function<Bytes(const Bytes)>;

using EncryptFunction = std::function<Bytes(const Bytes)>;

using SafetyNumberFunction = std::function<Bytes(const Bytes)>;

using VerifyFunction = std::function<bool(const Bytes, const Bytes)>;

struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionFunction = std::function<Session(const Bytes)>;

struct Handshake {
  Bytes message;
  SessionFunction establish_session;
};

using HandshakeFunction = std::function<Handshake(const Bytes, const Bytes)>;

struct Party {
  SafetyNumberFunction calculate_safety_number;
  HandshakeFunction perform_handshake;
};

Party create_initiator(const KeyPair identity_key_pair,
                       KeyPair ephemeral_key_pair);

Party create_responder(const KeyPair identity_key_pair,
                       KeyPair ephemeral_key_pair);

KeyPair generate_ephemeral_key_pair();

KeyPair generate_identity_key_pair();

void init();

}  // namespace autograph
#endif

#endif
