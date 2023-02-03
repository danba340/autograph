# The Autograph Protocol

Revision 2, 2023-02-03

Christoffer Carlsson (editor)

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. Preliminaries](#2-preliminaries)
  - [2.1. Roles](#21-roles)
  - [2.2. Keys & signatures](#22-keys--signatures)
  - [2.3. Cryptographic notation](#23-cryptographic-notation)
- [3. The Autograph protocol](#3-the-autograph-protocol)
  - [3.1. Overview](#31-overview)
  - [3.2. Key share messages](#32-key-share-messages)
  - [3.3. Key verification](#33-key-verification)
  - [3.4. Authentication](#34-authentication)
  - [3.5. Establishing trust](#35-establishing-trust)
  - [3.6. Certifying ownership](#36-certifying-ownership)
  - [3.7. Verifying ownership](#37-verifying-ownership)
  - [3.8. Revoking trust](#38-revoking-trust)
- [4. Security considerations](#4-security-considerations)
  - [4.1. Key compromise](#41-key-compromise)
  - [4.2. Verified key exchange](#42-verified-key-exchange)
  - [4.3 Trusted party manipulation](#43-trusted-party-manipulation)
- [5. IPR](#5-ipr)
- [6. Acknowledgements](#6-acknowledgements)
- [7. References](#7-references)

## 1. Introduction

This document describes the Autograph protocol. The protocol allows one party
(”Bob”) to cryptographically verify any type of data from another party
(”Alice”) based on public keys and signatures from trusted third parties (e.g.
”Charlie”). Autograph provides cryptographic deniability and forward secrecy.

## 2. Preliminaries

### 2.1 Roles

The Autograph protocol involves three parties: **Alice**, **Bob** and
**Charlie**.

- **Alice** wants to send encrypted data to Bob and certify that she is the
  owner of the data.
- **Bob** wants to accept encrypted data from parties like Alice and verify its
  ownership. To enable this scenario, Bob relies on cryptographic signatures
  from trusted third parties like Charlie.
- **Charlie** creates cryptographic signatures that certifies ownership of data
  for parties like Alice. This allows Bob to verify the ownership of data that
  he receives from Alice.

### 2.2 Keys & signatures

Prior to a protocol run each party will have one or more of the following
elliptic curve public keys and signatures:

| Name | Definition                                                    | Required |
| :--- | :------------------------------------------------------------ | :------- |
| IKS  | An identity key used for signing                              | Yes      |
| IKE  | An identity key used for deriving keys for encryption         | Yes      |
| C    | A certificate containing pairs of signing keys and signatures | No       |
| T    | A list of trusted signing keys                                | No       |

All public keys have corresponding private keys, but to simplify description
this document will focus on the public keys.

During a protocol run each party will generate ephemeral X25519 key pairs
\[[1](#7-references)\] using Elliptic-curve Diffie–Hellman (ECDH)
\[[2](#7-references)\], create Ed25519 signatures \[[3](#7-references)\] using
the Edwards-curve Digital Signature Algorithm (EdDSA) \[[4](#7-references)\],
and derive 256-bit shared secret keys to encrypt their communications using AES
\[[5](#7-references)\] in Galois/Counter Mode (GCM) \[[6](#7-references)\].

During a protocol run each party's existing C and T values may be replaced with
new ones.

### 2.3 Cryptographic notation

This document will use the following notation:

- The concatenation of byte sequences **X** and **Y** is **X || Y**.
- **""** (two double quotes) represents an empty byte sequence.
- **ENCRYPT(K, M)** represents the AES-GCM encryption of plaintext M with the
  256-bit key K. Since the key will be updated for every message the nonce is a
  constant of 12 zero-filled bytes. The 128-bit authentication tag is appended
  to the ciphertext.
- **DECRYPT(K, C)** represents the AES-GCM decryption of ciphertext C with the
  key K.
- **DH(PK1, PK2)** represents 32 bytes of shared secret output from the X25519
  Elliptic Curve Diffie-Hellman function involving the key pairs represented by
  public keys PK1 and PK2.
- **SIGN(PK, M)** represents a byte sequence that is an EdDSA signature on the
  byte sequence M and verifies with the public key PK, and was created using
  PK's corresponding private key. The signing and verification function will be
  Ed25519.
- **KDF(KM, C)** represents 32 bytes of output from the HKDF algorithm
  \[[7](#7-references)\], using SHA-512 \[[8](#7-references)\], with inputs:
  - Input keying material = The byte sequence KM.
  - Salt = A zero-filled byte sequence with the same length as the output of
    SHA-512 (64 bytes).
  - Info = A single byte C representing the context for the derived key
    material.
- **HASH(M, N)** represents 64 bytes of SHA-512 output produced by iteratively
  hashing the byte sequence M N times.

## 3. The Autograph protocol

### 3.1 Overview

Autograph can be divided into three different phases:

1. Bob and Charlie mutually authenticate each other. Bob adds Charlie as a
   trusted party.
2. Alice and Charlie mutually authenticate each other. As part of the
   authentication process Alice may include additional data that she owns.
   Charlie creates a signature that certifies Alice's ownership of her
   cryptographic identity and data. Alice adds the signature and Charlie's
   public key to a certificate.
3. Alice performs a one-way authentication with Bob. She includes the
   certificate from above. Since Charlie is one of Bob's trusted parties, Bob
   can verify Alice's ownership of her cryptographic identity and data without
   further contact with Charlie.

The following sections describe these phases.

### 3.2 Key share messages

This section describes how a party calculates a key share message. Bob
calculates the key share message KS<sub>B</sub> by performing the following
steps:

Bob generates an ephemeral X25519 key pair EK<sub>B</sub>. He then adds each of
his identity public keys and the ephemeral public key to a key share message:

KS<sub>B</sub> = IKS<sub>B</sub> || IKE<sub>B</sub> || EK<sub>B</sub>

How key share messages are used is explained further in the following sections.

### 3.3 Key verification

This section describes how two parties can manually verify each other's identity
keys to prevent man-in-the-middle attacks by calculating a safety number. Alice
and Bob, for example, can manually verify each other's identity keys by
performing the following steps:

Alice computes a 30-digit numeric fingerprint FH<sub>A</sub> for her identity
keys IKS<sub>A</sub> and IKE<sub>A</sub>:

FH<sub>A</sub> = HASH(IKS<sub>A</sub> || IKE<sub>A</sub>, 5200)

Alice takes the first 30 bytes of FH<sub>A</sub> and splits them into six 5-byte
chunks. She converts each 5-byte chunk into 5 digits by interpreting each chunk
as a big-endian unsigned integer and reducing it modulo 100000.

Alice then concatenates the 6 groups of 5 digits into 30 digits to produce her
fingerprint FP<sub>A</sub>.

Upon receiving a key share message from Bob, Alice repeats the above steps using
IKS<sub>B</sub> and IKE<sub>B</sub> to produce Bob's fingerprint FP<sub>B</sub>.

Alice sorts and concatenates FP<sub>A</sub> and FP<sub>B</sub> to produce the
safety number SN<sub>A</sub>.

Upon receiving a key share message from Alice, Bob repeats the above steps to
calculate SN<sub>B</sub>.

Alice and Bob manually compare each other's safety numbers out-of-band. If they
don't match both parties abort the protocol.

If the safety numbers match Alice and Bob have successfully verified each
other's identity keys.

### 3.4 Authentication

This section describes how one party authenticates with another. Bob, for
example, authenticates with Charlie by performing the following steps:

Using a shared secret key BK, Bob derives the secret key AK that will be used to
encrypt his auhentication message. A single byte KC is used to indicate the
context for which the derived key AK will be used:

AK = KDF(BK, KC)

How the values of BK and KC are determined is explained further in the following
sections.

Bob loads the data D<sub>B</sub> that he wants to certify ownership for.

If Bob does not have any data, or if he only wants to certify ownership for his
IKS<sub>B</sub> private key, he sets D<sub>B</sub> to an empty byte sequence:

D<sub>B</sub> = ""

Bob then loads a certificate C<sub>B</sub> that contains identity keys and
signatures from other parties that previously have cryptographically verified
him as the owner of the data D<sub>B</sub> and the IKS<sub>B</sub> private key.

If Bob does not yet have a certificate he sets C<sub>B</sub> to an empty byte
sequence:

C<sub>B</sub> = ""

The specifics of certificates and how the different signatures are created are
explained further in [Section 3.6](#36-certifying-ownership).

Bob creates a signature S<sub>B</sub> by signing Charlie's ephemeral public key
EK<sub>C</sub> and the data D<sub>B</sub>:

S<sub>B</sub> = SIGN(IKS<sub>B</sub>, D<sub>B</sub> || EK<sub>C</sub>)

The signature S<sub>B</sub> certifies that Bob is in control of the
IKS<sub>B</sub> private key.

Bob constructs the authentication message plaintext A<sub>B</sub> by
concatenating the signature S<sub>B</sub>, the certificate C<sub>B</sub>, and
the data D<sub>B</sub>. A 16-bit unsigned big-endian integer CL<sub>B</sub> is
used to denote the number of public key- and signature pairs in the certificate
C<sub>B</sub>:

A<sub>B</sub> = S<sub>B</sub> || CL<sub>B</sub> || C<sub>B</sub> ||
D<sub>B</sub>

Bob encrypts the plaintext A<sub>B</sub> using the secret key AK, producing the
authentication message AM<sub>B</sub>:

AM<sub>B</sub> = ENCRYPT(AK, A<sub>B</sub>)

Bob then deletes AK and sends AM<sub>B</sub> to Charlie.

Upon receiving Bob's encrypted authentication message, Charlie repeats the KDF
calculation from above to derive AK. He then attempts to decrypt the ciphertext
AM<sub>B</sub>:

A<sub>B</sub> = DECRYPT(AK, AM<sub>B</sub>)

If the decryption fails Charlie aborts the protocol and deletes AK.

If decryption succeeds Charlie deletes AK and reads S<sub>B</sub>,
C<sub>B</sub>, and D<sub>B</sub> from A<sub>B</sub>.

Charlie verifies the S<sub>B</sub> signature using IKS<sub>B</sub> and his
EK<sub>C</sub> public key. If the verification fails Charlie aborts the
protocol.

Charlie then performs a trusted party verification by comparing the identity
public keys in C<sub>B</sub> against a list of trusted public keys
T<sub>C</sub>. Charlie uses a threshold number TH<sub>C</sub> to determine how
many trusted public keys that needs to be found in C<sub>B</sub>.

If Bob's identity key IKS<sub>B</sub> is found in Charlie's list of trusted
public keys T<sub>C</sub>, Charlie will omit IKS<sub>B</sub> from T<sub>C</sub>
when comparing T<sub>C</sub> against C<sub>B</sub>, and if TH<sub>C</sub> is
greater than 0, Charlie will negate TH<sub>C</sub> by 1.

If the number of trusted public keys found in C<sub>B</sub> is less than
TH<sub>C</sub> Charlie aborts the protocol.

If TH<sub>C</sub> is now greater than 0, Charlie verifies the signature for each
of the corresponding trusted public keys found in C<sub>B</sub> using the data
D<sub>B</sub> and the IKS<sub>B</sub> public key. If any of the verifications
fail Charlie aborts the protocol.

If the trusted party verification succeeds Bob has successfully authenticated
with Charlie.

### 3.5 Establishing trust

This section describes how one party adds another as a trusted party. Bob adds
Charlie to his list of trusted parties by performing the following steps:

Charlie calculates a key share message KS<sub>C</sub> as described in
[Section 3.2](#32-key-share-messages).

Charlie sends KS<sub>C</sub> to Bob.

Upon receiving KS<sub>C</sub> from Charlie, Bob calculates a key share message
KS<sub>B</sub> as described in [Section 3.2](#32-key-share-messages).

Bob sends KS<sub>B</sub> to Charlie.

Bob calculates the shared secret key BK:

BK = DH(IKE<sub>B</sub>, EK<sub>C</sub>) || DH(IKE<sub>C</sub>, EK<sub>B</sub>)

Bob then deletes his ephemeral EK<sub>B</sub> private key.

Upon receiving KS<sub>B</sub> from Bob, Charlie repeats the above step to
calculate BK and then deletes his ephemeral EK<sub>C</sub> private key.

Optionally, Bob and Charlie perform a key verification as described in
[Section 3.3](#33-key-verification).

Bob sets KC to 0x00 and authenticates with Charlie as described in
[Section 3.4](#34-authentication). If the authentication fails both parties
aborts the protocol and deletes BK.

If Bob successfully authenticates with Charlie, Charlie sets KC to 0x01 and
authenticates with Bob as described in [Section 3.4](#34-authentication) and
then deletes BK.

If the authentication fails Bob aborts the protocol and deletes BK.

If Charlie successfully authenticates with Bob, Bob deletes BK and adds
Charlie's identity public key IKS<sub>C</sub> to his list of trusted parties
T<sub>B</sub>:

T<sub>B</sub>' = T<sub>B</sub> || IKS<sub>C</sub>

Bob replaces any existing T<sub>B</sub> with the updated value and stores it for
future protocol runs.

How lists of trusted parties are stored is beyond the scope of this document,
but subject to the security considerations in
[Section 4.3](#43-trusted-party-manipulation).

### 3.6 Certifying ownership

This section describes how one party can create a signature that certifies
another party's ownership of cryptographic identity and data. Charlie certifies
Alice's ownership by performing the following steps:

Charlie calculates a key share message KS<sub>C</sub> as described in
[Section 3.2](#32-key-share-messages).

Charlie sends KS<sub>C</sub> to Alice.

Upon receiving KS<sub>C</sub> from Charlie, Alice calculates a key share message
KS<sub>A</sub> as described in [Section 3.2](#32-key-share-messages).

Alice sends KS<sub>A</sub> to Charlie.

Alice calculates the shared secret key BK:

BK = DH(IKE<sub>A</sub>, EK<sub>C</sub>) || DH(IKE<sub>C</sub>, EK<sub>A</sub>)

Alice then deletes her ephemeral EK<sub>A</sub> private key.

Upon receiving KS<sub>A</sub> from Alice, Charlie repeats the above step to
calculate BK and then deletes his ephemeral EK<sub>C</sub> private key.

Optionally, Alice and Charlie perform a key verification as described in
[Section 3.3](#33-key-verification).

Alice sets KC to 0x00 and authenticates with Charlie as described in
[Section 3.4](#34-authentication). Alice includes the data D<sub>A</sub>, if
any, that she wants Charlie to sign in her authentication message. If the
authentication fails Charlie aborts the protocol and deletes BK.

If Alice successfully authenticates with Charlie, Charlie creates the signature
AS<sub>C</sub>:

AS<sub>C</sub> = SIGN(IKS<sub>C</sub>, D<sub>A</sub> || IKS<sub>A</sub>)

Charlie sets KC to 0x01 and authenticates with Alice, using AS<sub>C</sub> as
the data D<sub>C</sub> in his authentication message:

D<sub>C</sub> = AS<sub>C</sub>

Charlie then deletes BK.

Alice will omit the data D<sub>C</sub> when performing the trusted party
verification of Charlie's authentication. If the authentication fails Alice
aborts the protocol and deletes BK.

If Charlie successfully authenticates with Alice, Alice verifies the
AS<sub>C</sub> signature using IKS<sub>C</sub> and D<sub>A</sub>. If the
verification fails Alice aborts the protocol and deletes BK.

If the verification succeeds, Alice deletes BK and adds IKS<sub>C</sub> and
AS<sub>C</sub> to her certificate C<sub>A</sub>:

C<sub>A</sub>' = C<sub>A</sub> || IKS<sub>C</sub> || AS<sub>C</sub>

Alice can now use her updated certificate C<sub>A</sub>' to authenticate with
parties like Bob.

Alice replaces any existing certificate C<sub>A</sub> with the updated value and
stores it for future protocol runs.

How certificates are stored is beyond the scope of this document.

### 3.7 Verifying ownership

This section describes how one party can verify another party's ownership of
cryptographic identity and data. Bob verifies Alice's ownership by performing
the following steps:

Bob calculates a key share message KS<sub>B</sub> as described in
[Section 3.2](#32-key-share-messages).

Bob sends KS<sub>B</sub> to Alice.

Upon receiving KS<sub>B</sub> from Bob, Alice calculates a key share message
KS<sub>A</sub> as described in [Section 3.2](#32-key-share-messages).

Alice sends KS<sub>A</sub> to Bob.

Alice calculates the shared secret key BK:

BK = DH(IKE<sub>A</sub>, EK<sub>B</sub>) || DH(IKE<sub>B</sub>, EK<sub>A</sub>)

Alice then deletes her ephemeral EK<sub>A</sub> private key.

Upon receiving KS<sub>A</sub> from Alice, Bob repeats the above step to
calculate BK and then deletes his ephemeral EK<sub>B</sub> private key.

Optionally, Alice and Bob perform a key verification as described in
[Section 3.3](#33-key-verification).

Alice sets KC to 0x00 and authenticates with Bob as described in
[Section 3.4](#34-authentication). If the authentication fails both parties
aborts the protocol and deletes BK.

If the authentication succeeds, Bob has successfully verified Alice's ownership
of her cryptographic identity and data. Both parties deletes BK.

### 3.8 Revoking trust

This section describes how one party can revoke the trust that previously have
been established between another party as described in
[Section 3.5](#35-establishing-trust). Bob revokes his trust in Charlie by
performing the following steps:

Bob deletes Charlie's IKS<sub>C</sub> public key from his list of trusted
parties T<sub>B</sub>, producing T<sub>B</sub>'.

Bob replaces any existing T<sub>B</sub> with the updated T<sub>B</sub>' and
stores it for future protocol runs.

How lists of trusted parties are managed and under what circumstances a party
should or should not revoke the trust in another party is beyond the scope of
this document, but subject to the security considerations in
[Section 4.3](#43-trusted-party-manipulation).

## 4. Security considerations

### 4.1 Key compromise

Compromise of a party's identity private keys allows impersonation of that party
to others.

### 4.2 Key verification

If a key verification as described in [Section 3.3](#33-key-verification) is not
performed, the parties will have no cryptographic guarantee as to who they are
communicating with, which may enable man-in-the-middle attacks.

### 4.3 Trusted party manipulation

If a malicious party is able to manipulate another party's list of trusted
parties they could add or remove the identity keys of other parties (including
their own), thus bypassing the authentication step described in
[Section 3.5](#35-establishing-trust). Therefore, implementers of the protocol
should take the appropriate steps to prevent unauthorized access to trusted
party lists. How to implement these preventive measures is beyond the scope of
this document.

## 5. IPR

This document is hereby placed in the public domain.

## 6. Acknowledgements

The original Autograph concept was developed by Christoffer Carlsson and Max
Molin.

The Autograph protocol was designed by Christoffer Carlsson.

Thanks to Elnaz Abolahrar for discussions around using threshold numbers in
trusted party verifications.

## 7. References

[1] A. Langley, M. Hamburg, and S. Turner, “Elliptic Curves for Security”;
Internet Engineering Task Force; RFC 7748; January 2016.
<http://www.ietf.org/rfc/rfc7748.txt>

[2] D. McGrew, K. Igoe, and M. Salter, “Fundamental Elliptic Curve Cryptography
Algorithms”; Internet Engineering Task Force; RFC 6090; February 2011.
<http://www.ietf.org/rfc/rfc6090.txt>

[3] D. Bernstein, N. Duif, T. Lange, P. Schwabe, and B. Yang, "High-speed
high-security signatures"; September 2011.
<https://ed25519.cr.yp.to/ed25519-20110926.pdf>

[4] S. Josefsson and I. Liusvaara, “Edwards-Curve Digital Signature Algorithm
(EdDSA)”; Internet Engineering Task Force; RFC 8032; January 2017.
<http://www.ietf.org/rfc/rfc8032.txt>

[5] M. Dworkin, E. Barker, J. Nechvatal, J. Foti, L. Bassham, E. Roback, and J.
Dray Jr, "Advanced Encryption Standard (AES)"; Federal Information Processing
Standards Publication 197; November 2001.
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf>

[6] D. McGrew and J. Viega, “The Galois/Counter Mode of Operation (GCM)”;
Submission to NIST Modes of Operation Process; January, 2004.

[7] H. Krawczyk and P. Eronen, “HMAC-based Extract-and-Expand Key Derivation
Function (HKDF)”; Internet Engineering Task Force; RFC 5869; May 2010.
<http://www.ietf.org/rfc/rfc5869.txt>

[8] National Institute of Standards and Technology, "Secure Hash Standard
(SHS)"; Federal Information Processing Standards Publication 180-4;
August, 2015. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
