# The Autograph Protocol

Revision 1, 2021-09-07

## Table of Contents

- [1. Introduction](#1-introduction)
- [2. Preliminaries](#2-preliminaries)
  - [2.1. Roles](#21-roles)
  - [2.2. Keys & signatures](#22-keys--signatures)
  - [2.3. Cryptographic notation](#23-cryptographic-notation)
  - [2.4. Message types](#24-message-types)
- [3. The Autograph protocol](#3-the-autograph-protocol)
  - [3.1. Overview](#31-overview)
  - [3.2. One-way authentication](#32-one-way-authentication)
  - [3.3. Mutual authentication](#33-mutual-authentication)
  - [3.4. Manual authentication](#34-manual-authentication)
  - [3.5. Establishing trust](#35-establishing-trust)
  - [3.6. Certifying ownership](#36-certifying-ownership)
  - [3.7. Key agreement](#37-key-agreement)
  - [3.8. Asynchronous authentication](#38-asynchronous-authentication)
- [4. Security considerations](#4-security-considerations)
  - [4.1. Key compromise](#41-key-compromise)
  - [4.2. Manual authentication](#42-manual-authentication)
  - [4.3. Asynchronous authentication](#43-asynchronous-authentication)
- [5. IPR](#5-ipr)
- [6. Acknowledgements](#6-acknowledgements)
- [7. References](#7-references)

## 1. Introduction

This document describes the Autograph protocol. The protocol allows one party
(”Bob”) to cryptographically verify any type of data from another party
(”Alice”) based on public keys and signatures from trusted third parties (e.g.
”Charlie”). It also allows Alice and Bob to establish a shared secret key for
future communication. Autograph provides cryptographic deniability and forward
secrecy.

## 2. Preliminaries

### 2.1 Roles

The Autograph protocol involves four parties: **Alice**, **Bob**, **Charlie**
and (optionally) a **server**.

- **Alice** wants to send encrypted data to Bob and certify that she is the
  owner of the data. Depending on the situation, she might also want to
  establish a shared secret key with Bob so that they can exchange additional
  encrypted messages.
- **Bob** wants to accept encrypted data from parties like Alice and verify its
  ownership. He might also want to allow Alice to establish a shared secret key
  with him. To enable these scenarios, Bob relies on cryptographic signatures
  from trusted third parties like Charlie.
- **Charlie** creates cryptographic signatures that certifies ownership of data
  for parties like Alice. Charlie is trusted by both Alice and Bob. This allows
  Bob to verify the ownership of data that he receives from Alice.
- Alice, Bob, or Charlie might be offline when the other party tries to
  communicate. A **server** can be used to enable asynchronous communication
  between the parties.

### 2.2 Keys & signatures

Prior to a protocol run each party will have one or more of the following
elliptic curve public keys and signatures:

| Name | Definition                                                           | Required |
| :--- | :------------------------------------------------------------------- | :------- |
| IK   | An Ed25519 identity key                                              | Yes      |
| C    | A certificate containing pairs of Ed25519 keys and signatures        | No       |
| CS   | An Ed25519 signature of certificate C that verifies with the key IK  | No       |
| T    | A list of trusted Ed25519 keys                                       | No       |
| TS   | An Ed25519 signature of trusted keys T that verifies with the key IK | No       |

All public keys have a corresponding private key, but to simplify description
this document will focus on the public keys.

During a protocol run each party will generate ephemeral X25519 key pairs
\[[1](#7-references)\], create Ed25519 signatures \[[2](#7-references)\], and
derive 256-bit shared secret keys to encrypt their communications using AES
\[[3](#7-references)\] in Galois/Counter Mode (GCM) \[[4](#7-references)\].

During a protocol run each party's existing C, CS, T, and TS values may be
replaced with new ones.

### 2.3 Cryptographic notation

This document will use the following notation:

- The concatenation of byte sequences **X** and **Y** is **X || Y**.
- **""** (two double quotes) represents an empty byte sequence.
- **ENCRYPT(K, M, AD)** represents the AES-GCM encryption of plaintext M with
  the 256-bit key K and associated data AD \[[5](#7-references)\]. Since the key
  will be updated for every message the nonce is a constant of 12 zero-filled
  bytes. The 128-bit authentication tag is appended to the ciphertext.
- **DECRYPT(K, C, AD)** represents the AES-GCM decryption of ciphertext C with
  the key K and associated data AD.
- **DH(PK1, PK2)** represents a byte sequence which is the shared secret output
  from the X25519 function involving the key pairs represented by public keys
  PK1 and PK2.
- **SIGN(PK, M)** represents a byte sequence that is an Ed25519 signature on the
  byte sequence M and verifies with public key PK, and was created using PK's
  corresponding private key.
- **KDF(KM)** represents 32 bytes of output from the HKDF algorithm
  \[[6](#7-references)\], using SHA-512 \[[7](#7-references)\], with inputs:
  - Input keying material = The byte sequence KM.
  - Salt = A zero-filled byte sequence with the same length as the output of
    SHA-512 (64 bytes).
  - Info = An UTF-8 encoded byte sequence containing the characters "autograph".
- **HASH(M, N)** represents 64 bytes of SHA-512 output produced by iteratively
  hashing the byte sequence M N times.

### 2.4 Message types

Autograph will use the following single byte prefixes to identify the different
types of messages exchanged between parties:

| Byte prefix | Definition                                                                      |
| :---------- | :------------------------------------------------------------------------------ |
| 0x00        | Ephemeral X25519 key share message used for one-way authentication              |
| 0x01        | Ephemeral X25519 key share message used for mutual authentication               |
| 0x02        | Encrypted authentication message                                                |
| 0x03        | Ephemeral X25519 prekeys message used for asynchronous authentication           |
| 0x04        | Ephemeral X25519 key share request message used for asynchronous authentication |
| 0x05        | Authentication forwarding request message used for asynchronous authentication  |
| 0x06        | Forwarded authentication message used for asynchronous authentication           |

The message type prefixes in this document are denoted by MT.

## 3. The Autograph protocol

### 3.1 Overview

Autograph can be divided into four different phases:

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
4. Alice and Bob can derive a shared secret key by mutually authenticating each
   other. Each party generates an ephemeral X25519 key pair and includes the
   public key in their respective authentication messages. Using these keys
   Alice and Bob can derive a shared secret key for future communication.

The following sections describe these phases.

### 3.2 One-way authentication

This section describes how one party authenticates with another. Bob, for
example, authenticates with Charlie by performing the following steps:

Bob generates an ephemeral X25519 key pair EK<sub>B</sub>.

Bob uses the 0x00 message type prefix to identify an ephemeral key share
message.

Bob constructs the key share message KS<sub>B</sub>:

MT = 0x00\
KS<sub>B</sub> = MT || EK<sub>B</sub>

Bob sends KS<sub>B</sub> to Charlie.

Charlie generates an ephemeral X25519 key pair EK<sub>C</sub> and constructs his
key share KS<sub>C</sub>:

MT = 0x00\
KS<sub>C</sub> = MT || EK<sub>C</sub>

Charlie sends KS<sub>C</sub> to Bob.

Upon receiving Charlie's key share, Bob derives a shared secret key AK by
calculating:

AK = KDF(DH(EK<sub>B</sub>, EK<sub>C</sub>))

After calculating AK Bob deletes his ephemeral private key and the DH output.

Bob loads the data D<sub>B</sub> that he wants to certify ownership for.

Bob then loads a certificate C<sub>B</sub> that contains identity keys and
signatures from other parties that previously have cryptographically verified
him as the owner of the data D<sub>B</sub> and/or the IK<sub>B</sub> private
key.

Bob verifies his own signature CS<sub>B</sub> to make sure C<sub>B</sub> hasn't
been tampered with. If the verification fails Bob aborts the protocol.

In scenarios where Bob only wants to certify his cryptographic identity he omits
the data D<sub>B</sub> and loads a certificate C<sub>B</sub> that only certifies
that he is control of the IK<sub>B</sub> private key.

If Bob does not yet have a certificate he loads an empty C<sub>B</sub>
certificate:

C<sub>B</sub> = ""

The specifics of certificates and how the different signatures are created are
explained further in [Section 3.6](#36-certifying-ownership).

Bob then creates a signature S<sub>B</sub> by signing Charlie's ephemeral public
key EK<sub>C</sub> and the data D<sub>B</sub>:

S<sub>B</sub> = SIGN(IK<sub>B</sub>, D<sub>B</sub> || EK<sub>C</sub>)

The signature S<sub>B</sub> certifies that Bob is in control of the
IK<sub>B</sub> private key.

Bob constructs the authentication message plaintext A<sub>B</sub> by
concatenating his identity public key IK<sub>B</sub>, the signature
S<sub>B</sub>, the certificate C<sub>B</sub>, and the data D<sub>B</sub>. A
16-bit unsigned big-endian integer CL<sub>B</sub> is used to denote the number
of public key- and signature pairs in the certificate C<sub>B</sub>:

A<sub>B</sub> = IK<sub>B</sub> || S<sub>B</sub> || CL<sub>B</sub> ||
C<sub>B</sub> || D<sub>B</sub>

Bob uses the 0x02 message type prefix to identify the authentication message and
a 64-bit unsigned big-endian integer SA to denote the size of A<sub>B</sub> in
bytes.

Bob then calculates an associated data byte sequence AD:

MT = 0x02\
AD = EK<sub>B</sub> || EK<sub>C</sub> || MT || SA

Bob encrypts the plaintext A<sub>B</sub> using AK and AD, producing the
ciphertext AC<sub>B</sub>:

AC<sub>B</sub> = ENCRYPT(AK, A<sub>B</sub>, AD)

Bob prefixes the ciphertext with MT and SA to produce the complete
authentication payload AM<sub>B</sub>:

AM<sub>B</sub> = MT || SA || AC<sub>B</sub>

Bob then deletes AK and sends AM<sub>B</sub> to Charlie.

Upon receiving Bob's encrypted authentication message, Charlie repeats the DH
and KDF calculations from above to derive SK, and then deletes the DH output and
his ephemeral EK<sub>C</sub> private key.

Charlie then reads the MT prefix from AM<sub>B</sub> and constructs the AD byte
sequence using MT and the EK<sub>B</sub> and EK<sub>C</sub> public keys, and
attempts to decrypt the ciphertext AC<sub>B</sub> using AK and AD:

A<sub>B</sub> = DECRYPT(AK, AC<sub>B</sub>, AD)

If the decryption fails Charlie aborts the protocol and deletes AK.

If decryption succeeds Charlie deletes AK and reads IK<sub>B</sub>,
S<sub>B</sub>, C<sub>B</sub> and D<sub>B</sub> from A<sub>B</sub>.

Charlie verifies the S<sub>B</sub> signature using IK<sub>B</sub> and his
EK<sub>C</sub> public key. If the verification fails Charlie aborts the
protocol.

Charlie then performs a trusted party verification by comparing the identity
public keys in C<sub>B</sub> against a list of trusted public keys
T<sub>C</sub>. The number of public keys in T<sub>C</sub> is denoted by
TL<sub>C</sub>.

Charlie verifies his own signature TS<sub>C</sub> to make sure T<sub>C</sub>
hasn't been tampered with. If the verification fails Charlie aborts the
protocol. The creation of the signature TS<sub>C</sub> is described in
[Section 3.5](#35-establishing-trust).

Charlie uses a threshold number TH<sub>C</sub> to determine how many trusted
public keys that needs to be found in C<sub>B</sub>.\
If TH<sub>C</sub> is greater than TL<sub>C</sub> then Charlie sets TH<sub>C</sub>
to TL<sub>C</sub>.

If the number of trusted public keys found in C<sub>B</sub> is less than
TH<sub>C</sub> Charlie aborts the protocol.

Charlie verifies the signature for each of the corresponding trusted public keys
found in C<sub>B</sub> using D<sub>B</sub> and IK<sub>B</sub>. If any of the
verifications fail Charlie aborts the protocol.

If the trusted party verification succeeds Bob has successfully authenticated
with Charlie.

### 3.3 Mutual authentication

This section describes how two parties can mutually authenticate each other. Bob
and Charlie, for example, can authenticate each other by performing the
following steps:

Each party generates two ephemeral X25519 key pairs (EK<sub>B</sub> and
EKM<sub>B</sub> for Bob, and EK<sub>C</sub> and EKM<sub>C</sub> for Charlie).

Bob constructs his key share message. He sets the message type prefix MT to 0x01
to indicate a mutual authentication key share:

MT = 0x01\
KS<sub>B</sub> = MT || EK<sub>B</sub> || EKM<sub>B</sub>

Bob sends KS<sub>B</sub> to Charlie.

Charlie repeats the steps above to construct KS<sub>C</sub> and sends it to Bob.

Upon receiving Charlie's key share, Bob performs a one-way authentication with
Charlie as described in [Section 3.2](#32-one-way-authentication), using the
EK<sub>B</sub> and EK<sub>C</sub>.

If Bob successfully authenticates with Charlie, Charlie performs a one-way
authentication with Bob using EKM<sub>B</sub> and EKM<sub>C</sub>.

If Charlie successfully authenticates with Bob then both parties have
successfully authenticated with each other.

### 3.4 Manual authentication

This section describes how two parties can manually verify each other's identity
keys and data to prevent man-in-the-middle attacks by calculating a safety
number. Alice and Bob, for example, can manually authenticate by performing the
following steps:

Alice and Bob perform a mutual authentication as described in
[Section 3.3](#33-mutual-authentication).

If the authentication is successful both Alice and Bob compute two 30-digit
numeric fingerprints for each of their respective public identity keys
IK<sub>A</sub> and IK<sub>B</sub> and data D<sub>A</sub> and D<sub>B</sub>.

To produce the 30-digit numeric fingerprint for her identity key IK<sub>A</sub>
and data D<sub>A</sub> Alice starts by calculating FH<sub>A</sub>:

FH<sub>A</sub> = HASH(D<sub>A</sub> || IK<sub>A</sub>, 5200)

Alice takes the first 30 bytes of FH<sub>A</sub> and splits them into six 5-byte
chunks. She converts each 5-byte chunk into 5 digits by interpreting each chunk
as a big-endian unsigned integer and reducing it modulo 100000.

Alice then concatenates the 6 groups of 5 digits into 30 digits to produce her
fingerprint FP<sub>A</sub>.

Alice repeats the steps above using IK<sub>B</sub> and D<sub>B</sub> to produce
Bob's fingerprint FP<sub>B</sub>.

Alice sorts and concatenates FP<sub>A</sub> and FP<sub>B</sub> to produce the
safety number SN<sub>A</sub>.

Bob repeats the steps above to calculate SN<sub>B</sub>.

Alice and Bob manually compare each other's safety numbers out-of-band. If they
don't match both parties abort the protocol.

If the safety numbers match Alice and Bob have successfully verified each
other's identity keys and data.

### 3.5 Establishing trust

This section describes how one party adds another as a trusted party. Bob, for
example, adds Charlie to his list of trusted parties by performing the following
steps:

Bob and Charlie performs a mutual authentication as described in
[Section 3.3](#33-mutual-authentication) or a manual authentication as described
in [Section 3.4](#34-manual-authentication).

Bob verifies his own signature TS<sub>B</sub> to ensure that his current list of
trusted parties T<sub>B</sub> hasn't been tampered with. If the verification
fails Bob aborts the protocol.

If Charlie successfully authenticates with Bob, Bob adds Charlie's identity
public key IK<sub>C</sub> to his list of trusted parties T<sub>B</sub>:

T<sub>B</sub>' = T<sub>B</sub> || IK<sub>C</sub>

Bob then creates the signature TS<sub>B</sub>' by signing T<sub>B</sub>':

TS<sub>B</sub>' = SIGN(IK<sub>B</sub>, T<sub>B</sub>')

Bob replaces any existing T<sub>B</sub> and TS<sub>B</sub> with their updated
values and stores them for future protocol runs.

How T and TS are stored is beyond the scope of this document.

### 3.6 Certifying ownership

This section describes how one party can create a signature that certifies
another party's ownership of cryptographic identity and data. Charlie, for
example, can certify Alice's ownership by performing the following steps:

Alice and Charlie performs a mutual authentication as described in
[Section 3.3](#33-mutual-authentication) or a manual authentication as described
in [Section 3.4](#34-manual-authentication).

Alice includes the data D<sub>A</sub>, if any, that she wants Charlie to sign in
her authentication message.

If Alice successfully authenticates with Charlie, Charlie creates the signature
AS<sub>C</sub>:

AS<sub>C</sub> = SIGN(IK<sub>C</sub>, D<sub>A</sub> || IK<sub>A</sub>)

Charlie uses AS<sub>C</sub> as data D<sub>C</sub> in his authentication message:

D<sub>C</sub> = AS<sub>C</sub>

If Charlie successfully authenticates with Alice, Alice verifies the
AS<sub>C</sub> signature using IK<sub>C</sub> and D<sub>A</sub>. If the
verification fails Alice aborts the protocol.

If the verification succeeds Alice adds IK<sub>C</sub> and AS<sub>C</sub> to her
certificate C<sub>A</sub>:

C<sub>A</sub>' = C<sub>A</sub> || IK<sub>C</sub> || AS<sub>C</sub>

Alice can now use her updated certificate C<sub>A</sub>' to authenticate with
parties like Bob.

Alice then creates the signature CS<sub>A</sub>' by signing C<sub>A</sub>':

CS<sub>A</sub>' = SIGN(IK<sub>A</sub>, C<sub>A</sub>')

Alice replaces any existing C<sub>A</sub> and CS<sub>A</sub> with their updated
values and stores them for future protocol runs.

How C and CS are stored is beyond the scope of this document.

### 3.7 Key agreement

This section describes how two parties can derive a shared secret key for future
communication. Alice and Bob, for example, can establish a shared secret key by
performing the following steps:

Alice and Bob performs a mutual authentication as described in
[Section 3.3](#33-mutual-authentication) or a manual authentication as described
in [Section 3.4](#34-manual-authentication).

Each party generates an ephemeral X25519 key pair (EKS<sub>A</sub> for Alice,
EKS<sub>B</sub> for Bob) and uses the public keys as data in their respective
authentication messages:

D<sub>A</sub> = EKS<sub>A</sub>\
D<sub>B</sub> = EKS<sub>B</sub>

If the authentication succeeds Alice calculates:

SK = KDF(DH(EKS<sub>A</sub>, EKS<sub>B</sub>))

Alice then deletes her EKS<sub>A</sub> private key and the DH output.

Using EKS<sub>A</sub> and EKS<sub>B</sub>, Bob repeats the DH and KDF
calculations from the above to derive SK, and then deletes his EKS<sub>B</sub>
private key and the DH output.

Alice and Bob have now established a 32-byte secret key that they can use to
encrypt their future communications.

### 3.8 Asynchronous authentication

This section describes how the authentication methods described in the previous
sections can be performed asynchronously via a server.

In order for Alice and Bob to exchange asynchronous authentication messages with
each other both parties will establish a relationship with a server.

Bob generates a unique Ed25519 identity key pair IKS<sub>B</sub> that will be
used solely for communicating with the server that he and Alice chooses to use.

The server uses its identity key IK<sub>S</sub> to certify Bob's ownership of
the identity key IKS<sub>B</sub> as described in
[Section 3.6](#36-certifying-ownership). If the certification succeeds Bob
creates a new certificate ICS<sub>B</sub> that will be used solely when
authenticating with the server.

Bob creates a list of prekeys PKL<sub>B</sub> by generating a set of ephemeral
X25519 keys PK<sub>B</sub>. A 16-bit unsigned big-endian integer is used to
index each key. Bob uses the 0x03 message type prefix to identity the list of
prekeys:

MT = 0x03\
PKL<sub>B</sub> = MT || 0x0000 || PK<sub>B 0</sub> || ... || 0xFFFF || PK<sub>B 65535</sub>

Bob stores the private key for each ephemeral key share in PKL<sub>B</sub>
together with their corresponding index number.

Bob performs a one-way authentication with the server as described in
[Section 3.2](#32-one-way-authentication). Bob uses IKS<sub>B</sub> as the
identity key, ICS<sub>B</sub> as the certificate and PKL<sub>B</sub> as the data
in his authentication message.

The server reads the message type prefix to identify the data in Bob's
authentication message as a list of prekeys. The server uses its identity key
IK<sub>S</sub> to verify the certificate ICS<sub>B</sub>.

If the authentication succeeds the server stores Bob’s identity key
IKS<sub>B</sub> together with the list of prekeys PKL<sub>B</sub>.

Alice repeats the steps above to create her identity key IKS<sub>A</sub>, list
of prekeys PKL<sub>A</sub> and certificate ICS<sub>A</sub>.

Alice performs a one-way authentication with the server using IKS<sub>A</sub>,
PKL<sub>A</sub> and ICS<sub>A</sub>.

If the authentication succeeds the server stores Alice’s identity key
IKS<sub>A</sub> and list of prekeys PKL<sub>A</sub>.

When Alice wants to authenticate with Bob via the server, Alice requests one of
Bob's ephemeral key shares by performing a mutual authentication with the
server.

Alice uses Bob's identity key IKS<sub>B</sub> as the data D<sub>A</sub> in her
authentication message. She sets the message type prefix to 0x04 to identify a
key share request:

MT = 0x04\
D<sub>A</sub> = MT || IKS<sub>B</sub>

If the authentication succeeds the server reads the message type prefix and the
IKS<sub>B</sub> identity key to identify the request for one of Bob's ephemeral
key shares.

The server uses one of Bob's ephemeral key shares and the index (denoted by PI
below) as the data D<sub>S</sub> in its authentication message. For example, to
use Bob's third key share the server calculates:

PI = 0x0002\
D<sub>S</sub> = PI || KS<sub>B 2</sub>

The server deletes the key share indexed by PI from Bob's list of prekeys so
that it cannot be reused and sends the authentication message to Alice.

If the authentication succeeds Alice constructs the ephemeral key share message
KS<sub>A</sub> and the authentication message AM<sub>A</sub> that she will use
for the authentication with Bob.

Alice performs a one-way authentication with the server. She uses
IKS<sub>A</sub> as the identity key, ICS<sub>A</sub> as the certificate and PI,
IKS<sub>B</sub>, KS<sub>A</sub> and AM<sub>A</sub> as the data D<sub>A</sub> in
the authentication message. Alice sets the message type prefix to 0x05 to
identify a forwarding request:

MT = 0x05\
D<sub>A</sub> = MT || IKS<sub>B</sub> || PI || KS<sub>A</sub> || AM<sub>A</sub>

If the authentication succeeds the server reads the message type prefix,
IKS<sub>A</sub>, IKS<sub>B</sub> to identify the forwarding request of an
authentication message from Alice to Bob.

The server performs a one-way authentication with Bob. The server sets the
message type prefix MT to 0x06 to identify a forwarded authentication. It uses
MT, IKS<sub>A</sub>, PI, KS<sub>A</sub> and AM<sub>A</sub> as the data in the
authentication message:

MT = 0x06\
D<sub>S</sub> = MT || IKS<sub>A</sub> || PI || KS<sub>A</sub> || AM<sub>A</sub>

When Alice's message has been forwarded to Bob the server deletes the message.

If the authentication succeeds Bob reads PI, KS<sub>A</sub> and AM<sub>A</sub>.
Bob uses the KS<sub>B</sub> private key indexed by PI and KS<sub>A</sub> to
calculate the AK shared secret key needed to decrypt AM<sub>A</sub>.

After calculating AK, Bob deletes the KS<sub>B</sub> private key indexed by PI
form his list of prekeys so that it cannot be reused.

Bob decrypts and verifies Alice's authentication message as described in the
previous sections. If the verification succeeds Alice have successfully
authenticated with Bob via the server.

Periodically, Alice and Bob will need to generate and upload new prekeys to the
server to ensure that their respective lists of prekeys does not get depleted.

How IKS and PKL are stored on the server is beyond the scope of this document.

## 4. Security considerations

### 4.1 Key compromise

Compromise of a party's Ed25519 identity private key allows impersonation of
that party to others.

Compromise of prekey private keys used for asynchronous authentication as
described in [Section 3.8](#38-asynchronous-authentication) may enable attacks
that extend into the future, such as passive calculation of AK values.

### 4.2 Manual authentication

If a manual authentication as described in
[Section 3.4](#34-manual-authentication) is not performed, the parties will have
no cryptographic guarantee as to who they are communicating with, which may
enable man-in-the-middle attacks.

### 4.3 Asynchronous authentication

Servers used for asynchronous authentication as described in
[Section 3.8](#38-asynchronous-authentication) should prevent malicious parties
from depleting another party's prekeys by putting rate limits on fetching key
shares. The details of how such rate limits are implemented is beyond the scope
of this document.

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

[2] D. Bernstein, N. Duif, T. Lange, P. Schwabe, and B. Yang, "High-speed
high-security signatures"; September 2011.
<https://ed25519.cr.yp.to/ed25519-20110926.pdf>

[3] M. Dworkin, E. Barker, J. Nechvatal, J. Foti, L. Bassham, E. Roback, J. Dray
Jr, "Advanced Encryption Standard (AES)"; Federal Information Processing
Standards Publication 197; November 2001.
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf>

[4] D. McGrew and J. Viega, “The Galois/Counter Mode of Operation (GCM)”;
Submission to NIST Modes of Operation Process; January, 2004.

[5] P. Rogaway, “Authenticated-encryption with Associated-data”; September 2002.
<http://web.cs.ucdavis.edu/~rogaway/papers/ad.pdf>

[6] H. Krawczyk and P. Eronen, “HMAC-based Extract-and-Expand Key Derivation
Function (HKDF)”; Internet Engineering Task Force; RFC 5869; May 2010.
<http://www.ietf.org/rfc/rfc5869.txt>

[7] National Institute of Standards and Technology, "Secure Hash Standard
(SHS)"; Federal Information Processing Standards Publication 180-4;
August, 2015. <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
