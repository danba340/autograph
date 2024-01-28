#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>

#include "autograph.h"

TEST_CASE("Channel", "[channel]") {
  Autograph::Signature aliceHandshake = {
      108, 221, 39,  135, 29,  232, 233, 41,  202, 186, 132, 24,  139,
      184, 148, 25,  176, 220, 36,  233, 141, 198, 70,  202, 20,  200,
      68,  236, 107, 159, 123, 139, 153, 154, 90,  113, 25,  157, 63,
      161, 100, 176, 57,  50,  216, 252, 93,  76,  25,  164, 40,  82,
      84,  224, 230, 141, 109, 246, 107, 3,   238, 97,  56,  4,
  };

  Autograph::Signature bobHandshake = {
      250, 223, 89,  191, 184, 213, 155, 233, 5,   153, 109, 133, 148,
      152, 247, 25,  100, 247, 219, 247, 174, 18,  52,  119, 23,  0,
      229, 18,  104, 158, 177, 221, 100, 44,  83,  20,  129, 129, 39,
      156, 119, 247, 59,  12,  220, 184, 207, 44,  211, 160, 50,  225,
      163, 106, 15,  116, 0,   104, 33,  153, 120, 111, 170, 11};

  Autograph::Bytes aliceMessage = {51,  243, 8,   165, 206, 25,  129, 63,
                                   124, 51,  176, 40,  21,  4,   178, 3,
                                   128, 195, 26,  68,  65,  200, 192, 212,
                                   63,  10,  201, 247, 177, 3,   137, 113};

  Autograph::Bytes bobMessage = {253, 199, 105, 203, 139, 136, 132, 228,
                                 198, 157, 65,  140, 116, 90,  212, 112,
                                 55,  190, 186, 221, 205, 80,  46,  24,
                                 161, 117, 201, 113, 133, 213, 29,  105};

  Autograph::Signature aliceSignatureBobData = {
      198, 235, 143, 145, 121, 29,  143, 128, 167, 118, 33,  71, 38,
      209, 169, 2,   134, 90,  203, 72,  171, 252, 236, 237, 55, 41,
      227, 248, 198, 165, 58,  185, 31,  70,  147, 96,  181, 33, 188,
      7,   146, 43,  24,  197, 158, 216, 215, 49,  126, 186, 88, 238,
      233, 86,  167, 207, 20,  150, 227, 38,  160, 68,  82,  8};

  Autograph::Signature aliceSignatureBobIdentity = {
      170, 64,  159, 119, 20,  17,  130, 46,  124, 70,  154, 47,  90,
      7,   116, 204, 255, 198, 56,  60,  24,  112, 214, 188, 212, 64,
      210, 117, 228, 145, 111, 250, 84,  20,  216, 222, 21,  82,  213,
      225, 31,  28,  152, 211, 16,  82,  131, 7,   248, 186, 255, 184,
      35,  205, 183, 167, 138, 179, 217, 135, 163, 124, 13,  5};

  Autograph::Signature bobSignatureAliceData = {
      17,  229, 247, 220, 138, 161, 5,   224, 147, 178, 230, 168, 132,
      164, 94,  3,   119, 118, 16,  163, 222, 85,  3,   160, 88,  222,
      210, 140, 222, 158, 254, 231, 182, 232, 78,  211, 150, 146, 127,
      164, 238, 221, 119, 12,  230, 54,  49,  103, 177, 72,  126, 225,
      214, 41,  80,  214, 247, 95,  23,  145, 227, 87,  172, 4};

  Autograph::Signature bobSignatureAliceIdentity = {
      186, 27,  195, 159, 150, 127, 96,  11,  25,  224, 30,  145, 56,
      194, 138, 164, 70,  54,  243, 213, 229, 203, 179, 218, 207, 213,
      168, 160, 56,  32,  164, 245, 49,  102, 200, 36,  172, 152, 113,
      5,   82,  196, 154, 90,  20,  27,  180, 61,  189, 171, 20,  194,
      165, 165, 65,  178, 190, 16,  44,  82,  157, 68,  102, 13};

  Autograph::PublicKey charlieIdentityKey = {
      129, 128, 10,  70,  174, 223, 175, 90,  43, 37,  148,
      125, 188, 163, 110, 136, 15,  246, 192, 76, 167, 8,
      26,  149, 219, 223, 83,  47,  193, 159, 6,  3};

  Autograph::Signature charlieSignatureAliceData = {
      231, 126, 138, 39,  145, 83,  130, 243, 2,   56,  53,  185, 199,
      242, 217, 239, 118, 208, 172, 6,   201, 132, 94,  179, 57,  59,
      160, 23,  150, 221, 67,  122, 176, 56,  160, 63,  7,   161, 169,
      101, 240, 97,  108, 137, 142, 99,  197, 44,  179, 142, 37,  4,
      135, 162, 118, 160, 119, 245, 234, 39,  26,  75,  71,  6};

  Autograph::Signature charlieSignatureAliceIdentity = {
      146, 120, 170, 85,  78,  187, 162, 243, 234, 149, 138, 201, 18,
      132, 187, 129, 45,  53,  116, 227, 178, 209, 200, 224, 149, 91,
      166, 120, 203, 73,  138, 189, 63,  231, 213, 177, 163, 114, 66,
      151, 61,  253, 109, 250, 226, 140, 249, 3,   188, 44,  127, 108,
      196, 131, 204, 216, 54,  239, 157, 49,  107, 202, 123, 9};

  Autograph::Signature charlieSignatureBobData = {
      135, 249, 64,  214, 240, 146, 173, 141, 97,  18,  16,  47,  83,
      125, 13,  166, 169, 96,  99,  21,  215, 217, 236, 173, 120, 50,
      143, 251, 228, 76,  195, 8,   248, 133, 170, 103, 122, 169, 190,
      57,  51,  14,  171, 199, 229, 55,  55,  195, 53,  202, 139, 118,
      93,  68,  131, 96,  175, 50,  31,  243, 170, 34,  102, 1};

  Autograph::Signature charlieSignatureBobIdentity = {
      198, 41,  56,  189, 24,  9,   75,  102, 228, 51,  193, 102, 25,
      51,  92,  1,   192, 219, 16,  17,  22,  28,  22,  16,  198, 67,
      248, 16,  98,  164, 99,  243, 254, 45,  69,  156, 50,  115, 205,
      43,  155, 242, 78,  64,  205, 218, 80,  171, 34,  128, 255, 51,
      237, 60,  37,  224, 232, 149, 153, 213, 204, 93,  26,  7};

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  Autograph::SafetyNumber safetyNumber = {
      0, 0, 126, 217, 0, 0, 218, 180, 0, 1, 102, 162, 0, 0, 41, 97,
      0, 0, 40,  245, 0, 1, 15,  218, 0, 0, 12,  28,  0, 0, 98, 95,
      0, 0, 96,  224, 0, 0, 16,  147, 0, 1, 74,  101, 0, 1, 33, 26,
      0, 0, 234, 68,  0, 0, 190, 212, 0, 1, 96,  162, 0, 0, 48, 226};

  Autograph::KeyPair aliceIdentityKeyPair = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125,
      202, 197, 2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149,
      122, 103, 57,  199, 19,  17,  213, 153, 88,  124, 93,  136, 104,
      111, 196, 208, 155, 156, 165, 31,  120, 186, 79,  205, 247, 175,
      243, 184, 114, 80,  152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::KeyPair aliceEphemeralKeyPair = {
      201, 142, 54,  248, 151, 150, 224, 79,  30,  126, 207, 157, 118,
      85,  9,   212, 148, 156, 73,  176, 107, 107, 47,  111, 95,  98,
      33,  192, 80,  223, 48,  221, 35,  16,  23,  37,  205, 131, 166,
      97,  13,  81,  136, 246, 193, 253, 139, 193, 230, 155, 222, 221,
      37,  114, 190, 87,  104, 44,  210, 144, 127, 176, 198, 45};

  Autograph::KeyPair bobIdentityKeyPair = {
      52,  0,   150, 226, 138, 192, 249, 231, 126, 199, 95,  240, 106,
      17,  150, 95,  221, 247, 33,  201, 19,  62,  4,   135, 169, 104,
      128, 218, 250, 251, 243, 190, 177, 67,  45,  125, 158, 190, 181,
      222, 101, 149, 224, 200, 223, 235, 222, 110, 67,  61,  200, 62,
      29,  37,  150, 228, 137, 114, 143, 77,  115, 135, 143, 103};

  Autograph::KeyPair bobEphemeralKeyPair = {
      74,  233, 106, 152, 76,  212, 181, 144, 132, 237, 223, 58,  122,
      173, 99,  100, 152, 219, 214, 210, 213, 72,  171, 73,  167, 92,
      199, 196, 176, 66,  213, 208, 88,  115, 171, 4,   34,  181, 120,
      21,  10,  39,  204, 215, 158, 210, 177, 243, 28,  138, 52,  91,
      236, 55,  30,  117, 10,  125, 87,  232, 80,  6,   232, 93};

  Autograph::State aliceState;
  Autograph::State bobState;

  Autograph::Channel a(aliceState);
  Autograph::Channel b(bobState);

  auto [aliceInit, aliceHello] =
      a.useKeyPairs(aliceIdentityKeyPair, aliceEphemeralKeyPair);

  auto [bobInit, bobHello] =
      b.useKeyPairs(bobIdentityKeyPair, bobEphemeralKeyPair);

  a.usePublicKeys(bobHello);
  b.usePublicKeys(aliceHello);

  auto [aliceKeyExchange, handshakeAlice] = a.keyExchange(true);
  auto [bobKeyExchange, handshakeBob] = b.keyExchange(false);

  bool aliceVerified = a.verifyKeyExchange(handshakeBob);
  bool bobVerified = b.verifyKeyExchange(handshakeAlice);

  SECTION("should allow Alice and Bob to perform a key exchange") {
    REQUIRE(aliceInit == true);
    REQUIRE(bobInit == true);
    REQUIRE(aliceKeyExchange == true);
    REQUIRE(bobKeyExchange == true);
    REQUIRE(aliceVerified == true);
    REQUIRE(bobVerified == true);
    REQUIRE(handshakeAlice == aliceHandshake);
    REQUIRE(handshakeBob == bobHandshake);
  }

  SECTION("should calculate safety numbers correctly") {
    auto [aliceSuccess, aliceSafetyNumber] = a.authenticate();
    auto [bobSuccess, bobSafetyNumber] = b.authenticate();
    REQUIRE(aliceSuccess == true);
    REQUIRE(bobSuccess == true);
    REQUIRE(aliceSafetyNumber == safetyNumber);
    REQUIRE(bobSafetyNumber == safetyNumber);
  }

  SECTION("should allow Alice to send encrypted data to Bob") {
    auto [encryptSuccess, encryptIndex, message] = a.encrypt(data);
    auto [decryptSuccess, decryptIndex, plaintext] = b.decrypt(message);
    REQUIRE(encryptSuccess == true);
    REQUIRE(decryptSuccess == true);
    REQUIRE(encryptIndex == 1);
    REQUIRE(decryptIndex == 1);
    REQUIRE_THAT(message, Catch::Matchers::Equals(aliceMessage));
    REQUIRE_THAT(plaintext, Catch::Matchers::Equals(data));
  }

  SECTION("should allow Bob to send encrypted data to Alice") {
    auto [encryptSuccess, encryptIndex, message] = b.encrypt(data);
    auto [decryptSuccess, decryptIndex, plaintext] = a.decrypt(message);
    REQUIRE_THAT(message, Catch::Matchers::Equals(bobMessage));
    REQUIRE_THAT(plaintext, Catch::Matchers::Equals(data));
  }

  SECTION(
      "should allow Bob to certify Alice's ownership of her identity key and "
      "data") {
    auto [success, signature] = b.certifyData(data);
    REQUIRE(success == true);
    REQUIRE(signature == bobSignatureAliceData);
  }

  SECTION(
      "should allow Alice to certify Bob's ownership of his identity key and "
      "data") {
    auto [success, signature] = a.certifyData(data);
    REQUIRE(success == true);
    REQUIRE(signature == aliceSignatureBobData);
  }

  SECTION("should allow Bob to certify Alice's ownership of her identity key") {
    auto [success, signature] = b.certifyIdentity();
    REQUIRE(success == true);
    REQUIRE(signature == bobSignatureAliceIdentity);
  }

  SECTION("should allow Alice to certify Bob's ownership of his identity key") {
    auto [success, signature] = a.certifyIdentity();
    REQUIRE(success == true);
    REQUIRE(signature == aliceSignatureBobIdentity);
  }

  SECTION(
      "should allow Bob to verify Alice's ownership of her identity key and "
      "data based on Charlie's public key and signature") {
    bool verified =
        b.verifyData(data, charlieIdentityKey, charlieSignatureAliceData);
    REQUIRE(verified == true);
  }

  SECTION(
      "should allow Alice to verify Bob's ownership of his identity key and "
      "data based on Charlie's public key and signature") {
    bool verified =
        a.verifyData(data, charlieIdentityKey, charlieSignatureBobData);
    REQUIRE(verified == true);
  }

  SECTION(
      "should allow Bob to verify Alice's ownership of her identity key based "
      "on Charlie's public key and signature") {
    bool verified =
        b.verifyIdentity(charlieIdentityKey, charlieSignatureAliceIdentity);
    REQUIRE(verified == true);
  }

  SECTION(
      "should allow Alice to verify Bob's ownership of his identity key based "
      "on Charlie's public key and signature") {
    bool verified =
        a.verifyIdentity(charlieIdentityKey, charlieSignatureBobIdentity);
    REQUIRE(verified == true);
  }

  SECTION("should handle out of order messages correctly") {
    Autograph::Bytes data1 = {1, 2, 3};
    Autograph::Bytes data2 = {5, 6, 7};
    Autograph::Bytes data3 = {7, 8, 9};
    Autograph::Bytes data4 = {10, 11, 12};
    auto [encryptSuccess1, encryptIndex1, message1] = a.encrypt(data1);
    auto [encryptSuccess2, encryptIndex2, message2] = a.encrypt(data2);
    auto [encryptSuccess3, encryptIndex3, message3] = a.encrypt(data3);
    auto [encryptSuccess4, encryptIndex4, message4] = a.encrypt(data4);
    auto [decryptSuccess4, decryptIndex4, plaintext4] = b.decrypt(message4);
    auto [decryptSuccess2, decryptIndex2, plaintext2] = b.decrypt(message2);
    auto [decryptSuccess3, decryptIndex3, plaintext3] = b.decrypt(message3);
    auto [decryptSuccess1, decryptIndex1, plaintext1] = b.decrypt(message1);
    REQUIRE(decryptSuccess1 == true);
    REQUIRE(decryptSuccess2 == true);
    REQUIRE(decryptSuccess3 == true);
    REQUIRE(decryptSuccess4 == true);
    REQUIRE(decryptIndex1 == 1);
    REQUIRE(decryptIndex2 == 2);
    REQUIRE(decryptIndex3 == 3);
    REQUIRE(decryptIndex4 == 4);
    REQUIRE_THAT(plaintext1, Catch::Matchers::Equals(data1));
    REQUIRE_THAT(plaintext2, Catch::Matchers::Equals(data2));
    REQUIRE_THAT(plaintext3, Catch::Matchers::Equals(data3));
    REQUIRE_THAT(plaintext4, Catch::Matchers::Equals(data4));
  }

  SECTION("should handle sessions correctly") {
    auto [closeSuccess, key, ciphertext] = a.close();
    auto openSuccess = b.open(key, ciphertext);
    auto [certifySuccess, signature] = b.certifyIdentity();
    REQUIRE(closeSuccess == true);
    REQUIRE(openSuccess == true);
    REQUIRE(certifySuccess == true);
    REQUIRE(signature == aliceSignatureBobIdentity);
  }
}
