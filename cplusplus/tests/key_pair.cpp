#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Key pair", "[key_pair]") {
  Autograph::KeyPair emptyKeyPair;

  SECTION("should generate ephemeral key pairs") {
    auto [success, keyPair] = Autograph::generateKeyPair();
    REQUIRE(success == true);
    REQUIRE(keyPair != emptyKeyPair);
  }

  SECTION("should generate identity key pairs") {
    auto [success, keyPair] = Autograph::generateIdentityKeyPair();
    REQUIRE(success == true);
    REQUIRE(keyPair != emptyKeyPair);
  }
}
