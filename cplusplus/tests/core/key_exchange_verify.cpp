#include <catch2/catch_test_macros.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Key exchange verification", "[core_key_exchange_verify]") {
  std::vector<unsigned char> transcript = {
      91,  119, 85,  151, 32,  20,  121, 20,  19,  106, 90,  56,  141, 90,  16,
      210, 14,  244, 60,  251, 140, 48,  190, 65,  194, 35,  166, 246, 1,   209,
      4,   33,  232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235, 97,  118,
      3,   241, 131, 200, 140, 54,  155, 28,  46,  158, 76,  96,  4,   150, 61,
      34,  13,  133, 138, 16,  9,   47,  109, 23,  19,  165, 137, 95,  186, 203,
      186, 154, 179, 116, 3,   160, 119, 225, 180, 226, 19,  172, 45,  113, 125,
      124, 86,  94,  159, 161, 119, 249, 212, 82,  190, 253, 45,  230, 86,  74,
      150, 239, 0,   26,  41,  131, 245, 177, 87,  106, 105, 167, 58,  158, 184,
      244, 65,  205, 42,  40,  80,  134, 52};

  std::vector<unsigned char> identityKey = {
      232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235,
      97,  118, 3,   241, 131, 200, 140, 54,  155, 28,  46,
      158, 76,  96,  4,   150, 61,  34,  13,  133, 138};

  std::vector<unsigned char> secretKey = {
      57,  57,  108, 188, 142, 112, 7,   32,  79,  126, 171,
      206, 154, 13,  92,  105, 189, 213, 214, 43,  82,  217,
      140, 47,  83,  197, 190, 113, 200, 228, 185, 207};

  std::vector<unsigned char> ciphertext = {
      40,  96,  87,  46,  204, 210, 12,  62,  80,  86,  55,  252, 191, 201,
      183, 188, 150, 80,  124, 92,  248, 44,  173, 8,   66,  54,  229, 117,
      245, 117, 243, 248, 77,  227, 184, 224, 105, 115, 69,  212, 103, 64,
      198, 124, 122, 196, 195, 215, 250, 95,  169, 218, 185, 119, 150, 206,
      130, 255, 243, 124, 48,  52,  32,  211, 77,  244, 171, 54,  222, 115,
      138, 209, 166, 140, 240, 181, 115, 173, 224, 224, 108, 145, 15,  210,
      138, 188, 76,  13,  29,  19,  188, 120, 188, 109, 89,  34};

  autograph_init();

  int result =
      autograph_key_exchange_verify(transcript.data(), identityKey.data(),
                                    secretKey.data(), ciphertext.data());

  REQUIRE(result == 0);
}
