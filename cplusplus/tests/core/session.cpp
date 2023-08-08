#include <catch2/catch_test_macros.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Session", "[core_session]") {
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
      68,  193, 143, 187, 158, 133, 97, 136, 59,  188, 165,
      11,  242, 164, 152, 180, 9,   15, 203, 5,   115, 123,
      253, 225, 126, 133, 246, 222, 87, 236, 110, 140};

  std::vector<unsigned char> ciphertext = {
      10,  63,  180, 74, 97,  108, 26,  163, 144, 152, 159, 14,  195, 134,
      181, 244, 55,  32, 29,  68,  195, 2,   99,  176, 3,   188, 77,  223,
      82,  222, 85,  33, 164, 83,  212, 5,   137, 216, 156, 53,  173, 72,
      8,   43,  132, 54, 25,  6,   55,  62,  116, 75,  206, 125, 216, 8,
      52,  89,  117, 36, 65,  68,  225, 150, 17,  45,  160, 163, 56,  102,
      169, 218, 53,  41, 248, 194, 14,  51,  103, 188};

  autograph_init();

  int result = autograph_session(transcript.data(), identityKey.data(),
                                 secretKey.data(), ciphertext.data());

  REQUIRE(result == 0);
}
