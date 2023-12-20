#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void key_exchange(benchmark::State &benchmarkState) {
  Autograph::Bytes ourIdentityPrivateKey = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93, 254,
      238, 125, 202, 197, 2,   56,  252, 122, 177, 18, 187,
      249, 208, 29,  149, 122, 103, 57,  199, 19,  17};

  Autograph::Bytes ourIdentityPublicKey = {
      213, 153, 88,  124, 93,  136, 104, 111, 196, 208, 155,
      156, 165, 31,  120, 186, 79,  205, 247, 175, 243, 184,
      114, 80,  152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::Bytes aliceEphemeralPrivateKey = {
      201, 142, 54, 248, 151, 150, 224, 79,  30,  126, 207,
      157, 118, 85, 9,   212, 148, 156, 73,  176, 107, 107,
      47,  111, 95, 98,  33,  192, 80,  223, 48,  221};

  Autograph::Bytes ourEphemeralPublicKey = {
      35,  16,  23,  37,  205, 131, 166, 97,  13,  81, 136,
      246, 193, 253, 139, 193, 230, 155, 222, 221, 37, 114,
      190, 87,  104, 44,  210, 144, 127, 176, 198, 45};

  Autograph::Bytes theirIdentityKey = {77,  67,  45,  125, 158, 190, 181, 222,
                                       101, 149, 224, 200, 223, 235, 222, 110,
                                       67,  61,  200, 62,  29,  37,  150, 228,
                                       137, 114, 143, 77,  115, 135, 143, 103};

  Autograph::Bytes theirEphemeralKey = {88, 115, 171, 4,   34,  181, 120, 21,
                                        10, 39,  204, 215, 158, 210, 177, 243,
                                        28, 138, 52,  91,  236, 55,  30,  117,
                                        10, 125, 87,  232, 80,  6,   232, 93};

  Autograph::Bytes handshake(80);
  Autograph::Bytes ourEphemeralPrivateKey(32);
  auto state = Autograph::createStateBytes();

  for (auto _ : benchmarkState) {
    std::copy(aliceEphemeralPrivateKey.begin(), aliceEphemeralPrivateKey.end(),
              ourEphemeralPrivateKey.begin());
    if (!autograph_key_exchange(
            handshake.data(), state.data(), 1, ourIdentityPrivateKey.data(),
            ourIdentityPublicKey.data(), ourEphemeralPrivateKey.data(),
            ourEphemeralPublicKey.data(), theirIdentityKey.data(),
            theirEphemeralKey.data())) {
      throw std::runtime_error("Key exchange failed");
    }
  }
}

static void verify_key_exchange(benchmark::State &benchmarkState) {
  Autograph::Bytes verificationState = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125, 202,
      197, 2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149, 122, 103,
      57,  199, 19,  17,  213, 153, 88,  124, 93,  136, 104, 111, 196, 208,
      155, 156, 165, 31,  120, 186, 79,  205, 247, 175, 243, 184, 114, 80,
      152, 243, 24,  225, 91,  220, 141, 150, 177, 67,  45,  125, 158, 190,
      181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67,  61,  200, 62,
      29,  37,  150, 228, 137, 114, 143, 77,  115, 135, 143, 103, 0,   0,
      0,   0,   229, 152, 150, 64,  86,  142, 184, 73,  69,  27,  43,  178,
      92,  235, 209, 83,  247, 201, 107, 101, 30,  171, 111, 124, 61,  79,
      74,  85,  28,  31,  186, 140, 0,   0,   0,   0,   19,  204, 155, 9,
      177, 55,  134, 149, 159, 211, 24,  84,  231, 36,  192, 217, 101, 73,
      6,   231, 177, 120, 184, 52,  93,  155, 35,  35,  16,  40,  135, 52};

  Autograph::Bytes ourEphemeralPublicKey = {
      35,  16,  23,  37,  205, 131, 166, 97,  13,  81, 136,
      246, 193, 253, 139, 193, 230, 155, 222, 221, 37, 114,
      190, 87,  104, 44,  210, 144, 127, 176, 198, 45};

  Autograph::Bytes theirHandshake = {
      105, 178, 89,  152, 225, 150, 49,  251, 77,  155, 134, 254, 92,  168,
      57,  159, 252, 72,  82,  106, 91,  57,  65,  119, 0,   72,  102, 245,
      247, 26,  62,  212, 237, 20,  252, 233, 27,  144, 35,  93,  180, 235,
      237, 96,  46,  167, 156, 114, 58,  12,  43,  214, 201, 79,  108, 134,
      34,  34,  36,  220, 228, 255, 233, 146, 248, 162, 157, 164, 237, 38,
      77,  217, 133, 180, 27,  98,  3,   247, 199, 24};

  auto state = Autograph::createStateBytes();
  std::copy(verificationState.begin(), verificationState.end(), state.begin());

  for (auto _ : benchmarkState) {
    if (!autograph_verify_key_exchange(state.data(),
                                       ourEphemeralPublicKey.data(),
                                       theirHandshake.data())) {
      throw std::runtime_error("Key exchange verification failed");
    }
  }
}

BENCHMARK(key_exchange);
BENCHMARK(verify_key_exchange);
