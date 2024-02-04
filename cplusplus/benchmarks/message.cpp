#include <benchmark/benchmark.h>

#include <algorithm>
#include <stdexcept>

#include "autograph.h"

static void decrypt_message(benchmark::State& benchmarkState) {
  Autograph::State initialState = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125, 202, 197,
      2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149, 122, 103, 57,  199,
      19,  17,  213, 153, 88,  124, 93,  136, 104, 111, 196, 208, 155, 156, 165,
      31,  120, 186, 79,  205, 247, 175, 243, 184, 114, 80,  152, 243, 24,  225,
      91,  220, 141, 150, 177, 67,  45,  125, 158, 190, 181, 222, 101, 149, 224,
      200, 223, 235, 222, 110, 67,  61,  200, 62,  29,  37,  150, 228, 137, 114,
      143, 77,  115, 135, 143, 103, 0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   217, 155, 76,  165, 59,  188, 67,  41,  220, 168, 9,   28,
      236, 172, 159, 253, 132, 240, 104, 28,  183, 164, 95,  57,  132, 227, 32,
      234, 84,  97,  192, 180, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   228, 80,  92,  70,  9,   154, 102, 79,  79,  238, 183, 1,   104,
      239, 123, 93,  228, 74,  44,  60,  147, 21,  105, 30,  217, 135, 107, 104,
      104, 117, 50,  116,
  };

  Autograph::State state;
  Autograph::Bytes plaintext(16);
  Autograph::Size plaintextSize;
  Autograph::Index index;
  Autograph::Bytes ciphertext = {253, 199, 105, 203, 139, 136, 132, 228,
                                 198, 157, 65,  140, 116, 90,  212, 112,
                                 55,  190, 186, 221, 205, 80,  46,  24,
                                 161, 117, 201, 113, 133, 213, 29,  105};

  for (auto _ : benchmarkState) {
    std::copy(initialState.begin(), initialState.end(), state.begin());
    std::fill(state.begin() + 184, state.end(), 0);
    if (!autograph_decrypt_message(plaintext.data(), plaintextSize.data(),
                                   index.data(), state.data(),
                                   ciphertext.data(), ciphertext.size())) {
      throw std::runtime_error("Decryption failed");
    }
  }
}

static void encrypt_message(benchmark::State& benchmarkState) {
  Autograph::State state = {
      52,  0,   150, 226, 138, 192, 249, 231, 126, 199, 95,  240, 106, 17,  150,
      95,  221, 247, 33,  201, 19,  62,  4,   135, 169, 104, 128, 218, 250, 251,
      243, 190, 177, 67,  45,  125, 158, 190, 181, 222, 101, 149, 224, 200, 223,
      235, 222, 110, 67,  61,  200, 62,  29,  37,  150, 228, 137, 114, 143, 77,
      115, 135, 143, 103, 213, 153, 88,  124, 93,  136, 104, 111, 196, 208, 155,
      156, 165, 31,  120, 186, 79,  205, 247, 175, 243, 184, 114, 80,  152, 243,
      24,  225, 91,  220, 141, 150, 0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   228, 80,  92,  70,  9,   154, 102, 79,  79,  238, 183, 1,
      104, 239, 123, 93,  228, 74,  44,  60,  147, 21,  105, 30,  217, 135, 107,
      104, 104, 117, 50,  116, 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   217, 155, 76,  165, 59,  188, 67,  41,  220, 168, 9,   28,  236,
      172, 159, 253, 132, 240, 104, 28,  183, 164, 95,  57,  132, 227, 32,  234,
      84,  97,  192, 180};

  Autograph::Bytes plaintext = {72, 101, 108, 108, 111, 32,
                                87, 111, 114, 108, 100};
  Autograph::Bytes ciphertext(32);
  Autograph::Index index;

  for (auto _ : benchmarkState) {
    if (!autograph_encrypt_message(ciphertext.data(), index.data(),
                                   state.data(), plaintext.data(),
                                   plaintext.size())) {
      throw std::runtime_error("Encryption failed");
    }
  }
}

BENCHMARK(decrypt_message);
BENCHMARK(encrypt_message);
