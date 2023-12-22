#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void decrypt_message(benchmark::State& benchmarkState) {
  Autograph::Bytes decryptState = {
      52,  0,   150, 226, 138, 192, 249, 231, 126, 199, 95,  240, 106, 17,
      150, 95,  221, 247, 33,  201, 19,  62,  4,   135, 169, 104, 128, 218,
      250, 251, 243, 190, 177, 67,  45,  125, 158, 190, 181, 222, 101, 149,
      224, 200, 223, 235, 222, 110, 67,  61,  200, 62,  29,  37,  150, 228,
      137, 114, 143, 77,  115, 135, 143, 103, 213, 153, 88,  124, 93,  136,
      104, 111, 196, 208, 155, 156, 165, 31,  120, 186, 79,  205, 247, 175,
      243, 184, 114, 80,  152, 243, 24,  225, 91,  220, 141, 150, 0,   0,
      0,   0,   19,  204, 155, 9,   177, 55,  134, 149, 159, 211, 24,  84,
      231, 36,  192, 217, 101, 73,  6,   231, 177, 120, 184, 52,  93,  155,
      35,  35,  16,  40,  135, 52,  0,   0,   0,   0,   229, 152, 150, 64,
      86,  142, 184, 73,  69,  27,  43,  178, 92,  235, 209, 83,  247, 201,
      107, 101, 30,  171, 111, 124, 61,  79,  74,  85,  28,  31,  186, 140};

  auto state = Autograph::createState();
  Autograph::Bytes plaintext(16);
  Autograph::Bytes plaintextSize(4);
  Autograph::Bytes index(4);
  Autograph::Bytes ciphertext = {131, 234, 21,  146, 246, 197, 94,  148,
                                 235, 8,   84,  219, 17,  162, 128, 103,
                                 112, 25,  127, 50,  73,  12,  174, 1,
                                 124, 118, 175, 10,  130, 195, 225, 29};

  for (auto _ : benchmarkState) {
    std::copy(decryptState.begin(), decryptState.end(), state.begin());
    if (!autograph_decrypt_message(plaintext.data(), plaintextSize.data(),
                                   index.data(), state.data(),
                                   ciphertext.data(), ciphertext.size())) {
      throw std::runtime_error("Decryption failed");
    }
  }
}

static void encrypt_message(benchmark::State& benchmarkState) {
  Autograph::Bytes encryptState = {
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

  auto state = Autograph::createState();
  Autograph::Bytes plaintext = {72, 101, 108, 108, 111, 32,
                                87, 111, 114, 108, 100};
  Autograph::Bytes ciphertext(32);
  Autograph::Bytes index(4);

  for (auto _ : benchmarkState) {
    std::copy(encryptState.begin(), encryptState.end(), state.begin());
    if (!autograph_encrypt_message(ciphertext.data(), index.data(),
                                   state.data(), plaintext.data(),
                                   plaintext.size())) {
      throw std::runtime_error("Encryption failed");
    }
  }
}

BENCHMARK(decrypt_message);
BENCHMARK(encrypt_message);
