#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void certify_data(benchmark::State& benchmarkState) {
  Autograph::State state = {
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
      104, 117, 50,  116};

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  Autograph::Signature signature;

  for (auto _ : benchmarkState) {
    if (!autograph_certify_data(signature.data(), state.data(), data.data(),
                                data.size())) {
      throw std::runtime_error("Data certification failed");
    }
  }
}

static void certify_identity(benchmark::State& benchmarkState) {
  Autograph::State state = {
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
      104, 117, 50,  116};

  Autograph::Signature signature;

  for (auto _ : benchmarkState) {
    if (!autograph_certify_identity(signature.data(), state.data())) {
      throw std::runtime_error("Identity certification failed");
    }
  }
}

static void verify_data(benchmark::State& benchmarkState) {
  Autograph::State state = {
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
      104, 117, 50,  116};

  Autograph::PublicKey charlieIdentityKey = {
      129, 128, 10,  70,  174, 223, 175, 90,  43, 37,  148,
      125, 188, 163, 110, 136, 15,  246, 192, 76, 167, 8,
      26,  149, 219, 223, 83,  47,  193, 159, 6,  3};

  Autograph::Signature charlieSignatureData = {
      135, 249, 64,  214, 240, 146, 173, 141, 97,  18,  16,  47,  83,
      125, 13,  166, 169, 96,  99,  21,  215, 217, 236, 173, 120, 50,
      143, 251, 228, 76,  195, 8,   248, 133, 170, 103, 122, 169, 190,
      57,  51,  14,  171, 199, 229, 55,  55,  195, 53,  202, 139, 118,
      93,  68,  131, 96,  175, 50,  31,  243, 170, 34,  102, 1};

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  for (auto _ : benchmarkState) {
    if (!autograph_verify_data(state.data(), data.data(), data.size(),
                               charlieIdentityKey.data(),
                               charlieSignatureData.data())) {
      throw std::runtime_error("Data verification failed");
    }
  }
}

static void verify_identity(benchmark::State& benchmarkState) {
  Autograph::State state = {
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
      104, 117, 50,  116};

  Autograph::Bytes charlieIdentityKey = {129, 128, 10,  70,  174, 223, 175, 90,
                                         43,  37,  148, 125, 188, 163, 110, 136,
                                         15,  246, 192, 76,  167, 8,   26,  149,
                                         219, 223, 83,  47,  193, 159, 6,   3};

  Autograph::Bytes charlieSignatureIdentity = {
      198, 41,  56,  189, 24,  9,   75,  102, 228, 51,  193, 102, 25,
      51,  92,  1,   192, 219, 16,  17,  22,  28,  22,  16,  198, 67,
      248, 16,  98,  164, 99,  243, 254, 45,  69,  156, 50,  115, 205,
      43,  155, 242, 78,  64,  205, 218, 80,  171, 34,  128, 255, 51,
      237, 60,  37,  224, 232, 149, 153, 213, 204, 93,  26,  7};

  for (auto _ : benchmarkState) {
    if (!autograph_verify_identity(state.data(), charlieIdentityKey.data(),
                                   charlieSignatureIdentity.data())) {
      throw std::runtime_error("Identity verification failed");
    }
  }
}

BENCHMARK(certify_data);
BENCHMARK(certify_identity);
BENCHMARK(verify_data);
BENCHMARK(verify_identity);
