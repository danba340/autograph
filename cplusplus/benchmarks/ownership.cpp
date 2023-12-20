#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void certify_data(benchmark::State& benchmarkState) {
  Autograph::Bytes certificationState = {
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

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  Autograph::Bytes signature(64);
  auto state = Autograph::createStateBytes();
  std::copy(certificationState.begin(), certificationState.end(),
            state.begin());

  for (auto _ : benchmarkState) {
    if (!autograph_certify_data(signature.data(), state.data(), data.data(),
                                data.size())) {
      throw std::runtime_error("Data certification failed");
    }
  }
}

static void certify_identity(benchmark::State& benchmarkState) {
  Autograph::Bytes certificationState = {
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

  Autograph::Bytes signature(64);
  auto state = Autograph::createStateBytes();
  std::copy(certificationState.begin(), certificationState.end(),
            state.begin());

  for (auto _ : benchmarkState) {
    if (!autograph_certify_identity(signature.data(), state.data())) {
      throw std::runtime_error("Identity certification failed");
    }
  }
}

static void verify_data(benchmark::State& benchmarkState) {
  Autograph::Bytes verificationState = {
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

  Autograph::Bytes charlieIdentityKey = {129, 128, 10,  70,  174, 223, 175, 90,
                                         43,  37,  148, 125, 188, 163, 110, 136,
                                         15,  246, 192, 76,  167, 8,   26,  149,
                                         219, 223, 83,  47,  193, 159, 6,   3};

  Autograph::Bytes charlieSignatureData = {
      231, 126, 138, 39,  145, 83,  130, 243, 2,   56,  53,  185, 199,
      242, 217, 239, 118, 208, 172, 6,   201, 132, 94,  179, 57,  59,
      160, 23,  150, 221, 67,  122, 176, 56,  160, 63,  7,   161, 169,
      101, 240, 97,  108, 137, 142, 99,  197, 44,  179, 142, 37,  4,
      135, 162, 118, 160, 119, 245, 234, 39,  26,  75,  71,  6};

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  auto state = Autograph::createStateBytes();
  std::copy(verificationState.begin(), verificationState.end(), state.begin());

  for (auto _ : benchmarkState) {
    if (!autograph_verify_data(state.data(), data.data(), data.size(),
                               charlieIdentityKey.data(),
                               charlieSignatureData.data())) {
      throw std::runtime_error("Data verification failed");
    }
  }
}

static void verify_identity(benchmark::State& benchmarkState) {
  Autograph::Bytes verificationState = {
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

  Autograph::Bytes charlieIdentityKey = {129, 128, 10,  70,  174, 223, 175, 90,
                                         43,  37,  148, 125, 188, 163, 110, 136,
                                         15,  246, 192, 76,  167, 8,   26,  149,
                                         219, 223, 83,  47,  193, 159, 6,   3};

  Autograph::Bytes charlieSignatureIdentity = {
      146, 120, 170, 85,  78,  187, 162, 243, 234, 149, 138, 201, 18,
      132, 187, 129, 45,  53,  116, 227, 178, 209, 200, 224, 149, 91,
      166, 120, 203, 73,  138, 189, 63,  231, 213, 177, 163, 114, 66,
      151, 61,  253, 109, 250, 226, 140, 249, 3,   188, 44,  127, 108,
      196, 131, 204, 216, 54,  239, 157, 49,  107, 202, 123, 9};

  auto state = Autograph::createStateBytes();
  std::copy(verificationState.begin(), verificationState.end(), state.begin());

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
