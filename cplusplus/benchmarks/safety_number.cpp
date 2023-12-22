#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void safety_number(benchmark::State& benchmarkState) {
  Autograph::Bytes safetyNumberState = {
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

  Autograph::Bytes safetyNumber(64);
  auto state = Autograph::createState();
  std::copy(safetyNumberState.begin(), safetyNumberState.end(), state.begin());

  for (auto _ : benchmarkState) {
    if (!autograph_safety_number(safetyNumber.data(), state.data())) {
      throw std::runtime_error("Safety number calculation failed");
    }
  }
}

BENCHMARK(safety_number);
