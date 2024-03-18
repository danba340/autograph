#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void ephemeral_key_pair(benchmark::State& benchmarkState) {
  Autograph::KeyPair keyPair;

  for (auto _ : benchmarkState) {
    if (!autograph_ephemeral_key_pair(keyPair.data())) {
      throw std::runtime_error("Ephemeral key pair generation failed");
    }
  }
}

static void identity_key_pair(benchmark::State& benchmarkState) {
  Autograph::KeyPair keyPair;

  for (auto _ : benchmarkState) {
    if (!autograph_identity_key_pair(keyPair.data())) {
      throw std::runtime_error("Identity key pair generation failed");
    }
  }
}

BENCHMARK(ephemeral_key_pair);
BENCHMARK(identity_key_pair);
