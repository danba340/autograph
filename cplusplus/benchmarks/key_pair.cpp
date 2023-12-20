#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void ephemeral_key_pair(benchmark::State& benchmarkState) {
  Autograph::Bytes privateKey(32);
  Autograph::Bytes publicKey(32);

  for (auto _ : benchmarkState) {
    if (!autograph_ephemeral_key_pair(privateKey.data(), publicKey.data())) {
      throw std::runtime_error("Ephemeral key pair generation failed");
    }
  }
}

static void identity_key_pair(benchmark::State& benchmarkState) {
  Autograph::Bytes privateKey(32);
  Autograph::Bytes publicKey(32);

  for (auto _ : benchmarkState) {
    if (!autograph_identity_key_pair(privateKey.data(), publicKey.data())) {
      throw std::runtime_error("Identity key pair generation failed");
    }
  }
}

BENCHMARK(ephemeral_key_pair);
BENCHMARK(identity_key_pair);
