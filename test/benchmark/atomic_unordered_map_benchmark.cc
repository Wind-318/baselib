#include <benchmark/benchmark.h>

#include <string>
#include <unordered_map>

#include "atomic_unordered_map.h"

static void BM_atomic_map_range(benchmark::State& state) {
    ::wind::atomic_unordered_map<int, int> map;
    for (int i = 0; i < 100; ++i) {
        map.insert(i, i);
    }

    for (auto _ : state) {
        map.range([](const int& key, const int& value) {
            for (int i = 0; i < 1000; ++i) {
                auto x = key + value;
                x += x;
                x *= x;
                auto y = x + x * x + key + value;
            }
        });
    }
}

static void BM_atomic_map_range_s(benchmark::State& state) {
    ::wind::atomic_unordered_map<int, int> map;
    for (int i = 0; i < 100; ++i) {
        map.insert(i, i);
    }
    for (auto _ : state) {
        map.range_s([](const int& key, const int& value) {
            for (int i = 0; i < 1000; ++i) {
                auto x = key + value;
                x += x;
                x *= x;
                auto y = x + x * x + key + value;
            }
        });
    }
}

static void BM_atomic_map_range_short(benchmark::State& state) {
    ::wind::atomic_unordered_map<int, int> map;
    for (int i = 0; i < 100; ++i) {
        map.insert(i, i);
    }

    for (auto _ : state) {
        map.range([](const int& key, const int& value) {
            for (int i = 0; i < 100; ++i) {
                auto x = key + value;
            }
        });
    }
}

static void BM_atomic_map_range_s_short(benchmark::State& state) {
    ::wind::atomic_unordered_map<int, int> map;
    for (int i = 0; i < 100; ++i) {
        map.insert(i, i);
    }
    for (auto _ : state) {
        map.range_s([](const int& key, const int& value) {
            for (int i = 0; i < 100; ++i) {
                auto x = key + value;
            }
        });
    }
}

BENCHMARK(BM_atomic_map_range)->Iterations(10000);
BENCHMARK(BM_atomic_map_range_s)->Iterations(10000);
BENCHMARK(BM_atomic_map_range_short)->Iterations(10000);
BENCHMARK(BM_atomic_map_range_s_short)->Iterations(10000);