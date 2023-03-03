#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
// #include <jwt-cpp/jwt.h>
#include <cstdio>
#include <iostream>
#include <string>

#include "encrypt.h"
#include "pwt.h"

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    std::printf("Running main() from %s\n", __FILE__);
    testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}