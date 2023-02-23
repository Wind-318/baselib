#include <benchmark/benchmark.h>
#include <encrypt.h>
#include <gtest/gtest.h>
// #include <jwt-cpp/jwt.h>
#include <pwt.h>

#include <cstdio>
#include <iostream>
#include <string>

static void BM_PWT_encode(benchmark::State& state) {
    ::wind::utils::pwt::PWTInstance pwtss;
    pwtss.SetPwk("test").SetIss("test").SetAud("test").SetSub("test");
    for (auto _ : state) {
        try {
            pwtss.Encode();
        } catch (const std::exception& e) {
            std::cout << e.what() << std::endl;
            continue;
        }
    }
}
/*
static void BM_jwt_cpp_encode(benchmark::State& state) {
    auto token = jwt::create();
    token.set_issuer("test")
        .set_type("test")
        .set_payload_claim("test", jwt::claim(std::string("test")));
    for (auto _ : state) {
        token.sign(jwt::algorithm::hs256{"secret"});
    }
}
*/
static void BM_PWT_decode(benchmark::State& state) {
    ::wind::utils::pwt::PWTInstance pwtss;
    auto s = pwtss.SetKid("test").Encode();
    for (auto _ : state) {
        auto n = ::wind::utils::pwt::PWTInstance();
        n.CopyAlgorithm(pwtss);
        auto f = n.Decode(s);
        if (!f) {
            std::cout << "decode failed" << std::endl;
            continue;
        }
    }
}

static void BM_PWT_repeat_decode(benchmark::State& state) {
    ::wind::utils::pwt::PWTInstance pwtss;
    auto s = pwtss.SetKid("test").Encode();
    for (auto _ : state) {
        auto f = pwtss.Decode(s);
        if (!f) {
            std::cout << "decode failed" << std::endl;
            continue;
        }
    }
}
/*
static void BM_jwt_cpp_decode(benchmark::State& state) {
    auto s = jwt::create()
                 .set_payload_claim("test", jwt::claim(std::string("test")))
                 .sign(jwt::algorithm::hs256{"secret"});

    for (auto _ : state) {
        try {
            jwt::decode(s);
        } catch (const std::exception& e) {
            continue;
        }
    }
}
*/
static void BM_PWT_encode_long(benchmark::State& state) {
    ::wind::utils::pwt::PWTInstance pwtss;
    pwtss.SetPwk("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
        .SetIss("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
        .SetAud("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
        .SetSub("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog");

    for (auto _ : state) {
        try {
            pwtss.Encode();
        } catch (const std::exception& e) {
            std::cout << e.what() << std::endl;
            continue;
        }
    }
}
/*
static void BM_jwt_cpp_encode_long(benchmark::State& state) {
    auto token = jwt::create();
    token.set_issuer("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
        .set_type("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
        .set_payload_claim("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog",
                           jwt::claim(std::string("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")));

    for (auto _ : state) {
        token.sign(jwt::algorithm::hs256{"secret"});
    }
}
*/
static void BM_PWT_decode_long(benchmark::State& state) {
    ::wind::utils::pwt::PWTInstance pwtss;
    std::string s;
    try {
        s = pwtss.SetPwk("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .SetIss("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .SetAud("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .SetSub("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .Encode();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    for (auto _ : state) {
        auto n = ::wind::utils::pwt::PWTInstance();
        n.CopyAlgorithm(pwtss);
        auto f = n.Decode(s);
        if (!f) {
            std::cout << "decode failed" << std::endl;
            continue;
        }
    }
}

static void BM_PWT_repeat_decode_long(benchmark::State& state) {
    ::wind::utils::pwt::PWTInstance pwtss;
    std::string s;
    try {
        s = pwtss.SetPwk("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .SetIss("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .SetAud("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .SetSub("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                .Encode();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    for (auto _ : state) {
        auto f = pwtss.Decode(s);
        if (!f) {
            std::cout << "decode failed" << std::endl;
            continue;
        }
    }
}
/*
static void BM_jwt_cpp_decode_long(benchmark::State& state) {
    auto s = jwt::create()
                 .set_issuer("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                 .set_type("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")
                 .set_payload_claim("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog",
                                    jwt::claim(std::string("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog")))
                 .sign(jwt::algorithm::hs256{"secret"});

    for (auto _ : state) {
        try {
            jwt::decode(s);
        } catch (const std::exception& e) {
            continue;
        }
    }
}
*/
static void BM_custom(benchmark::State& state) {
    for (auto _ : state) {
        try {
            auto s = ::wind::utils::pwt::CreatePWTInstance()
                         .AddHeaderCustomField("loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooog", "test")
                         .Encode();
        } catch (const std::exception& e) {
            continue;
        }
    }
}

BENCHMARK(BM_PWT_encode)->Iterations(1000);
// BENCHMARK(BM_jwt_cpp_encode)->Iterations(1000);
BENCHMARK(BM_PWT_decode)->Iterations(1000);
BENCHMARK(BM_PWT_repeat_decode)->Iterations(1000);
// BENCHMARK(BM_jwt_cpp_decode)->Iterations(1000);
BENCHMARK(BM_PWT_encode)->Iterations(10000);
// BENCHMARK(BM_jwt_cpp_encode)->Iterations(10000);
BENCHMARK(BM_PWT_decode)->Iterations(10000);
BENCHMARK(BM_PWT_repeat_decode)->Iterations(10000);
// BENCHMARK(BM_jwt_cpp_decode)->Iterations(10000);

BENCHMARK(BM_PWT_encode_long)->Iterations(1000);
// BENCHMARK(BM_jwt_cpp_encode_long)->Iterations(1000);
BENCHMARK(BM_PWT_decode_long)->Iterations(1000);
BENCHMARK(BM_PWT_repeat_decode_long)->Iterations(1000);
// BENCHMARK(BM_jwt_cpp_decode_long)->Iterations(1000);
BENCHMARK(BM_PWT_encode_long)->Iterations(10000);
// BENCHMARK(BM_jwt_cpp_encode_long)->Iterations(10000);
BENCHMARK(BM_PWT_decode_long)->Iterations(10000);
BENCHMARK(BM_PWT_repeat_decode_long)->Iterations(10000);
// BENCHMARK(BM_jwt_cpp_decode_long)->Iterations(10000);

BENCHMARK(BM_custom);

int main(int argc, char** argv) {
    // benchmark::Initialize(&argc, argv);
    // benchmark::RunSpecifiedBenchmarks();
    std::printf("Running main() from %s\n", __FILE__);
    testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}