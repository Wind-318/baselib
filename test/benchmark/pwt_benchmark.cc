#include <benchmark/benchmark.h>

#include <string>

#include "pwt.h"

static void BM_pwt_encode(benchmark::State& state) {
    auto pwt_ist = ::wind::utils::pwt::CreatePWTInstance();
    pwt_ist.AddAudience("audience1")
        .AddHeaderCustomField("header1", "value1")
        .AddHeaderCustomField("header2", "value2")
        .AddPayloadCustomField("payload1", "value1")
        .AddPayloadCustomField("payload2", "value2");
    for (auto _ : state) {
        pwt_ist.Encode();
    }
}

static void BM_pwt_decode(benchmark::State& state) {
    auto pwt_ist = ::wind::utils::pwt::CreatePWTInstance();
    auto s = pwt_ist.AddAudience("audience1")
                 .AddHeaderCustomField("header1", "value1")
                 .AddHeaderCustomField("header2", "value2")
                 .AddPayloadCustomField("payload1", "value1")
                 .AddPayloadCustomField("payload2", "value2")
                 .Encode();
    for (auto _ : state) {
        auto new_ist = ::wind::utils::pwt::CreatePWTInstance();
        new_ist.CopyAlgorithm(pwt_ist);
        bool flag = new_ist.Decode(s);
        if (!flag) {
            state.SkipWithError("Decode failed");
        }
    }
}

static void BM_pwt_pool_encode(benchmark::State& state) {
    ::wind::utils::pwt::PWTPool pool;
    std::vector<std::shared_ptr<::wind::utils::pwt::PWTInstance<>>> pwt_ists;
    for (int i = 0; i < 100; ++i) {
        auto tmp = pool.Get();
        tmp->AddAudience("audience1")
            .AddHeaderCustomField("header1", "value1")
            .AddHeaderCustomField("header2", "value2")
            .AddPayloadCustomField("payload1", "value1")
            .AddPayloadCustomField("payload2", "value2");
        pwt_ists.push_back(tmp);
    }
    for (auto& pwt_ist : pwt_ists) {
        pool.Put(pwt_ist);
    }
    pwt_ists.clear();
    for (auto _ : state) {
        auto pwt_ist = pool.Get();
        pwt_ist->Encode();
        pool.Put(pwt_ist);
    }
}

static void BM_pwt_pool_decode(benchmark::State& state) {
    ::wind::utils::pwt::PWTPool pool;
    auto pwt_ist = pool.Get();
    auto s = pwt_ist->AddAudience("audience1")
                 .AddHeaderCustomField("header1", "value1")
                 .AddHeaderCustomField("header2", "value2")
                 .AddPayloadCustomField("payload1", "value1")
                 .AddPayloadCustomField("payload2", "value2")
                 .Encode();
    pool.Put(pwt_ist);

    for (auto _ : state) {
        auto new_ist = pool.Get();
        bool flag = new_ist->Decode(s);
        if (!flag) {
            state.SkipWithError("Decode failed");
        }
        pool.Put(new_ist);
    }
}

BENCHMARK(BM_pwt_pool_encode)->Iterations(10000);
BENCHMARK(BM_pwt_encode)->Iterations(10000);
BENCHMARK(BM_pwt_pool_decode)->Iterations(10000);
BENCHMARK(BM_pwt_decode)->Iterations(10000);