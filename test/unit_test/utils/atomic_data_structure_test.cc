#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include "atomic_unordered_map.h"

TEST(AtomicUnorderedMapTest, TestUnorderedMap) {
    ::wind::atomic_unordered_map<std::string, std::string> rec;
    rec.size();
    rec.empty();
    rec.clear();
    auto key = "key";
    auto value = "value";
    rec.insert(key, value);
    rec.insert(key, "value2");
    rec.insert("key2", value);
    rec.insert("key2", "value2");
    rec.erase(key);
    rec.at("key2");
    EXPECT_THROW(rec.at(key), std::out_of_range);
    rec["key2"];
    rec[key];
    rec.count("key2");
    rec.contains("key2");
    ::wind::atomic_unordered_map<std::string, std::string> rec2;
    rec.swap(rec2);
    rec.merge(rec2);
    rec.reserve(10);
    rec == rec2;
    rec != rec2;
}

TEST(AtomicUnorderedMapTest, TestUnorderedMapConcurrency) {
    ::wind::atomic_unordered_map<std::string, std::string> rec;

    std::vector<std::thread> threads;
    for (int i = 0; i < 1000; ++i) {
        threads.emplace_back([&rec, i]() {
            rec.insert(std::to_string(i), std::to_string(i));
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto maps = rec.get_map();
}