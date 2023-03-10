#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include "atomic_unordered_map.h"

// Copy and move constructor and assignment operator
TEST(AtomicMapTest, CopyAndMove) {
    ::wind::atomic_unordered_map<std::string, std::string> map;
    map.insert("a", "b");
    map.insert("c", "d");
    auto map2(map);
    ASSERT_EQ(map2, map);
    auto map3(std::move(map));
    ASSERT_EQ(map3, map2);
    map2 = map2;
    map2 = std::move(map2);
    map2 = map3;
    ASSERT_EQ(map2, map3);
    auto map4 = map3;
    map2 = std::move(map3);
    ASSERT_EQ(map2, map4);
}

// Basic methods test
TEST(AtomicMapTest, BasicMethods) {
    ::wind::atomic_unordered_map<std::string, std::string> map;
    map.get_map();
    ASSERT_EQ(map.size(), 0);
    ASSERT_EQ(map.empty(), true);
    map.clear();
    std::string key = "key", value = "value";
    map.insert(key, value);
    map.insert(key, "value2");
    map.insert("key2", value);
    map.insert("key2", "value2");
    ASSERT_NO_THROW(map.erase(key));
    ASSERT_NO_THROW(map.erase(key));
    ASSERT_NO_THROW(map.at("key2"));
    ASSERT_THROW(map.at(key), std::exception);
    ASSERT_EQ(map["key2"], "value");
    ASSERT_NE(map[key], "value");
    ASSERT_EQ(map.count(key), 1);
    ASSERT_EQ(map.contains(key), true);
    auto map2 = map;
    ASSERT_NO_THROW(map.swap(map));
    ASSERT_NO_THROW(map.swap(map2));
    ASSERT_NO_THROW(map.reserve(100));
    ASSERT_NO_THROW(map.copy_from(map));
    ASSERT_NO_THROW(map.copy_from(map2));
    ASSERT_NO_THROW(map.copy_from(map2.get_map()));
    ASSERT_EQ(map == map, true);
    ASSERT_EQ(map == map2, true);
    ASSERT_EQ(map != map, false);
    ASSERT_EQ(map != map2, false);
    ASSERT_EQ(map.keys(), map2.keys());
    ASSERT_EQ(map.values(), map2.values());
    ASSERT_EQ(map.pair_begin(), map2.pair_begin());
    ASSERT_EQ(map.pair_begin(), map2.pair_begin());
    ASSERT_EQ(map.pair_begin(), map2.pair_begin());

    map.insert("key2", "value2");

    map.range([](const std::string& key, const std::string& value) {
        EXPECT_EQ(key, "key2");
        EXPECT_EQ(value, "value2");
        return true;
    });

    map.store(key, value);
    map.store(key, "value2");
    map.store("key2", value);
    map.store("key2", "value2");
}

TEST(AtomicMapTest, MultiThreaded) {
    ::wind::atomic_unordered_map<std::string, std::string> map;
    std::vector<std::thread> threads;
    for (int i = 0; i < 100; ++i) {
        threads.emplace_back([&map, i]() {
            map.insert(std::to_string(i), std::to_string(i));
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    ASSERT_EQ(map.size(), 100);
    for (int i = 0; i < 100; ++i) {
        ASSERT_EQ(map.count(std::to_string(i)), 1);
    }
    for (int i = 0; i < 100; ++i) {
        ASSERT_EQ(map.contains(std::to_string(i)), true);
    }

    map.range([](const std::string& key, const std::string& value) {
        ASSERT_EQ(key, value);
    });

    map.range_s([](const std::string& key, const std::string& value) {
        ASSERT_EQ(key, value);
    });

    threads.clear();
    for (int i = 0; i < 100; ++i) {
        threads.emplace_back([&map, i]() {
            map.erase(std::to_string(i));
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    ASSERT_EQ(map.size(), 0);
    for (int i = 0; i < 100; ++i) {
        ASSERT_EQ(map.count(std::to_string(i)), 0);
    }
    for (int i = 0; i < 100; ++i) {
        ASSERT_EQ(map.contains(std::to_string(i)), false);
    }
    for (int i = 0; i < 100; ++i) {
        ASSERT_THROW(map.at(std::to_string(i)), std::exception);
    }
}