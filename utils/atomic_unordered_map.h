/**
 * @file atomic_unordered_map.h
 * @author Wind
 * @brief A thread-safe unordered_map with atomic operations.
 * @link https://github.com/Wind-318/wind @endlink
 * @date 2023-02-25
 *
 * @copyright Copyright (c) 2023 Wind. All rights reserved.
 *
 * Use of this source code is governed by a MIT license
 * that can be found in the LICENSE file.
 */

#pragma once

#include <algorithm>
#include <atomic>
#include <execution>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace wind {
    /**
     * @brief A thread-safe unordered_map.
     *
     * @tparam Key The key type.
     * @tparam T The value type.
     * @tparam Hash The hash function.
     * @tparam KeyEqual The key equal function.
     * @tparam std::allocator<std::pair<const Key, T>> The allocator.
     */
    template <typename Key, typename T, typename Hash = std::hash<Key>,
              typename KeyEqual = std::equal_to<Key>,
              typename Allocator = std::allocator<std::pair<const Key, T>>>
    class atomic_unordered_map {
    private:
        std::unordered_map<Key, T, Hash, KeyEqual, Allocator> map_;
        // shared_mutex
        mutable std::shared_mutex mutex_;

        inline void CopyConstruct(const atomic_unordered_map& other) {
            if (this == &other) {
                return;
            }
            std::unique_lock lock(mutex_);
            std::shared_lock other_lock(other.mutex_);
            map_ = other.map_;
        }

        inline void MoveConstruct(atomic_unordered_map&& other) {
            if (this == &other) {
                return;
            }
            std::unique_lock lock(mutex_);
            std::unique_lock other_lock(other.mutex_);
            map_ = std::move(other.map_);
        }

    public:
        atomic_unordered_map() = default;

        inline atomic_unordered_map(const atomic_unordered_map& other) {
            CopyConstruct(other);
        }

        inline atomic_unordered_map(atomic_unordered_map&& other) {
            MoveConstruct(std::forward<atomic_unordered_map>(other));
        }

        inline atomic_unordered_map& operator=(const atomic_unordered_map& other) {
            CopyConstruct(other);
            return *this;
        }

        inline atomic_unordered_map& operator=(atomic_unordered_map&& other) {
            MoveConstruct(std::forward<atomic_unordered_map>(other));
            return *this;
        }

        ~atomic_unordered_map() = default;

        /**
         * @brief Get a copy of the map.
         *
         * @return std::unordered_map<Key, T, Hash, KeyEqual, Allocator> The copy of the map.
         */
        inline std::unordered_map<Key, T, Hash, KeyEqual, Allocator> get_map() const noexcept {
            std::shared_lock lock(mutex_);
            return map_;
        }

        inline size_t size() const noexcept {
            std::shared_lock lock(mutex_);
            return map_.size();
        }

        inline bool empty() const noexcept {
            std::shared_lock lock(mutex_);
            return map_.empty();
        }

        inline void clear() noexcept {
            std::unique_lock lock(mutex_);
            map_.clear();
        }

        // Insert a key-value pair, will not overwrite the value if the key exists.
        inline bool insert(const Key& key, const T& value) noexcept {
            std::unique_lock lock(mutex_);
            return map_.insert(std::make_pair(key, value)).second;
        }

        inline bool insert(const Key& key, T&& value) noexcept {
            std::unique_lock lock(mutex_);
            return map_.insert(std::make_pair(key, std::forward<T>(value))).second;
        }

        inline bool insert(Key&& key, const T& value) noexcept {
            std::unique_lock lock(mutex_);
            return map_.insert(std::make_pair(std::forward<Key>(key), value)).second;
        }

        inline bool insert(Key&& key, T&& value) noexcept {
            std::unique_lock lock(mutex_);
            return map_.insert(std::make_pair(std::forward<Key>(key), std::forward<T>(value))).second;
        }

        // Insert a key-value pair, will overwrite the value if the key exists.
        inline void store(const Key& key, const T& value) noexcept {
            std::unique_lock lock(mutex_);
            map_[key] = value;
        }

        inline void store(const Key& key, T&& value) noexcept {
            std::unique_lock lock(mutex_);
            map_[key] = std::forward<T>(value);
        }

        inline void store(Key&& key, const T& value) noexcept {
            std::unique_lock lock(mutex_);
            map_[std::forward<Key>(key)] = value;
        }

        inline void store(Key&& key, T&& value) noexcept {
            std::unique_lock lock(mutex_);
            map_[std::forward<Key>(key)] = std::forward<T>(value);
        }

        inline T operator[](const Key& key) noexcept {
            std::shared_lock lock(mutex_);
            return map_[key];
        }

        inline void erase(const Key& key) {
            std::unique_lock lock(mutex_);
            try {
                map_.erase(key);
            } catch (const std::exception& e) {
                throw;
            }
        }

        /**
         * @brief Get a reference to the value.
         *
         * @param key The key.
         * @return const T& The reference to the value.
         *
         * @throw std::out_of_range If the key is not found.
         */
        inline const T& at(const Key& key) const {
            std::shared_lock lock(mutex_);
            try {
                return map_.at(key);
            } catch (const std::exception& e) {
                throw;
            }
        }

        inline size_t count(const Key& key) const noexcept {
            std::shared_lock lock(mutex_);
            return map_.count(key);
        }

        inline bool contains(const Key& key) const noexcept {
            std::shared_lock lock(mutex_);
            return map_.find(key) != map_.end();
        }

        inline void swap(atomic_unordered_map& other) noexcept {
            if (this == &other) {
                return;
            }
            std::unique_lock lock(mutex_, std::defer_lock);
            std::unique_lock other_lock(other.mutex_, std::defer_lock);
            std::lock(lock, other_lock);
            map_.swap(other.map_);
        }

        inline void merge(atomic_unordered_map& other) noexcept {
            if (this == &other) {
                return;
            }
            std::unique_lock lock(mutex_, std::defer_lock);
            std::unique_lock other_lock(other.mutex_, std::defer_lock);
            std::lock(lock, other_lock);
            map_.merge(other.map_);
        }

        inline void reserve(size_t n) noexcept {
            std::unique_lock lock(mutex_);
            map_.reserve(n);
        }

        inline void copy_from(const atomic_unordered_map& other) noexcept {
            CopyConstruct(other);
        }

        inline void copy_from(const std::unordered_map<Key, T, Hash, KeyEqual, Allocator>& other) noexcept {
            std::unique_lock lock(mutex_);
            map_ = other;
        }

        inline bool operator==(const atomic_unordered_map& rhs) const noexcept {
            if (this == &rhs) {
                return true;
            }
            std::shared_lock lock(mutex_);
            return map_ == rhs.map_;
        }

        inline bool operator!=(const atomic_unordered_map& rhs) const noexcept {
            if (this == &rhs) {
                return false;
            }
            std::shared_lock lock(mutex_);
            return map_ != rhs.map_;
        }

        inline std::vector<Key> keys() const noexcept {
            std::shared_lock lock(mutex_);
            std::vector<Key> keys;

            for (const auto& [key, _] : map_) {
                keys.emplace_back(key);
            }

            return keys;
        }

        inline std::vector<T> values() const noexcept {
            std::shared_lock lock(mutex_);
            std::vector<T> values;

            for (const auto& [_, value] : map_) {
                values.emplace_back(value);
            }

            return values;
        }

        /**
         * @brief Get the first element of the map and remove it.
         *
         * @return std::pair<Key, T> The first element of the map.
         */
        inline std::pair<Key, T> pair_begin() {
            std::unique_lock lock(mutex_);
            if (map_.empty()) {
                return std::make_pair(Key(), T());
            }
            auto [key, value] = *map_.begin();
            map_.erase(key);
            return std::make_pair(key, value);
        }

        /**
         * @brief Iterate over the map.
         *
         * @param f The function to call for each element.
         *
         * @note Make sure the function is thread-safe.
         * @code
         * atomic_unordered_map<int, std::string> map;
         * map.insert(1, "hello");
         * map.insert(2, "world");
         * map.range([](int key, const std::string& value) {
         *    printf("%d: %s\n", key, value.c_str());
         * });
         * @endcode
         */
        inline void range(const std::function<void(Key, T)>& f) noexcept {
            std::unique_lock lock(mutex_);
            std::for_each(std::execution::par, map_.begin(), map_.end(), [&](auto& kv) {
                f(kv.first, kv.second);
            });
        }

        inline void range_s(const std::function<void(Key, T)>& f) noexcept {
            std::unique_lock lock(mutex_);
            std::for_each(map_.begin(), map_.end(), [&](auto& kv) {
                f(kv.first, kv.second);
            });
        }
    };
}  // namespace wind