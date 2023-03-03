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

#include <atomic>
#include <shared_mutex>
#include <thread>
#include <unordered_map>

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

    public:
        atomic_unordered_map() = default;
        atomic_unordered_map(const atomic_unordered_map&) = delete;
        atomic_unordered_map(atomic_unordered_map&&) = delete;
        atomic_unordered_map& operator=(const atomic_unordered_map&) = delete;
        atomic_unordered_map& operator=(atomic_unordered_map&&) = delete;

        ~atomic_unordered_map() = default;

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

        inline void insert(const Key& key, const T& value) noexcept {
            std::unique_lock lock(mutex_);
            map_.insert(std::make_pair(key, value));
        }

        inline void insert(const Key& key, T&& value) noexcept {
            std::unique_lock lock(mutex_);
            map_.insert(std::make_pair(key, std::move(value)));
        }

        inline void insert(Key&& key, const T& value) noexcept {
            std::unique_lock lock(mutex_);
            map_.insert(std::make_pair(std::move(key), value));
        }

        inline void insert(Key&& key, T&& value) noexcept {
            std::unique_lock lock(mutex_);
            map_.insert(std::make_pair(std::move(key), std::move(value)));
        }

        inline void erase(const Key& key) {
            std::unique_lock lock(mutex_);
            try {
                map_.erase(key);
            } catch (const std::out_of_range& e) {
                throw;
            }
        }

        inline const T& at(const Key& key) const {
            std::shared_lock lock(mutex_);
            try {
                return map_.at(key);
            } catch (const std::out_of_range& e) {
                throw;
            }
        }

        inline T& operator[](const Key& key) noexcept {
            std::unique_lock lock(mutex_);
            return map_[key];
        }

        inline T& operator[](Key&& key) noexcept {
            std::unique_lock lock(mutex_);
            return map_[std::move(key)];
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

        inline bool operator==(const atomic_unordered_map& rhs) const noexcept {
            std::shared_lock lock(mutex_);
            return map_ == rhs.map_;
        }

        inline bool operator!=(const atomic_unordered_map& rhs) const noexcept {
            std::shared_lock lock(mutex_);
            return map_ != rhs.map_;
        }
    };
}  // namespace wind