/**
 * @file encrypt.h
 * @author Wind
 * @link https://github.com/Wind-318/wind @endlink
 * @date 2023-02-21
 *
 * @copyright Copyright (c) 2023 Wind. All rights reserved.
 *
 * Use of this source code is governed by a MIT license
 * that can be found in the LICENSE file.
 *
 */

#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace wind {
    namespace utils {
        namespace encrypt {
            /**
             * @brief Generate a random string of the specified size.
             *
             * @param size The size of the random string to be generated.
             * @return std::string The generated random string.
             *
             * @throw std::runtime_error If the random number generator fails to generate random data.
             * @throw std::invalid_argument If the size is 0.
             */
            std::string GenerateRandomString(const uint8_t& size = 64);
            class Algorithm {
            private:
                inline void CopyConstructor(const Algorithm& other) noexcept {
                    if (this == &other) {
                        return;
                    }
                    std::shared_lock lock(other.mutex_);
                    std::unique_lock lock2(this->mutex_);
                    this->key_ = other.key_;
                    this->iv_ = other.iv_;
                    this->salt_ = other.salt_;
                }

                inline void MoveConstructor(Algorithm&& other) noexcept {
                    if (this == &other) {
                        return;
                    }
                    std::unique_lock lock(this->mutex_);
                    std::unique_lock lock2(other.mutex_);
                    this->key_ = std::move(other.key_);
                    this->iv_ = std::move(other.iv_);
                    this->salt_ = std::move(other.salt_);
                }

            protected:
                // The key used to encrypt the data.
                std::string key_;
                // Initialization vector.
                std::string iv_;
                // A salt can be added to the key to make it more secure.
                std::string salt_;
                // A mutex to ensure thread safety.
                mutable std::shared_mutex mutex_;

            public:
                /**
                 * @brief Encrypt the data.
                 *
                 * @return std::string The encrypted data.
                 */
                virtual std::string Encrypt(const std::string& data) const = 0;
                /**
                 * @brief Clone the current object.
                 *
                 * @return std::unique_ptr<Algorithm> The cloned object.
                 */
                virtual std::unique_ptr<Algorithm> Clone() const noexcept = 0;
                virtual ~Algorithm() = default;

                Algorithm() noexcept {
                    try {
                        this->key_ = GenerateRandomString();
                    } catch (...) {
                        this->key_ = "";
                    }
                    try {
                        this->iv_ = GenerateRandomString(12);
                    } catch (...) {
                        this->iv_ = "";
                    }
                    try {
                        this->salt_ = GenerateRandomString();
                    } catch (...) {
                        this->salt_ = "";
                    }
                }

                Algorithm(const Algorithm& other) noexcept {
                    CopyConstructor(other);
                }

                Algorithm(Algorithm&& other) noexcept {
                    MoveConstructor(std::forward<Algorithm>(other));
                }

                Algorithm& operator=(const Algorithm& other) noexcept {
                    CopyConstructor(other);
                    return *this;
                }

                Algorithm& operator=(Algorithm&& other) noexcept {
                    MoveConstructor(std::forward<Algorithm>(other));
                    return *this;
                }

                inline void SetKey(const std::string& key) noexcept {
                    std::unique_lock lock(this->mutex_);
                    this->key_ = key;
                }

                inline void SetIV(const std::string& iv) noexcept {
                    std::unique_lock lock(this->mutex_);
                    this->iv_ = iv;
                }

                inline void SetSalt(const std::string& salt) noexcept {
                    std::unique_lock lock(this->mutex_);
                    this->salt_ = salt;
                }

                inline std::string GetKey() const noexcept {
                    std::shared_lock lock(this->mutex_);
                    return this->key_;
                }

                inline std::string GetIV() const noexcept {
                    std::shared_lock lock(this->mutex_);
                    return this->iv_;
                }

                inline std::string GetSalt() const noexcept {
                    std::shared_lock lock(this->mutex_);
                    return this->salt_;
                }
            };

            /**
             * @brief Base class inherited by all encryption algorithms.
             */
            class AlgorithmBase : public Algorithm {
            public:
                /**
                 * @brief Encrypt the data.
                 *
                 * @return std::string The encrypted data.
                 */
                std::string Encrypt(const std::string& data) const;

                std::unique_ptr<Algorithm> Clone() const noexcept {
                    std::shared_lock lock(this->mutex_);
                    return std::make_unique<AlgorithmBase>(*this);
                }

                inline explicit AlgorithmBase() noexcept = default;

                /**
                 * @brief Construct a new Algorithm Base object
                 *
                 * @param e The AlgorithmBase object to be copied.
                 */
                AlgorithmBase(const AlgorithmBase& alg) noexcept = default;
                AlgorithmBase(AlgorithmBase&&) noexcept = default;

                /**
                 * @brief Copy assignment operator
                 *
                 * @param alg The AlgorithmBase object to be copied.
                 * @return AlgorithmBase& The reference to the current object.
                 */
                AlgorithmBase& operator=(const AlgorithmBase& alg) noexcept = default;
                AlgorithmBase& operator=(AlgorithmBase&&) noexcept = default;
                ~AlgorithmBase() = default;
            };

            /**
             * @TODO: More Algorithms
             */
        }
    }
}