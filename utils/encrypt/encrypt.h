/**
 * @file encrypt.h
 * @author Wind
 * @date 2023-02-21
 *
 * @copyright Copyright (c) 2023 Wind. All rights reserved.
 *
 * Use of this source code is governed by a MIT license
 * that can be found in the LICENSE file.
 *
 */

#pragma once

#include <functional>
#include <memory>
#include <optional>
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
            public:
                // The data to be encrypted or decrypted.
                std::string data_;
                // The key used to encrypt the data.
                std::string key_;
                // Block cipher mode to be used.
                std::string mode_;
                // Initialization vector.
                std::string iv_;
                // A salt can be added to the key to make it more secure.
                std::string salt_;
                // Padding mode to be used.
                std::optional<std::string> padding_;
                // Number of iterations for key derivation
                std::optional<uint32_t> iterations_;
                // Additional authenticated data.
                std::optional<std::string> aad_;
                // Length of the message authentication code (MAC) in bytes.
                std::optional<uint32_t> mac_length_;
                // Length of the authentication tag in bytes.
                std::optional<uint32_t> tag_length_;
                // Flag indicating whether to use authenticated encryption with associated data (AEAD).
                std::optional<bool> use_aead_;
                // Flag indicating whether to compress the plaintext before encryption.
                std::optional<bool> compress_;
                // External key to be used for encryption.
                std::optional<std::string> external_key_;
                // Public key to be used for encryption or verification.
                std::optional<std::string> public_key_;
                // Private key to be used for decryption or signing.
                std::optional<std::string> private_key_;
                // Passphrase for unlocking the private key.
                std::optional<std::string> passphrase_;
                // Format of the public key (e.g., PEM, DER, etc.).
                std::optional<std::string> public_key_format_;
                // Format of the private key (e.g., PEM, DER, etc.).
                std::optional<std::string> private_key_format_;
                /**
                 * @brief Encrypt the data.
                 *
                 * @return std::string The encrypted data.
                 */
                virtual std::string Encrypt() const = 0;
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
                Algorithm(const Algorithm&) noexcept;
                Algorithm(Algorithm&&) = default;
                Algorithm& operator=(const Algorithm&) noexcept;
                Algorithm& operator=(Algorithm&&) = default;
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
                std::string Encrypt() const;

                std::unique_ptr<Algorithm> Clone() const noexcept {
                    return std::make_unique<AlgorithmBase>(*this);
                }

                inline explicit AlgorithmBase() noexcept : Algorithm() {}

                /**
                 * @brief Construct a new Algorithm Base object
                 *
                 * @param data The data to be encrypted.
                 * @param key Key used to encrypt the data.
                 * @param iv Initialization vector.
                 * @param salt A salt can be added to the key to make it more secure.
                 */
                inline explicit AlgorithmBase(const std::string& data, const std::string& key = "", const std::string& iv = "", const std::string& salt = "") noexcept {
                    this->data_ = data;
                    try {
                        this->key_ = key.empty() ? GenerateRandomString() : key;
                    } catch (...) {
                        this->key_ = "";
                    }
                    try {
                        this->iv_ = iv.empty() ? GenerateRandomString(12) : iv;
                    } catch (...) {
                        this->iv_ = "";
                    }
                    try {
                        this->salt_ = salt.empty() ? GenerateRandomString() : salt;
                    } catch (...) {
                        this->salt_ = "";
                    }
                }

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