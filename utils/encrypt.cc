/**
 * @file encrypt.cc
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

#include "encrypt.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace wind {
    namespace utils {
        namespace encrypt {
            std::string GenerateRandomString(const uint8_t& size) {
                std::string key;
                if (size < 1) {
                    throw std::invalid_argument("Key size must be greater than 0");
                }
                key.resize(size);
                if (RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), size) != 1) {
                    throw std::runtime_error("Could not generate random key");
                }
                return key;
            }

            /**
             * @brief Encrypt the data.
             *
             * @return std::string The encrypted data.
             */
            std::string AlgorithmBase::Encrypt() const {
                if (key_.empty()) {
                    throw std::invalid_argument("Key is empty");
                } else if (data_.empty()) {
                    throw std::invalid_argument("Data is empty");
                }

                // Create a new cipher context for AES-256-CBC encryption
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key_.data(), NULL);

                // Allocate a buffer for the encrypted output
                size_t outlen = data_.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
                std::unique_ptr<unsigned char[]> outbuf(new unsigned char[outlen]);

                // Encrypt the input data
                int outlen_actual = 0;
                EVP_EncryptUpdate(ctx, outbuf.get(), &outlen_actual, (const unsigned char*)data_.data(), data_.size());
                int outlen_final = 0;
                EVP_EncryptFinal_ex(ctx, outbuf.get() + outlen_actual, &outlen_final);

                // Concatenate the encrypted output into a string
                std::string result((const char*)outbuf.get(), outlen_actual + outlen_final);

                // Clean up the cipher context
                EVP_CIPHER_CTX_free(ctx);

                return result;
            }

            Algorithm::Algorithm(const Algorithm& alg) noexcept {
                if (this != &alg) {
                    this->data_ = alg.data_;
                    try {
                        this->key_ = alg.key_.empty() ? GenerateRandomString() : alg.key_;
                    } catch (...) {
                        this->key_ = "";
                    }
                    try {
                        this->iv_ = alg.iv_.empty() ? GenerateRandomString(12) : alg.iv_;
                    } catch (...) {
                        this->iv_ = "";
                    }
                    try {
                        this->salt_ = alg.salt_.empty() ? GenerateRandomString() : alg.salt_;
                    } catch (...) {
                        this->salt_ = "";
                    }
                    this->mode_ = alg.mode_;
                    this->padding_ = alg.padding_;
                    this->iterations_ = alg.iterations_;
                    this->aad_ = alg.aad_;
                    this->mac_length_ = alg.mac_length_;
                    this->tag_length_ = alg.tag_length_;
                    this->use_aead_ = alg.use_aead_;
                    this->compress_ = alg.compress_;
                    this->external_key_ = alg.external_key_;
                    this->public_key_ = alg.public_key_;
                    this->private_key_ = alg.private_key_;
                }
            }
        }  // namespace encrypt
    }      // namespace utils
}  // namespace wind
