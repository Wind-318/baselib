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
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
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
            std::string AlgorithmBase::Encrypt(const std::string& data) const {
                std::shared_lock lock(this->mutex_);
                if (key_.empty()) {
                    throw std::invalid_argument("Key is empty");
                } else if (data.empty()) {
                    throw std::invalid_argument("Data is empty");
                }

                // Create a new cipher context for AES-256-CBC encryption
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key_.data(), NULL);

                // Allocate a buffer for the encrypted output
                size_t outlen = data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
                std::unique_ptr<unsigned char[]> outbuf(new unsigned char[outlen]);

                // Encrypt the input data
                int outlen_actual = 0;
                EVP_EncryptUpdate(ctx, outbuf.get(), &outlen_actual, (const unsigned char*)data.data(), data.size());
                int outlen_final = 0;
                EVP_EncryptFinal_ex(ctx, outbuf.get() + outlen_actual, &outlen_final);

                // Concatenate the encrypted output into a string
                std::string result((const char*)outbuf.get(), outlen_actual + outlen_final);

                // Clean up the cipher context
                EVP_CIPHER_CTX_free(ctx);

                return result;
            }
        }  // namespace encrypt
    }      // namespace utils
}  // namespace wind
