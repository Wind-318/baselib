/**
 * @file encrypt.cc
 * @author Wind
 * @date 2023-02-21
 *
 * @copyright Copyright (c) 2023 Wind. All rights reserved.
 *
 * Use of this source code is governed by a MIT license
 * that can be found in the LICENSE file.
 *
 */

#include "pwt.h"

#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/json_util.h>
#include <openssl/rand.h>

#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "encrypt.h"
#include "pwt.pb.h"

namespace wind {
    namespace utils {
        namespace pwt {
            /**
             * @brief Encode the header to a string.
             *
             * @return std::string The encoded header.
             *
             * @note How to use:
             * @code
             * PWTHeaderBase header;
             * header.SetTyp("JWT");
             * header.Encode();
             * @endcode
             */
            std::string PWTHeaderBase::Encode() const {
                HeaderMessage header;
                header.set_typ(typ_);
                header.set_kid(kid_);
                header.set_pwk(pwk_);
                header.set_x5u(x5u_);
                // Add custom fields
                for (const auto& [key, value] : custom_fields_) {
                    auto field = header.add_custom();
                    field->set_key(key);
                    field->set_value(value);
                }
                // Serialize the header
                InstanceMessage ist_msg;
                if (!header.SerializeToString(ist_msg.mutable_head())) {
                    throw std::runtime_error("Failed to serialize header");
                }
                // Serialize the custom header
                if (custom_headers_.has_value()) {
                    if (!custom_headers_->SerializeToString(ist_msg.mutable_custom())) {
                        throw std::runtime_error("Failed to serialize custom header");
                    }
                }
                // Serialize the instance message
                std::string result;
                if (!ist_msg.SerializeToString(&result)) {
                    throw std::runtime_error("Failed to serialize PWT message");
                }
                return result;
            }

            /**
             * @brief Decode the header from a string.
             *
             * @param msg The encoded header, which is a binary protobuf message.
             * @return true If the header is decoded successfully.
             * @return false If the header is decoded unsuccessfully.
             */
            bool PWTHeaderBase::Decode(const std::string& msg) noexcept {
                if (msg.empty()) {
                    return false;
                }
                InstanceMessage ist_msg;
                if (!ist_msg.ParseFromString(msg)) {
                    return false;
                }
                ::wind::utils::pwt::HeaderMessage header;
                if (!header.ParseFromString(ist_msg.head())) {
                    return false;
                }
                this->typ_ = header.typ();
                this->kid_ = header.kid();
                this->pwk_ = header.pwk();
                this->x5u_ = header.x5u();
                if (ist_msg.custom().empty()) {
                    this->custom_headers_ = std::nullopt;
                } else {
                    if (!this->custom_headers_.has_value()) {
                        this->custom_headers_ = ::google::protobuf::Any();
                    }
                    if (!this->custom_headers_->ParseFromString(ist_msg.custom())) {
                        return false;
                    }
                }
                for (const auto& field : header.custom()) {
                    this->custom_fields_[field.key()] = field.value();
                }
                return true;
            }

            /**
             * @brief Generate a random PBI.
             *
             * @param size The size of the PBI.
             * @return std::string The generated PBI.
             */
            std::string PWTPayload::GeneratePbi(const uint8_t& size) {
                if (size == 0) {
                    throw std::invalid_argument("Size cannot be zero");
                }
                std::vector<unsigned char> random_data(size);
                std::stringstream pbi;
                if (!RAND_bytes(random_data.data(), random_data.size())) {
                    throw std::runtime_error("Error generating random data");
                }

                for (int i = 0; i < random_data.size(); i++) {
                    pbi << std::hex << static_cast<int>(random_data[i]);
                }
                return pbi.str();
            }

            /**
             * @brief Encode the payload to a string.
             *
             * @return std::string The encoded payload, which is a binary protobuf message.
             */
            std::string PWTPayloadBase::Encode() const {
                PayloadMessage payload_msg;
                payload_msg.set_iss(iss_);
                payload_msg.set_sub(sub_);
                // Add aud
                if (std::holds_alternative<std::string>(aud_)) {
                    payload_msg.set_aud(std::get<std::string>(aud_));
                } else {
                    for (const auto& aud : std::get<std::vector<std::string>>(aud_)) {
                        payload_msg.add_aud_vec(aud);
                    }
                }
                // Add custom fields
                for (const auto& [key, value] : custom_fields_) {
                    auto field = payload_msg.add_custom();
                    field->set_key(key);
                    field->set_value(value);
                }
                // Set exp, nbf, iat and pbi
                if (exp_.has_value()) {
                    auto exp_msg = ::google::protobuf::Timestamp();
                    exp_msg.CopyFrom(exp_.value());
                    payload_msg.set_allocated_exp(&exp_msg);
                }
                if (nbf_.has_value()) {
                    auto nbf_msg = ::google::protobuf::Timestamp();
                    nbf_msg.CopyFrom(nbf_.value());
                    payload_msg.set_allocated_nbf(&nbf_msg);
                }
                if (iat_.has_value()) {
                    auto iat_msg = ::google::protobuf::Timestamp();
                    iat_msg.CopyFrom(iat_.value());
                    payload_msg.set_allocated_iat(&iat_msg);
                }
                payload_msg.set_pbi(pbi_);
                // Serialize the payload
                InstanceMessage ist_msg;
                try {
                    ist_msg.set_head(payload_msg.SerializeAsString());
                    if (custom_payloads_.has_value()) {
                        ist_msg.set_custom(custom_payloads_->SerializeAsString());
                    }
                    auto result = ist_msg.SerializeAsString();
                    auto _ = payload_msg.release_exp();
                    _ = payload_msg.release_nbf();
                    _ = payload_msg.release_iat();
                    return result;
                } catch (const std::exception& e) {
                    throw;
                }
            }

            /**
             * @brief Decode the payload from a string.
             *
             * @param msg The encoded payload, which is a binary protobuf message.
             * @return true If the payload is decoded successfully.
             * @return false If the payload is decoded unsuccessfully.
             */
            bool PWTPayloadBase::Decode(const std::string& msg) noexcept {
                // If the message is empty, return false
                if (msg.empty()) {
                    return false;
                }
                // Parse to instance message
                InstanceMessage ist_msg;
                if (!ist_msg.ParseFromString(msg)) {
                    return false;
                }
                // Parse to payload message
                PayloadMessage payload_msg;
                if (!payload_msg.ParseFromString(ist_msg.head())) {
                    return false;
                }
                this->iss_ = payload_msg.iss();
                this->sub_ = payload_msg.sub();
                // Add aud
                if (payload_msg.aud_vec_size() > 0) {
                    std::vector<std::string> aud_vec;
                    for (const auto& aud : payload_msg.aud_vec()) {
                        aud_vec.emplace_back(aud);
                    }
                    this->aud_ = std::variant<std::string, std::vector<std::string>>(aud_vec);
                } else {
                    this->aud_ = std::variant<std::string, std::vector<std::string>>(payload_msg.aud());
                }
                // Add custom fields
                for (const auto& field : payload_msg.custom()) {
                    this->custom_fields_[field.key()] = field.value();
                }
                // Set exp, nbf, iat and pbi
                this->exp_ = std::optional<::google::protobuf::Timestamp>(payload_msg.exp());
                this->nbf_ = std::optional<::google::protobuf::Timestamp>(payload_msg.nbf());
                this->iat_ = std::optional<::google::protobuf::Timestamp>(payload_msg.iat());
                this->pbi_ = payload_msg.pbi();
                // Parse custom payload
                if (ist_msg.custom().empty()) {
                    this->custom_payloads_ = std::nullopt;
                } else {
                    if (!this->custom_payloads_.has_value()) {
                        this->custom_payloads_ = ::google::protobuf::Any();
                    }
                    if (!this->custom_payloads_->ParseFromString(ist_msg.custom())) {
                        return false;
                    }
                }
                return true;
            }
        }  // namespace pwt
    }      // namespace utils
}  // namespace wind