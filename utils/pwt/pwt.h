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

#pragma once

#include <google/protobuf/any.pb.h>
#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>
#include <pwt.pb.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

#include "encrypt.h"
#include "time_opt.h"

namespace wind {
    namespace utils {
        namespace pwt {
            /**
             * @brief Base class for PWTHeader
             */
            class PWTHeader {
            public:
                // The type of the token
                std::string typ_;
                // The key id
                std::string kid_;
                // Protobuf web token
                std::string pwk_;
                // The X.509 URL
                std::string x5u_;
                // Custom fields
                std::unordered_map<std::string, std::string> custom_fields_;
                // Custom headers
                std::optional<::google::protobuf::Any> custom_headers_;

                virtual ~PWTHeader() = default;

                /**
                 * @brief Seralize the header to a string
                 *
                 * @return std::string
                 */
                virtual std::string Encode() const = 0;

                /**
                 * @brief Decode a binary protobuf message to a PWTHeader
                 *
                 * @param msg The binary protobuf message
                 * @return true If the message is successfully decoded
                 * @return false If the message is not successfully decoded
                 */
                virtual bool Decode(const std::string& msg) noexcept = 0;

                inline explicit PWTHeader(const std::string& typ, const std::string& kid,
                                          const std::string& pwk, const std::string& x5u,
                                          const std::unordered_map<std::string, std::string>& custom_fields = {},
                                          const std::optional<::google::protobuf::Any>& custom_headers = std::nullopt) noexcept {
                    this->typ_ = typ;
                    this->kid_ = kid;
                    this->pwk_ = pwk;
                    this->x5u_ = x5u;
                    this->custom_fields_ = custom_fields;
                    custom_headers_ = custom_headers;
                }

                inline explicit PWTHeader() noexcept {
                    this->typ_ = "PWT";
                    this->custom_headers_ = std::nullopt;
                }

                inline PWTHeader(const PWTHeader& header) noexcept {
                    if (this == &header) {
                        return;
                    }
                    this->typ_ = header.typ_;
                    this->kid_ = header.kid_;
                    this->pwk_ = header.pwk_;
                    this->x5u_ = header.x5u_;
                    this->custom_fields_ = header.custom_fields_;
                    // Copy the custom headers
                    if (header.custom_headers_.has_value()) {
                        custom_headers_->CopyFrom(*header.custom_headers_);
                    } else {
                        custom_headers_ = std::nullopt;
                    }
                }

                inline PWTHeader& operator=(const PWTHeader& header) noexcept {
                    if (this == &header) {
                        return *this;
                    }
                    typ_ = header.typ_;
                    kid_ = header.kid_;
                    pwk_ = header.pwk_;
                    x5u_ = header.x5u_;
                    custom_fields_ = header.custom_fields_;
                    // Copy the custom headers
                    if (header.custom_headers_.has_value()) {
                        custom_headers_->CopyFrom(*header.custom_headers_);
                    } else {
                        custom_headers_ = std::nullopt;
                    }
                    return *this;
                }
            };

            /**
             * @brief The base class for PWTHeader, which is need to be inherited.
             */
            class PWTHeaderBase : public PWTHeader {
            public:
                inline explicit PWTHeaderBase(const std::string& typ, const std::string& kid,
                                              const std::string& pwk, const std::string& x5u,
                                              const std::unordered_map<std::string, std::string>& custom_fields = {},
                                              const std::optional<::google::protobuf::Any>& custom_headers = std::nullopt) noexcept
                    : PWTHeader(typ, kid, pwk, x5u, custom_fields, custom_headers) {}

                inline explicit PWTHeaderBase() noexcept : PWTHeader() {}

                PWTHeaderBase(const PWTHeaderBase& header) noexcept = default;

                PWTHeaderBase(PWTHeaderBase&&) noexcept = default;

                inline PWTHeaderBase& operator=(const PWTHeaderBase& header) noexcept = default;

                PWTHeaderBase& operator=(PWTHeaderBase&&) noexcept = default;
                /**
                 * @brief Encode the header to a string
                 *
                 * @return std::string The encoded header, which is a binary protobuf message
                 * @throw std::runtime_error If the header is not successfully encoded
                 */
                std::string Encode() const;
                /**
                 * @brief Decode the header from a string.
                 *
                 * @param msg The encoded header, which is a binary protobuf message.
                 * @return true If the header is decoded successfully.
                 * @return false If the header is decoded unsuccessfully.
                 */
                bool Decode(const std::string& msg) noexcept;

                ~PWTHeaderBase() = default;
            };

            /**
             * @brief Base class for PWTPayload
             */
            class PWTPayload {
            public:
                // The issuer of the token
                std::string iss_;
                // The subject of the token
                std::string sub_;
                // The Protobuf ID
                std::string pbi_;
                // The audience of the token (can be a string or a vector of strings)
                std::variant<std::string, std::vector<std::string>> aud_;
                // The expiration time of the token
                std::optional<::google::protobuf::Timestamp> exp_;
                // The not before time of the token
                std::optional<::google::protobuf::Timestamp> nbf_;
                // The issued at time of the token
                std::optional<::google::protobuf::Timestamp> iat_;
                // The custom fields of the token
                std::unordered_map<std::string, std::string> custom_fields_;
                // The custom payloads of the token
                std::optional<::google::protobuf::Any> custom_payloads_;
                virtual ~PWTPayload() = default;
                /**
                 * @brief Seralize the payload to a string
                 *
                 * @return std::string
                 */
                virtual std::string Encode() const = 0;
                /**
                 * @brief Decode a binary protobuf message to a PWTPayload
                 *
                 * @param msg The binary protobuf message
                 * @return true If the message is successfully decoded
                 * @return false If the message is not successfully decoded
                 */
                virtual bool Decode(const std::string& msg) noexcept = 0;
                /**
                 * @brief Check if the token is expired
                 *
                 * @return true The token is expired
                 * @return false The token is not expired
                 */
                virtual bool IsExpired() const noexcept = 0;

                /**
                 * @brief Generate a random PBI.
                 *
                 * @param size The size of the PBI.
                 * @return std::string The generated PBI.
                 *
                 * @throw std::invalid_argument If the size is zero.
                 * @throw std::runtime_error If the PBI is not successfully generated.
                 */
                static std::string GeneratePbi(const uint8_t& size = 16);

                inline explicit PWTPayload(const std::string& iss, const std::string& sub, const std::string& aud,
                                           const std::optional<::google::protobuf::Any>& custom_payloads = std::nullopt,
                                           const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0) {
                    this->iss_ = iss;
                    this->sub_ = sub;
                    this->aud_ = std::variant<std::string, std::vector<std::string>>(aud);
                    this->nbf_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(nbf));
                    this->iat_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(iat));
                    this->exp_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(exp));
                    custom_payloads_ = std::optional<::google::protobuf::Any>(custom_payloads);
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        throw;
                    }

                    if (exp < iat) {
                        throw std::invalid_argument("Expiration time must be greater than the issued at time");
                    } else if (nbf > exp) {
                        throw std::invalid_argument("Expiration time must be greater than the issued at time");
                    }
                }

                inline explicit PWTPayload(const std::string& iss, const std::string& sub, const std::vector<std::string>& aud,
                                           const std::optional<::google::protobuf::Any>& custom_payloads = std::nullopt,
                                           const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0) {
                    this->iss_ = iss;
                    this->sub_ = sub;
                    this->aud_ = std::variant<std::string, std::vector<std::string>>(aud);
                    this->nbf_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(nbf));
                    this->iat_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(iat));
                    this->exp_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(exp));
                    custom_payloads_ = std::optional<::google::protobuf::Any>(custom_payloads);
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        throw;
                    }
                }

                inline explicit PWTPayload() {
                    this->nbf_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(0));
                    this->iat_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(0));
                    this->exp_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(3600));
                    this->custom_payloads_ = std::nullopt;
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        throw;
                    }
                }

                inline PWTPayload(const PWTPayload& payload) {
                    if (this == &payload) {
                        return;
                    }
                    this->iss_ = payload.iss_;
                    this->sub_ = payload.sub_;
                    this->aud_ = payload.aud_;
                    this->nbf_ = payload.nbf_;
                    this->iat_ = payload.iat_;
                    this->exp_ = payload.exp_;
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        throw;
                    }
                    if (payload.custom_payloads_.has_value()) {
                        custom_payloads_->CopyFrom(*payload.custom_payloads_);
                    } else {
                        custom_payloads_ = std::nullopt;
                    }
                }

                inline PWTPayload& operator=(const PWTPayload& payload) {
                    if (this == &payload) {
                        return *this;
                    }
                    iss_ = payload.iss_;
                    sub_ = payload.sub_;
                    aud_ = payload.aud_;
                    nbf_ = payload.nbf_;
                    iat_ = payload.iat_;
                    exp_ = payload.exp_;
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        throw;
                    }
                    if (payload.custom_payloads_.has_value()) {
                        custom_payloads_->CopyFrom(*payload.custom_payloads_);
                    } else {
                        custom_payloads_ = std::nullopt;
                    }
                    return *this;
                }
            };

            /**
             * @brief Base class for PWTPayload, which is need to be inherited.
             */
            class PWTPayloadBase : public PWTPayload {
            public:
                inline explicit PWTPayloadBase(const std::string& iss, const std::string& sub, const std::string& aud,
                                               const std::optional<::google::protobuf::Any>& custom_payloads = std::nullopt,
                                               const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0)
                    : PWTPayload(iss, sub, aud, custom_payloads, exp, nbf, iat) {}

                inline explicit PWTPayloadBase(const std::string& iss, const std::string& sub, const std::vector<std::string>& aud,
                                               const std::optional<::google::protobuf::Any>& custom_payloads = std::nullopt,
                                               const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0)
                    : PWTPayload(iss, sub, aud, custom_payloads, exp, nbf, iat) {}

                inline explicit PWTPayloadBase() : PWTPayload() {}

                PWTPayloadBase(const PWTPayloadBase& payload) = default;

                PWTPayloadBase(PWTPayloadBase&&) noexcept = default;

                inline PWTPayloadBase& operator=(const PWTPayloadBase& payload) = default;

                PWTPayloadBase& operator=(PWTPayloadBase&&) noexcept = default;
                /**
                 * @brief Encode the header to a string.
                 *
                 * @return std::string The encoded header.
                 * @throw std::invalid_argument If the header is invalid.
                 * @throw std::runtime_error If the header cannot be encoded.
                 * @throw std::exception If any other error occurs.
                 * @note The header is encoded to binary protobuf format.
                 */
                std::string Encode() const;
                /**
                 * @brief Decode the header from a string.
                 *
                 * @param msg The encoded header.
                 * @return true If the header is decoded successfully.
                 * @return false If the header is invalid.
                 *
                 * @throw std::invalid_argument If the header is invalid.
                 * @throw std::runtime_error If the header cannot be decoded.
                 * @throw std::exception If any other error occurs.
                 * @note The header is decoded from binary protobuf format.
                 */
                bool Decode(const std::string& msg) noexcept;
                /**
                 * @brief Whether the token is expired, i.e. the current time is greater than the expiration time.
                 *
                 * @return true If the token is expired.
                 * @return false If the token is not expired.
                 *
                 * @note If the expiration time is not set, the token is not expired.
                 */
                inline bool IsExpired() const noexcept {
                    if (!exp_.has_value()) {
                        return false;
                    }
                    return exp_.value() < ::wind::utils::time::GetTimestamp();
                }

                ~PWTPayloadBase() = default;
            };

            /**
             * @brief The PWT class.
             *
             * @tparam Header Template parameter for the header, which must be derived from PWTHeader.
             * @tparam Payload Template parameter for the payload, which must be derived from PWTPayload.
             * @tparam Algorithm Template parameter for the crypto algorithm, which must be derived from Algorithm.
             */
            template <typename Header = PWTHeaderBase, typename Payload = PWTPayloadBase, typename Algorithm = ::wind::utils::encrypt::AlgorithmBase>
            class PWTInstance {
            private:
                // A unique pointer to the header, pointing to a derived class of PWTHeader.
                std::unique_ptr<PWTHeader> header_;
                // A unique pointer to the payload, pointing to a derived class of PWTPayload.
                std::unique_ptr<PWTPayload> payload_;
                // A unique pointer to the crypto algorithm, pointing to a derived class of Algorithm.
                std::unique_ptr<::wind::utils::encrypt::Algorithm> crypto_;

                /**
                 * @brief Sign the string with the crypto algorithm.
                 *
                 * @param s The string to be signed.
                 * @return std::string The signature.
                 *
                 * @throw std::invalid_argument If the string to be signed is empty.
                 * @throw std::invalid_argument If the crypto algorithm is empty.
                 * @throw std::runtime_error If the string cannot be signed.
                 */
                inline std::string Sign(const std::string& s) const {
                    if (s.empty()) {
                        throw std::invalid_argument("The string to be signed cannot be empty");
                    } else if (!this->crypto_) {
                        throw std::invalid_argument("The crypto algorithm cannot be empty");
                    }
                    // Set the data to be signed.
                    this->crypto_->data_ = s;
                    try {
                        return this->crypto_->Encrypt();
                    } catch (std::exception& e) {
                        throw;
                    }
                }

            public:
                /**
                 * @brief Is the token valid.
                 *
                 * @param s The token.
                 * @return true If the token is valid.
                 * @return false If the token is invalid.
                 */
                inline bool IsTokenValid(const std::string& s) const {
                    PWTMessage jwt_msg;
                    if (!jwt_msg.ParseFromString(s)) {
                        return false;
                    }
                    auto header_str = jwt_msg.header();
                    auto payload_str = jwt_msg.payload();
                    auto signature = jwt_msg.signature();
                    return signature == Sign(header_str + payload_str);
                }

                /**
                 * @brief Is the token expired.
                 *
                 * @return true If the token is expired.
                 * @return false If the token is not expired.
                 *
                 * @note If the payload is empty, the token is expired.
                 * @note If the expiration time is not set, the token is not expired.
                 */
                inline bool IsExpired() const noexcept {
                    if (!this->payload_) {
                        return true;
                    }
                    return payload_->IsExpired();
                }

                /**
                 * @brief Encode data to a token.
                 *
                 * @return std::string The encoded token.
                 *
                 * @throw std::invalid_argument If the header is empty.
                 * @throw std::invalid_argument If the payload is empty.
                 * @throw std::invalid_argument If the crypto algorithm is empty.
                 * @throw std::runtime_error If the header cannot be encoded.
                 */
                inline std::string Encode() const {
                    if (!this->header_) {
                        throw std::invalid_argument("The header cannot be empty");
                    } else if (!this->payload_) {
                        throw std::invalid_argument("The payload cannot be empty");
                    } else if (!this->crypto_) {
                        throw std::invalid_argument("The crypto cannot be empty");
                    }
                    try {
                        auto header_str = header_->Encode();
                        auto payload_str = payload_->Encode();
                        auto signature = Sign(header_str + payload_str);
                        PWTMessage pwt_msg;
                        pwt_msg.set_header(header_str);
                        pwt_msg.set_payload(payload_str);
                        pwt_msg.set_signature(signature);
                        return pwt_msg.SerializeAsString();
                    } catch (std::exception& e) {
                        throw;
                    }
                }

                /**
                 * @brief Decode the token to the header and payload.
                 *
                 * @param msg The token.
                 * @return true If the token is valid, which means the header and payload are decoded successfully, and the signature is valid.
                 * @return false If the token is invalid.
                 */
                inline bool Decode(const std::string& msg) const {
                    PWTMessage pwt_msg;
                    if (!pwt_msg.ParseFromString(msg) || !this->header_ || !this->payload_ || !this->crypto_) {
                        return false;
                    }

                    auto header_str = pwt_msg.header();
                    auto payload_str = pwt_msg.payload();
                    auto signature_str = pwt_msg.signature();
                    return signature_str == Sign(header_str + payload_str) && header_->Decode(header_str) && payload_->Decode(payload_str);
                }

                ~PWTInstance() = default;

                /**
                 * @brief Construct a new PWT Instance object
                 *
                 * @param header Optional, the header class derived from PWTHeader.
                 * @param payload Optional, the payload class derived from PWTPayload.
                 * @param crypto Optional, the crypto algorithm class derived from Algorithm.
                 *
                 * @throw runtime_error if payload initialization failed.
                 * @note If the header is not provided, the default header will be used.
                 */
                inline explicit PWTInstance(std::unique_ptr<PWTHeader>&& header = nullptr, std::unique_ptr<PWTPayload>&& payload = nullptr,
                                            std::unique_ptr<::wind::utils::encrypt::Algorithm>&& crypto = nullptr) {
                    static_assert(std::is_base_of_v<PWTHeader, Header>, "Header must be derived from PWTHeader");
                    static_assert(std::is_base_of_v<PWTPayload, Payload>, "Payload must be derived from PWTPayload");
                    static_assert(std::is_base_of_v<::wind::utils::encrypt::AlgorithmBase, Algorithm>, "Algorithm must be derived from AlgorithmBase");
                    if (header) {
                        this->header_ = std::move(header);
                    } else {
                        this->header_ = std::make_unique<Header>();
                    }
                    if (payload) {
                        this->payload_ = std::move(payload);
                    } else {
                        try {
                            this->payload_ = std::make_unique<Payload>();
                        } catch (std::exception& e) {
                            throw;
                        }
                    }
                    if (crypto) {
                        this->crypto_ = std::move(crypto);
                    } else {
                        this->crypto_ = std::make_unique<Algorithm>();
                    }
                }

                inline PWTInstance(PWTInstance& other) noexcept {
                    if (this != &other) {
                        this->header_ = std::make_unique<Header>();
                        this->payload_ = std::make_unique<Payload>();
                        this->crypto_ = std::make_unique<Algorithm>();
                        if (other.header_) {
                            this->header_->pwk_ = other.header_->pwk_;
                            this->header_->x5u_ = other.header_->x5u_;
                            this->header_->custom_fields_ = other.header_->custom_fields_;
                            this->header_->custom_headers_ = other.header_->custom_headers_;
                            this->header_->kid_ = other.header_->kid_;
                            this->header_->typ_ = other.header_->typ_;
                        }
                        if (other.payload_) {
                            this->payload_->custom_fields_ = other.payload_->custom_fields_;
                            this->payload_->custom_payloads_ = other.payload_->custom_payloads_;
                            this->payload_->exp_ = other.payload_->exp_;
                            this->payload_->iat_ = other.payload_->iat_;
                            this->payload_->iss_ = other.payload_->iss_;
                            this->payload_->nbf_ = other.payload_->nbf_;
                            this->payload_->sub_ = other.payload_->sub_;
                            this->payload_->aud_ = other.payload_->aud_;
                            this->payload_->pbi_ = this->payload_->GeneratePbi();
                        }
                        if (other.crypto_) {
                            this->crypto_->data_ = other.crypto_->data_;
                            this->crypto_->key_ = other.crypto_->key_;
                            this->crypto_->iv_ = other.crypto_->iv_;
                            this->crypto_->salt_ = other.crypto_->salt_;
                        }
                    }
                }

                inline PWTInstance(PWTInstance&& other) noexcept {
                    if (other.header_) {
                        this->header_ = std::move(other.header_);
                        other.header_ = nullptr;
                    }
                    if (other.payload_) {
                        this->payload_ = std::move(other.payload_);
                        other.payload_ = nullptr;
                    }
                    if (other.crypto_) {
                        this->crypto_ = std::move(other.crypto_);
                        other.crypto_ = nullptr;
                    }
                }

                inline PWTInstance& operator=(const PWTInstance& other) {
                    if (this == &other) {
                        return *this;
                    }
                    this->header_ = std::make_unique<Header>();
                    this->payload_ = std::make_unique<Payload>();
                    this->crypto_ = std::make_unique<Algorithm>();
                    if (other.header_) {
                        this->header_->pwk_ = other.header_->pwk_;
                        this->header_->x5u_ = other.header_->x5u_;
                        this->header_->custom_fields_ = other.header_->custom_fields_;
                        this->header_->custom_headers_ = other.header_->custom_headers_;
                        this->header_->kid_ = other.header_->kid_;
                        this->header_->typ_ = other.header_->typ_;
                    }
                    if (other.payload_) {
                        this->payload_->custom_fields_ = other.payload_->custom_fields_;
                        this->payload_->custom_payloads_ = other.payload_->custom_payloads_;
                        this->payload_->exp_ = other.payload_->exp_;
                        this->payload_->iat_ = other.payload_->iat_;
                        this->payload_->iss_ = other.payload_->iss_;
                        this->payload_->nbf_ = other.payload_->nbf_;
                        this->payload_->sub_ = other.payload_->sub_;
                        this->payload_->aud_ = other.payload_->aud_;
                        this->payload_->pbi_ = this->payload_->GeneratePbi();
                    }
                    if (other.crypto_) {
                        this->crypto_->data_ = other.crypto_->data_;
                        this->crypto_->key_ = other.crypto_->key_;
                        this->crypto_->iv_ = other.crypto_->iv_;
                        this->crypto_->salt_ = other.crypto_->salt_;
                    }
                    return *this;
                }

                inline PWTInstance& operator=(PWTInstance&& other) noexcept {
                    if (this->header_) {
                        this->header_ = std::move(other.header_);
                        other.header_ = nullptr;
                    }
                    if (this->payload_) {
                        this->payload_ = std::move(other.payload_);
                        other.payload_ = nullptr;
                    }
                    if (this->crypto_) {
                        this->crypto_ = std::move(other.crypto_);
                        other.crypto_ = nullptr;
                    }
                    return *this;
                }

                /**
                 * @brief Set the Typ object of the header.
                 *
                 * @param typ The typ value, which must be less than 255 characters.
                 * @return PWTInstance& The reference of the current instance.
                 */
                inline PWTInstance& SetTyp(const std::string& typ) noexcept {
                    if (this->header_ && typ.length() <= 255) {
                        this->header_->typ_ = typ;
                    }
                    return *this;
                }

                inline PWTInstance& SetKid(const std::string& kid) noexcept {
                    if (this->header_) {
                        this->header_->kid_ = kid;
                    }
                    return *this;
                }

                inline PWTInstance& SetPwk(const std::string& pwk) {
                    if (this->header_) {
                        this->header_->pwk_ = pwk;
                    }
                    return *this;
                }

                inline PWTInstance& SetX5u(const std::string& x5u) {
                    if (this->header_) {
                        this->header_->x5u_ = x5u;
                    }
                    return *this;
                }

                inline PWTInstance& SetHeaderCustomField(const std::unordered_map<std::string, std::string>& custom_fields) {
                    if (this->header_) {
                        this->header_->custom_fields_ = custom_fields;
                    }
                    return *this;
                }

                inline PWTInstance& AddHeaderCustomField(const std::string& key, const std::string& value) {
                    this->header_->custom_fields_[key] = value;
                    return *this;
                }

                inline PWTInstance& SetCustomHeader(const ::google::protobuf::Any& custom_header) {
                    if (this->header_) {
                        if (this->header_->custom_headers_.has_value()) {
                            this->header_->custom_headers_.value() = custom_header;
                        } else {
                            this->header_->custom_headers_ = std::optional<::google::protobuf::Any>(custom_header);
                        }
                    }
                    return *this;
                }

                inline PWTInstance& SetIss(const std::string& iss) {
                    if (this->payload_) {
                        this->payload_->iss_ = iss;
                    }
                    return *this;
                }

                inline PWTInstance& SetSub(const std::string& sub) {
                    if (this->payload_) {
                        this->payload_->sub_ = sub;
                    }
                    return *this;
                }
                /**
                 * @brief Set the Aud object of the payload.
                 *
                 * @note This method will replace the aud value of the payload.
                 */
                inline PWTInstance& SetAud(const std::string& aud) {
                    if (this->payload_) {
                        this->payload_->aud_ = aud;
                    }
                    return *this;
                }

                /**
                 * @brief Add the aud value to the aud vector of the payload.
                 * @note This method will add the aud value to the aud vector of the payload.
                 */
                inline PWTInstance& AddAud(const std::string& aud) {
                    if (this->payload_) {
                        if (std::holds_alternative<std::string>(this->payload_->aud_)) {
                            this->payload_->aud_ = std::vector<std::string>({std::move(std::get<std::string>(this->payload_->aud_)), aud});
                        } else if (std::holds_alternative<std::vector<std::string>>(this->payload_->aud_)) {
                            std::get<std::vector<std::string>>(this->payload_->aud_).emplace_back(aud);
                        } else {
                            this->payload_->aud_ = aud;
                        }
                    }
                    return *this;
                }

                /**
                 * @brief Add the aud values to the aud vector of the payload.
                 * @note This method will add the aud values to the aud vector of the payload.
                 */
                inline PWTInstance& AddAud(const std::vector<std::string>& auds) {
                    if (!this->payload_) {
                        if (std::holds_alternative<std::string>(this->payload_->aud_)) {
                            std::vector<std::string> auds_vec = {std::get<std::string>(this->payload_->aud_)};
                            auds_vec.insert(auds_vec.end(), auds.begin(), auds.end());
                            this->payload_->aud_ = auds_vec;
                        } else if (std::holds_alternative<std::vector<std::string>>(this->payload_->aud_)) {
                            std::get<std::vector<std::string>>(this->payload_->aud_).insert(std::get<std::vector<std::string>>(this->payload_->aud_).end(), auds.begin(), auds.end());
                        } else {
                            this->payload_->aud_ = auds;
                        }
                    }
                    return *this;
                }

                inline PWTInstance& SetExp(const std::uint64_t exp) {
                    if (this->payload_) {
                        this->payload_->exp_ = ::wind::utils::time::GetTimestamp(exp);
                    }
                    return *this;
                }

                inline PWTInstance& SetNbf(const std::uint64_t nbf) {
                    if (this->payload_) {
                        this->payload_->nbf_ = ::wind::utils::time::GetTimestamp(nbf);
                    }
                    return *this;
                }

                inline PWTInstance& SetIat(const std::uint64_t iat) {
                    if (this->payload_) {
                        this->payload_->iat_ = ::wind::utils::time::GetTimestamp(iat);
                    }
                    return *this;
                }

                inline PWTInstance& SetPayloadCutsomField(const std::unordered_map<std::string, std::string>& custom_fields) {
                    if (this->payload_) {
                        this->payload_->custom_fields_ = custom_fields;
                    }
                    return *this;
                }

                inline PWTInstance& AddPayloadCustomField(const std::string& key, const std::string& value) {
                    if (this->payload_) {
                        this->payload_->custom_fields_[key] = value;
                    }
                    return *this;
                }

                inline PWTInstance& SetCustomPayload(const ::google::protobuf::Any& custom_payload) {
                    if (this->payload_) {
                        if (this->payload_->custom_payloads_.has_value()) {
                            this->payload_->custom_payloads_.value() = custom_payload;
                        } else {
                            this->payload_->custom_payloads_ = std::optional<::google::protobuf::Any>(custom_payload);
                        }
                    }
                    return *this;
                }

                inline PWTInstance& SetHeader(std::unique_ptr<PWTHeader>&& header) {
                    this->header_ = std::move(header);
                    return *this;
                }

                inline PWTInstance& SetPayload(std::unique_ptr<PWTPayload>&& payload) {
                    this->payload_ = std::move(payload);
                    return *this;
                }

                inline PWTInstance& SetCrypto(std::unique_ptr<::wind::utils::encrypt::Algorithm>&& crypto) {
                    this->crypto_ = std::move(crypto);
                    return *this;
                }

                inline std::string GetTyp() const noexcept {
                    if (!this->header_) {
                        return std::string();
                    }
                    return this->header_->typ_;
                }

                inline std::string GetKid() const noexcept {
                    if (!this->header_) {
                        return std::string();
                    }
                    return this->header_->kid_;
                }

                inline std::string GetPwk() const noexcept {
                    if (!this->header_) {
                        return std::string();
                    }
                    return this->header_->pwk_;
                }

                inline std::string GetX5u() const noexcept {
                    if (!this->header_) {
                        return std::string();
                    }
                    return this->header_->x5u_;
                }

                inline std::unordered_map<std::string, std::string> GetHeaderCustomFields() const noexcept {
                    if (!this->header_) {
                        return std::unordered_map<std::string, std::string>();
                    }
                    return this->header_->custom_fields_;
                }

                inline std::string GetHeaderCustomField(const std::string& key) const noexcept {
                    if (!this->header_) {
                        return std::string();
                    }
                    return this->header_->custom_fields_[key];
                }

                inline std::optional<::google::protobuf::Any> GetCustomHeader() const noexcept {
                    if (!this->header_) {
                        return std::nullopt;
                    }
                    return this->header_->custom_headers_;
                }

                inline std::string GetIss() const noexcept {
                    if (!this->payload_) {
                        return std::string();
                    }
                    return this->payload_->iss_;
                }

                inline std::string GetSub() const noexcept {
                    if (!this->payload_) {
                        return std::string();
                    }
                    return this->payload_->sub_;
                }

                /**
                 * @brief Get a aud.
                 *
                 * @return std::string If the aud is a string, return it directly. If the aud is a vector, return the first element of the vector.
                 */
                inline std::string GetAud() const noexcept {
                    if (!this->payload_) {
                        return std::string();
                    } else if (std::holds_alternative<std::string>(this->payload_->aud_)) {
                        return std::get<std::string>(this->payload_->aud_);
                    } else if (!std::holds_alternative<std::vector<std::string>>(this->payload_->aud_) || std::get<std::vector<std::string>>(this->payload_->aud_).empty()) {
                        return std::string();
                    }
                    return std::get<std::vector<std::string>>(this->payload_->aud_)[0];
                }

                inline std::vector<std::string> GetAuds() const noexcept {
                    if (!this->payload_) {
                        return std::vector<std::string>();
                    } else if (std::holds_alternative<std::string>(this->payload_->aud_)) {
                        return std::vector<std::string>({std::get<std::string>(this->payload_->aud_)});
                    } else if (!std::holds_alternative<std::vector<std::string>>(this->payload_->aud_) || std::get<std::vector<std::string>>(this->payload_->aud_).empty()) {
                        return std::vector<std::string>();
                    }
                    return std::get<std::vector<std::string>>(this->payload_->aud_);
                }

                inline ::google::protobuf::Timestamp GetExp() const noexcept {
                    if (!this->payload_ || !this->payload_->exp_.has_value()) {
                        return ::wind::utils::time::GetTimestamp();
                    }
                    return this->payload_->exp_.value();
                }

                inline std::string GetExpStr() const noexcept {
                    if (!this->payload_ || !this->payload_->exp_.has_value()) {
                        return ::wind::utils::time::GetTimestampString();
                    }
                    return ::wind::utils::time::TimestampToString(this->payload_->exp_.value());
                }

                inline ::google::protobuf::Timestamp GetNbf() const noexcept {
                    if (!this->payload_ || !this->payload_->nbf_.has_value()) {
                        return ::wind::utils::time::GetTimestamp();
                    }
                    return this->payload_->nbf_.value();
                }

                inline std::string GetNbfStr() const noexcept {
                    if (!this->payload_ || !this->payload_->nbf_.has_value()) {
                        return ::wind::utils::time::GetTimestampString();
                    }
                    return ::wind::utils::time::TimestampToString(this->payload_->nbf_.value());
                }

                inline ::google::protobuf::Timestamp GetIat() const noexcept {
                    if (!this->payload_ || !this->payload_->iat_.has_value()) {
                        return ::wind::utils::time::GetTimestamp();
                    }
                    return this->payload_->iat_.value();
                }

                inline std::string GetIatStr() const noexcept {
                    if (!this->payload_ || !this->payload_->iat_.has_value()) {
                        return ::wind::utils::time::GetTimestampString();
                    }
                    return ::wind::utils::time::TimestampToString(this->payload_->iat_.value());
                }

                inline std::unordered_map<std::string, std::string> GetPayloadCustomFields() const noexcept {
                    if (!this->payload_) {
                        return std::unordered_map<std::string, std::string>();
                    }
                    return this->payload_->custom_fields_;
                }

                inline std::string GetPayloadCustomField(const std::string& key) const noexcept {
                    if (!this->payload_) {
                        return std::string();
                    }
                    return this->payload_->custom_fields_[key];
                }

                inline std::optional<::google::protobuf::Any> GetCustomPayload() const noexcept {
                    if (!this->payload_) {
                        return std::nullopt;
                    }
                    return this->payload_->custom_payloads_;
                }

                inline const PWTHeader* const GetHeader() const noexcept {
                    if (!this->header_) {
                        return nullptr;
                    }
                    return this->header_.get();
                }

                inline const PWTPayload* const GetPayload() const noexcept {
                    if (!this->payload_) {
                        return nullptr;
                    }
                    return this->payload_.get();
                }

                inline const ::wind::utils::encrypt::Algorithm* const GetCrypto() const noexcept {
                    if (!this->crypto_) {
                        return nullptr;
                    }
                    return this->crypto_.get();
                }

                inline PWTInstance& CopyAlgorithm(const PWTInstance& other) noexcept {
                    if (!other.crypto_) {
                        return *this;
                    }
                    auto tmp = std::make_unique<::wind::utils::encrypt::AlgorithmBase>();
                    tmp->data_ = other.GetCrypto()->data_;
                    tmp->key_ = other.GetCrypto()->key_;
                    tmp->iv_ = other.GetCrypto()->iv_;
                    tmp->salt_ = other.GetCrypto()->salt_;
                    this->crypto_ = std::move(tmp);
                    return *this;
                }
            };

            /**
             * @brief Create a PWT Instance object
             *
             * @tparam Header Derived from PWTHeader
             * @tparam Payload Derived from PWTPayload
             * @tparam Algorithm Derived from Algorithm
             * @return PWTInstance<Header, Payload, Algorithm> PWTInstance
             *
             * @throw std::exception if failed to create PWTInstance
             *
             * @example
             * auto pwt = wind::utils::pwt::CreatePWTInstance();
             * auto pwt = wind::utils::pwt::CreatePWTInstance().SetTyp("PWT").Encode();
             */
            template <typename Header = PWTHeaderBase, typename Payload = PWTPayloadBase, typename Algorithm = ::wind::utils::encrypt::AlgorithmBase>
            inline PWTInstance<Header, Payload, Algorithm> CreatePWTInstance() {
                try {
                    return PWTInstance<Header, Payload, Algorithm>();
                } catch (const std::exception& e) {
                    throw;
                }
            }
        }  // namespace pwt
    }      // namespace utils
}  // namespace wind