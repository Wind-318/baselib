/**
 * @file pwt.h
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

#include <google/protobuf/any.pb.h>
#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

#include "atomic_unordered_map.h"
#include "encrypt.h"
#include "pwt.pb.h"
#include "time_opt.h"

namespace wind {
    namespace utils {
        namespace pwt {
            /**
             * @brief Base class for PWTHeader
             */
            class PWTHeader {
            private:
                inline void CopyConstructor(const PWTHeader& header) noexcept {
                    if (this == &header) {
                        return;
                    }
                    std::shared_lock lock(header.mutex_);
                    std::unique_lock lock2(mutex_);
                    this->typ_ = header.typ_;
                    this->kid_ = header.kid_;
                    this->pwk_ = header.pwk_;
                    this->x5u_ = header.x5u_;
                    this->custom_fields_.copy_from(header.custom_fields_);

                    if (header.custom_header_.has_value()) {
                        if (!this->custom_header_.has_value()) {
                            this->custom_header_ = std::make_optional<::google::protobuf::Any>();
                        }
                        this->custom_header_->CopyFrom(*header.custom_header_);
                    } else {
                        this->custom_header_ = std::nullopt;
                    }
                }

                inline void MoveConstructor(PWTHeader&& header) noexcept {
                    if (this == &header) {
                        return;
                    }
                    std::unique_lock lock(header.mutex_);
                    std::unique_lock lock2(mutex_);
                    this->typ_ = std::move(header.typ_);
                    this->kid_ = std::move(header.kid_);
                    this->pwk_ = std::move(header.pwk_);
                    this->x5u_ = std::move(header.x5u_);
                    this->custom_fields_ = std::move(header.custom_fields_);
                    this->custom_header_ = std::move(header.custom_header_);
                }

            protected:
                // The type of the token
                std::string typ_;
                // The key id
                std::string kid_;
                // Protobuf web token
                std::string pwk_;
                // The X.509 URL
                std::string x5u_;
                // Custom fields
                atomic_unordered_map<std::string, std::string> custom_fields_;
                // Custom headers
                std::optional<::google::protobuf::Any> custom_header_;
                // Mutex for custom_fields_
                mutable std::shared_mutex custom_header_mutex_;
                // Mutex for custom_header_
                mutable std::shared_mutex mutex_;

            public:
                virtual ~PWTHeader() = default;

                /**
                 * @brief Seralize the header to a string
                 *
                 * @return std::string
                 */
                virtual std::string Encode() = 0;

                /**
                 * @brief Decode a binary protobuf message to a PWTHeader
                 *
                 * @param msg The binary protobuf message
                 * @return true If the message is successfully decoded
                 * @return false If the message is not successfully decoded
                 */
                virtual bool Decode(const std::string& msg) noexcept = 0;
                /**
                 * @brief Clone the header
                 *
                 * @return std::unique_ptr<PWTHeader> A unique pointer to the cloned header
                 */
                virtual std::unique_ptr<PWTHeader> Clone() const noexcept = 0;

                inline std::string GetType() const noexcept {
                    std::shared_lock lock(mutex_);
                    return typ_;
                }

                inline std::string GetKeyID() const noexcept {
                    std::shared_lock lock(mutex_);
                    return kid_;
                }

                inline std::string GetPWK() const noexcept {
                    std::shared_lock lock(mutex_);
                    return pwk_;
                }

                inline std::string GetX5U() const noexcept {
                    std::shared_lock lock(mutex_);
                    return x5u_;
                }

                inline atomic_unordered_map<std::string, std::string> GetCustomFields() const noexcept {
                    return custom_fields_;
                }

                inline std::string GetCustomField(const std::string& key) noexcept {
                    return custom_fields_[key];
                }

                inline std::optional<::google::protobuf::Any> GetCustomHeader() const noexcept {
                    std::shared_lock lock(custom_header_mutex_);
                    return custom_header_;
                }

                inline void SetType(const std::string& typ) noexcept {
                    std::unique_lock lock(mutex_);
                    typ_ = typ;
                }

                inline void SetKeyID(const std::string& kid) noexcept {
                    std::unique_lock lock(mutex_);
                    kid_ = kid;
                }

                inline void SetPWK(const std::string& pwk) noexcept {
                    std::unique_lock lock(mutex_);
                    pwk_ = pwk;
                }

                inline void SetX5U(const std::string& x5u) noexcept {
                    std::unique_lock lock(mutex_);
                    x5u_ = x5u;
                }

                inline void SetCustomFields(const std::unordered_map<std::string, std::string>& custom_fields) noexcept {
                    custom_fields_.copy_from(custom_fields);
                }

                inline void SetCustomFields(const atomic_unordered_map<std::string, std::string>& custom_fields) noexcept {
                    custom_fields_.copy_from(custom_fields);
                }

                inline void AddCustomField(const std::string& key, const std::string& value) noexcept {
                    custom_fields_.insert(key, value);
                }

                inline void SetCustomHeader(const ::google::protobuf::Any& custom_header) noexcept {
                    std::unique_lock lock(custom_header_mutex_);
                    custom_header_ = std::make_optional(custom_header);
                }

                inline explicit PWTHeader(const std::string& typ, const std::string& kid,
                                          const std::string& pwk, const std::string& x5u,
                                          const std::unordered_map<std::string, std::string>& custom_fields = {},
                                          const std::optional<::google::protobuf::Any>& custom_header = std::nullopt) noexcept {
                    std::unique_lock lock(mutex_);
                    this->typ_ = typ;
                    this->kid_ = kid;
                    this->pwk_ = pwk;
                    this->x5u_ = x5u;
                    this->custom_fields_.copy_from(custom_fields);
                    custom_header_ = custom_header;
                }

                inline explicit PWTHeader() noexcept {
                    std::unique_lock lock(mutex_);
                    this->typ_ = std::string("PWT");
                    this->custom_header_ = std::nullopt;
                }

                inline PWTHeader(const PWTHeader& header) noexcept {
                    CopyConstructor(header);
                }

                inline PWTHeader(PWTHeader&& header) noexcept {
                    MoveConstructor(std::forward<PWTHeader>(header));
                }

                inline PWTHeader& operator=(const PWTHeader& header) noexcept {
                    CopyConstructor(header);
                    return *this;
                }

                inline PWTHeader& operator=(PWTHeader&& header) noexcept {
                    MoveConstructor(std::forward<PWTHeader>(header));
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
                                              const std::optional<::google::protobuf::Any>& custom_header = std::nullopt) noexcept
                    : PWTHeader(typ, kid, pwk, x5u, custom_fields, custom_header) {}

                inline explicit PWTHeaderBase() noexcept : PWTHeader() {}

                PWTHeaderBase(const PWTHeaderBase& header) noexcept = default;

                PWTHeaderBase(PWTHeaderBase&&) noexcept = default;

                inline PWTHeaderBase& operator=(const PWTHeaderBase& header) noexcept = default;

                PWTHeaderBase& operator=(PWTHeaderBase&&) noexcept = default;

                std::unique_ptr<PWTHeader> Clone() const noexcept {
                    return std::make_unique<PWTHeaderBase>(*this);
                }
                /**
                 * @brief Encode the header to a string
                 *
                 * @return std::string The encoded header, which is a binary protobuf message
                 *
                 * @throw std::runtime_error If the header is not successfully encoded
                 */
                std::string Encode();
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
            private:
                inline void CopyConstructor(const PWTPayload& payload) noexcept {
                    if (this == &payload) {
                        return;
                    }
                    std::shared_lock lock(payload.mutex_);
                    std::shared_lock lock2(mutex_);
                    this->iss_ = payload.iss_;
                    this->sub_ = payload.sub_;
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        this->pbi_ = std::string();
                    }
                    this->custom_fields_.copy_from(payload.custom_fields_);

                    this->aud_ = payload.aud_;
                    this->nbf_ = payload.nbf_;
                    this->iat_ = payload.iat_;
                    this->exp_ = payload.exp_;
                    if (payload.custom_payload_.has_value()) {
                        if (!custom_payload_.has_value()) {
                            custom_payload_ = std::make_optional(::google::protobuf::Any());
                        }
                        custom_payload_->CopyFrom(*payload.custom_payload_);
                    } else {
                        custom_payload_ = std::nullopt;
                    }
                }

                inline void MoveConstructor(PWTPayload&& payload) noexcept {
                    if (this == &payload) {
                        return;
                    }
                    std::unique_lock lock(payload.mutex_);
                    std::unique_lock lock2(this->mutex_);
                    this->iss_ = std::move(payload.iss_);
                    this->sub_ = std::move(payload.sub_);
                    this->pbi_ = std::move(payload.pbi_);
                    this->aud_ = std::move(payload.aud_);
                    this->nbf_ = std::move(payload.nbf_);
                    this->iat_ = std::move(payload.iat_);
                    this->exp_ = std::move(payload.exp_);
                    this->custom_fields_ = std::move(payload.custom_fields_);
                    this->custom_payload_ = std::move(payload.custom_payload_);
                }

                inline void InitConstructor(const std::string& iss, const std::string& sub,
                                            const std::variant<std::string, std::vector<std::string>>& aud,
                                            const unsigned& exp, const unsigned& nbf, const unsigned& iat,
                                            const std::optional<::google::protobuf::Any>& custom_payload) noexcept {
                    std::unique_lock lock(mutex_);
                    this->iss_ = iss;
                    this->sub_ = sub;
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        this->pbi_ = std::string();
                    }

                    this->aud_ = std::variant<std::string, std::vector<std::string>>(aud);
                    this->nbf_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(nbf));
                    this->iat_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(iat));
                    this->exp_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(exp));
                    custom_payload_ = std::optional<::google::protobuf::Any>(custom_payload);

                    if (exp < iat || nbf > exp) {
                        this->exp_ = std::nullopt;
                        this->nbf_ = std::nullopt;
                        this->iat_ = std::nullopt;
                    }
                }

            protected:
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
                atomic_unordered_map<std::string, std::string> custom_fields_;
                // The custom payloads of the token
                std::optional<::google::protobuf::Any> custom_payload_;
                // The mutex for aud_
                mutable std::shared_mutex aud_mutex_;
                // The mutex for exp_
                mutable std::shared_mutex exp_mutex_;
                // The mutex for nbf_
                mutable std::shared_mutex nbf_mutex_;
                // The mutex for iat_
                mutable std::shared_mutex iat_mutex_;
                // The mutex for custom_fields_
                mutable std::shared_mutex custom_payload_mutex_;
                // The mutex for the class
                mutable std::shared_mutex mutex_;

            public:
                virtual ~PWTPayload() = default;
                /**
                 * @brief Seralize the payload to a string
                 *
                 * @return std::string
                 */
                virtual std::string Encode() = 0;
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
                 * @brief Clone the payload
                 *
                 * @return std::unique_ptr<PWTPayload> The cloned payload
                 */
                virtual std::unique_ptr<PWTPayload> Clone() const noexcept = 0;

                inline std::string GetIssuer() const noexcept {
                    std::shared_lock lock(mutex_);
                    return this->iss_;
                }

                inline std::string GetSubject() const noexcept {
                    std::shared_lock lock(mutex_);
                    return this->sub_;
                }

                inline const std::string GetAudience() const noexcept {
                    std::shared_lock lock(aud_mutex_);
                    if (std::holds_alternative<std::string>(aud_)) {
                        return std::get<std::string>(aud_);
                    } else if (std::holds_alternative<std::vector<std::string>>(aud_) && !std::get<std::vector<std::string>>(aud_).empty()) {
                        return std::get<std::vector<std::string>>(aud_).front();
                    }
                    return std::string("");
                }

                inline const std::vector<std::string> GetAudiences() const noexcept {
                    std::shared_lock lock(aud_mutex_);
                    if (std::holds_alternative<std::string>(aud_)) {
                        return std::vector<std::string>({std::get<std::string>(aud_)});
                    } else if (std::holds_alternative<std::vector<std::string>>(aud_)) {
                        return std::get<std::vector<std::string>>(aud_);
                    }
                    return std::vector<std::string>();
                }

                inline std::optional<::google::protobuf::Timestamp> GetExpirationTime() const noexcept {
                    std::shared_lock lock(exp_mutex_);
                    return this->exp_;
                }

                inline std::optional<::google::protobuf::Timestamp> GetNotBeforeTime() const noexcept {
                    std::shared_lock lock(nbf_mutex_);
                    return this->nbf_;
                }

                inline std::optional<::google::protobuf::Timestamp> GetIssuedAtTime() const noexcept {
                    std::shared_lock lock(iat_mutex_);
                    return this->iat_;
                }

                inline std::optional<::google::protobuf::Any> GetCustomPayload() const noexcept {
                    std::shared_lock lock(custom_payload_mutex_);
                    return this->custom_payload_;
                }

                inline std::string GetCustomField(const std::string& key) noexcept {
                    return this->custom_fields_[key];
                }

                inline atomic_unordered_map<std::string, std::string> GetCustomFields() const noexcept {
                    return this->custom_fields_;
                }

                inline void SetIssuer(const std::string& iss) noexcept {
                    std::unique_lock lock(mutex_);
                    this->iss_ = iss;
                }

                inline void SetSubject(const std::string& sub) noexcept {
                    std::unique_lock lock(mutex_);
                    this->sub_ = sub;
                }

                inline void SetAudience(const std::string& aud) noexcept {
                    std::unique_lock lock(aud_mutex_);
                    this->aud_ = aud;
                }

                inline void SetAudience(const std::vector<std::string>& aud) noexcept {
                    std::unique_lock lock(aud_mutex_);
                    this->aud_ = aud;
                }

                inline void AddAudience(const std::string& aud) noexcept {
                    std::unique_lock lock(aud_mutex_);
                    if (std::holds_alternative<std::string>(aud_)) {
                        this->aud_ = std::vector<std::string>({std::move(std::get<std::string>(aud_)), aud});
                    } else if (std::holds_alternative<std::vector<std::string>>(aud_)) {
                        std::get<std::vector<std::string>>(aud_).emplace_back(aud);
                    } else {
                        this->aud_ = aud;
                    }
                }

                inline void AddAudience(const std::vector<std::string>& auds) noexcept {
                    std::unique_lock lock(aud_mutex_);
                    if (std::holds_alternative<std::string>(aud_)) {
                        this->aud_ = std::vector<std::string>({std::move(std::get<std::string>(this->aud_)), std::move(std::get<std::string>(aud_))});
                    } else if (std::holds_alternative<std::vector<std::string>>(aud_)) {
                        std::get<std::vector<std::string>>(aud_).insert(std::get<std::vector<std::string>>(aud_).end(), auds.begin(), auds.end());
                    } else {
                        this->aud_ = auds;
                    }
                }

                inline void SetExpirationTime(const unsigned& exp) noexcept {
                    std::unique_lock lock(exp_mutex_);
                    this->exp_ = std::make_optional(::wind::utils::time::GetTimestamp(exp));
                }

                inline void SetNotBeforeTime(const unsigned& nbf) noexcept {
                    std::unique_lock lock(nbf_mutex_);
                    this->nbf_ = std::make_optional(::wind::utils::time::GetTimestamp(nbf));
                }

                inline void SetIssuedAtTime(const unsigned& iat) noexcept {
                    std::unique_lock lock(iat_mutex_);
                    this->iat_ = std::make_optional(::wind::utils::time::GetTimestamp(iat));
                }

                inline void SetCustomPayload(const ::google::protobuf::Any& custom_payload) noexcept {
                    std::unique_lock lock(custom_payload_mutex_);
                    this->custom_payload_ = std::make_optional(custom_payload);
                }

                inline void AddCustomField(const std::string& key, const std::string& value) noexcept {
                    this->custom_fields_.insert(key, value);
                }

                inline void SetCustomFields(const atomic_unordered_map<std::string, std::string>& custom_fields) noexcept {
                    this->custom_fields_.copy_from(custom_fields);
                }

                inline void SetCustomFields(const std::unordered_map<std::string, std::string>& custom_fields) noexcept {
                    this->custom_fields_.copy_from(custom_fields);
                }

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
                                           const std::optional<::google::protobuf::Any>& custom_payload = std::nullopt,
                                           const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0) noexcept {
                    InitConstructor(iss, sub, aud, exp, nbf, iat, custom_payload);
                }

                inline explicit PWTPayload(const std::string& iss, const std::string& sub, const std::vector<std::string>& aud,
                                           const std::optional<::google::protobuf::Any>& custom_payload = std::nullopt,
                                           const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0) noexcept {
                    InitConstructor(iss, sub, aud, exp, nbf, iat, custom_payload);
                }

                inline explicit PWTPayload() noexcept {
                    std::unique_lock lock(mutex_);
                    this->nbf_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(0));
                    this->iat_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(0));
                    this->exp_ = std::optional<::google::protobuf::Timestamp>(::wind::utils::time::GetTimestamp(3600));
                    this->custom_payload_ = std::nullopt;
                    try {
                        this->pbi_ = GeneratePbi();
                    } catch (std::exception& e) {
                        this->pbi_ = "";
                    }
                }

                inline PWTPayload(const PWTPayload& payload) noexcept {
                    CopyConstructor(payload);
                }

                inline PWTPayload(PWTPayload&& payload) noexcept {
                    MoveConstructor(std::forward<PWTPayload>(payload));
                }

                inline PWTPayload& operator=(const PWTPayload& payload) {
                    CopyConstructor(payload);
                    return *this;
                }

                inline PWTPayload& operator=(PWTPayload&& payload) {
                    MoveConstructor(std::forward<PWTPayload>(payload));
                    return *this;
                }
            };

            /**
             * @brief Base class for PWTPayload, which is need to be inherited.
             */
            class PWTPayloadBase : public PWTPayload {
            public:
                inline explicit PWTPayloadBase(const std::string& iss, const std::string& sub, const std::string& aud,
                                               const std::optional<::google::protobuf::Any>& custom_payload = std::nullopt,
                                               const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0)
                    : PWTPayload(iss, sub, aud, custom_payload, exp, nbf, iat) {}

                inline explicit PWTPayloadBase(const std::string& iss, const std::string& sub, const std::vector<std::string>& aud,
                                               const std::optional<::google::protobuf::Any>& custom_payload = std::nullopt,
                                               const unsigned& exp = 3600, const unsigned& nbf = 0, const unsigned& iat = 0)
                    : PWTPayload(iss, sub, aud, custom_payload, exp, nbf, iat) {}

                inline explicit PWTPayloadBase() : PWTPayload() {}

                PWTPayloadBase(const PWTPayloadBase& payload) = default;

                PWTPayloadBase(PWTPayloadBase&&) noexcept = default;

                inline PWTPayloadBase& operator=(const PWTPayloadBase& payload) = default;

                PWTPayloadBase& operator=(PWTPayloadBase&&) noexcept = default;

                std::unique_ptr<PWTPayload> Clone() const noexcept {
                    return std::make_unique<PWTPayloadBase>(*this);
                }
                /**
                 * @brief Encode the header to a string.
                 *
                 * @return std::string The encoded header.
                 * @throw std::exception If any other error occurs.
                 * @note The header is encoded to binary protobuf format.
                 */
                std::string Encode();
                /**
                 * @brief Decode the header from a string.
                 *
                 * @param msg The encoded header.
                 * @return true If the header is decoded successfully.
                 * @return false If the header is invalid.
                 *
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
                    std::shared_lock lock(exp_mutex_);
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
                // A mutex for the header.
                mutable std::shared_mutex header_mutex_;
                // A mutex for the payload.
                mutable std::shared_mutex payload_mutex_;
                // A mutex for the crypto algorithm.
                mutable std::shared_mutex crypto_mutex_;
                // A mutex for the PWT.
                mutable std::shared_mutex mutex_;

                inline void CopyConstructor(const PWTInstance& other) {
                    if (this == &other) {
                        return;
                    }
                    std::shared_lock lock(other.mutex_);
                    std::unique_lock lock1(this->mutex_);
                    if (other.header_) {
                        this->header_ = other.header_->Clone();
                    }
                    if (other.payload_) {
                        this->payload_ = other.payload_->Clone();
                    }
                    if (other.crypto_) {
                        this->crypto_ = other.crypto_->Clone();
                    }
                }

                inline void MoveConstructor(PWTInstance&& other_pwt) noexcept {
                    if (this == &other_pwt) {
                        return;
                    }
                    std::unique_lock lock(this->mutex_);
                    std::unique_lock lock1(other_pwt.mutex_);
                    if (other_pwt.header_) {
                        this->header_ = std::move(other_pwt.header_);
                    }
                    if (other_pwt.payload_) {
                        this->payload_ = std::move(other_pwt.payload_);
                    }
                    if (other_pwt.crypto_) {
                        this->crypto_ = std::move(other_pwt.crypto_);
                    }
                }

                /**
                 * @brief Sign the string with the crypto algorithm.
                 *
                 * @param s The string to be signed.
                 * @return std::string The signature.
                 *
                 * @throw runtime_error If the string to be signed is empty.
                 * @throw exception If any other error occurs.
                 */
                inline std::string Sign(const std::string& s) const {
                    if (s.empty()) {
                        throw std::runtime_error("The string to be signed is empty.");
                    }
                    try {
                        return this->crypto_->Encrypt(s);
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
                inline bool IsTokenValid(const std::string& s) const noexcept {
                    PWTMessage pwt_msg;
                    if (s.empty() || !pwt_msg.ParseFromString(s)) {
                        return false;
                    }
                    auto header_str = pwt_msg.header();
                    auto payload_str = pwt_msg.payload();
                    auto signature = pwt_msg.signature();
                    try {
                        return signature == Sign(header_str + payload_str);
                    } catch (std::exception& e) {
                        return false;
                    }
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
                    return payload_->IsExpired();
                }

                /**
                 * @brief Encode data to a token.
                 *
                 * @return std::string The encoded token.
                 *
                 * @throw std::runtime_error If the header cannot be encoded.
                 */
                inline std::string Encode() {
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
                inline bool Decode(const std::string& msg) {
                    PWTMessage pwt_msg;
                    if (msg.empty() || !pwt_msg.ParseFromString(msg)) {
                        return false;
                    }
                    auto header_str = pwt_msg.header();
                    auto payload_str = pwt_msg.payload();
                    auto signature_str = pwt_msg.signature();

                    try {
                        return signature_str == Sign(header_str + payload_str) && header_->Decode(header_str) && payload_->Decode(payload_str);
                    } catch (std::exception& e) {
                        return false;
                    }
                }

                ~PWTInstance() = default;

                /**
                 * @brief Construct a new PWT Instance object
                 *
                 * @param header Optional, the header class derived from PWTHeader.
                 * @param payload Optional, the payload class derived from PWTPayload.
                 * @param crypto Optional, the crypto algorithm class derived from Algorithm.
                 *
                 * @note If the header is not provided, the default header will be used.
                 */
                inline explicit PWTInstance(std::unique_ptr<PWTHeader>&& header = nullptr, std::unique_ptr<PWTPayload>&& payload = nullptr,
                                            std::unique_ptr<::wind::utils::encrypt::Algorithm>&& crypto = nullptr) noexcept {
                    static_assert(std::is_base_of_v<PWTHeader, Header>, "Header must be derived from PWTHeader");
                    static_assert(std::is_base_of_v<PWTPayload, Payload>, "Payload must be derived from PWTPayload");
                    static_assert(std::is_base_of_v<::wind::utils::encrypt::Algorithm, Algorithm>, "Algorithm must be derived from AlgorithmBase");
                    if (header) {
                        this->header_ = std::move(header);
                    } else {
                        this->header_ = std::make_unique<Header>();
                    }
                    if (payload) {
                        this->payload_ = std::move(payload);
                    } else {
                        this->payload_ = std::make_unique<Payload>();
                    }
                    if (crypto) {
                        this->crypto_ = std::move(crypto);
                    } else {
                        this->crypto_ = std::make_unique<Algorithm>();
                    }
                }

                inline PWTInstance(PWTInstance& other) noexcept {
                    CopyConstructor(other);
                }

                inline PWTInstance(PWTInstance&& other) noexcept {
                    MoveConstructor(std::forward<PWTInstance>(other));
                }

                inline PWTInstance& operator=(const PWTInstance& other) {
                    CopyConstructor(other);
                    return *this;
                }

                inline PWTInstance& operator=(PWTInstance&& other) noexcept {
                    MoveConstructor(std::forward<PWTInstance>(other));
                    return *this;
                }

                /**
                 * @brief Set the Typ object of the header.
                 *
                 * @param typ The typ value, which must be less than 255 characters.
                 * @return PWTInstance& The reference of the current instance.
                 */
                inline PWTInstance& SetType(const std::string& typ) noexcept {
                    if (typ.length() <= 255) {
                        this->header_->SetType(typ);
                    }
                    return *this;
                }

                inline PWTInstance& SetKeyID(const std::string& kid) noexcept {
                    this->header_->SetKeyID(kid);
                    return *this;
                }

                inline PWTInstance& SetPWK(const std::string& pwk) {
                    this->header_->SetPWK(pwk);
                    return *this;
                }

                inline PWTInstance& SetX5U(const std::string& x5u) {
                    this->header_->SetX5U(x5u);
                    return *this;
                }

                inline PWTInstance& SetHeaderCustomFields(const std::unordered_map<std::string, std::string>& custom_fields) {
                    this->header_->SetCustomFields(custom_fields);
                    return *this;
                }

                inline PWTInstance& SetHeaderCustomFields(const atomic_unordered_map<std::string, std::string>& custom_fields) {
                    this->header_->SetCustomFields(custom_fields);
                    return *this;
                }

                inline PWTInstance& AddHeaderCustomField(const std::string& key, const std::string& value) {
                    this->header_->AddCustomField(key, value);
                    return *this;
                }

                inline PWTInstance& SetCustomHeader(const ::google::protobuf::Any& custom_header) {
                    this->header_->SetCustomHeader(custom_header);
                    return *this;
                }

                inline PWTInstance& SetIssuer(const std::string& iss) {
                    this->payload_->SetIssuer(iss);
                    return *this;
                }

                inline PWTInstance& SetSubject(const std::string& sub) {
                    this->payload_->SetSubject(sub);
                    return *this;
                }
                /**
                 * @brief Set the Aud object of the payload.
                 *
                 * @note This method will replace the aud value of the payload.
                 */
                inline PWTInstance& SetAudience(const std::string& aud) {
                    this->payload_->SetAudience(aud);
                    return *this;
                }

                inline PWTInstance& SetAudience(const std::vector<std::string>& aud) {
                    this->payload_->SetAudience(aud);
                    return *this;
                }

                /**
                 * @brief Add the aud value to the aud vector of the payload.
                 * @note This method will add the aud value to the aud vector of the payload.
                 */
                inline PWTInstance& AddAudience(const std::string& aud) {
                    this->payload_->AddAudience(aud);
                    return *this;
                }

                /**
                 * @brief Add the aud values to the aud vector of the payload.
                 * @note This method will add the aud values to the aud vector of the payload.
                 */
                inline PWTInstance& AddAudience(const std::vector<std::string>& auds) {
                    this->payload_->AddAudience(auds);
                    return *this;
                }

                inline PWTInstance& SetExpirationTime(const unsigned& exp) {
                    this->payload_->SetExpirationTime(exp);
                    return *this;
                }

                inline PWTInstance& SetNotBeforeTime(const unsigned& nbf) {
                    this->payload_->SetNotBeforeTime(nbf);
                    return *this;
                }

                inline PWTInstance& SetIssuedAtTime(const unsigned& iat) {
                    this->payload_->SetIssuedAtTime(iat);
                    return *this;
                }

                inline PWTInstance& SetPayloadCutsomFields(const std::unordered_map<std::string, std::string>& custom_fields) {
                    this->payload_->SetCustomFields(custom_fields);
                    return *this;
                }

                inline PWTInstance& SetPayloadCutsomFields(const atomic_unordered_map<std::string, std::string>& custom_fields) {
                    this->payload_->SetCustomFields(custom_fields);
                    return *this;
                }

                inline PWTInstance& AddPayloadCustomField(const std::string& key, const std::string& value) {
                    this->payload_->AddCustomField(key, value);
                    return *this;
                }

                inline PWTInstance& SetCustomPayload(const ::google::protobuf::Any& custom_payload) {
                    this->payload_->SetCustomPayload(custom_payload);
                    return *this;
                }

                inline std::string GetType() const noexcept {
                    return this->header_->GetType();
                }

                inline std::string GetKeyID() const noexcept {
                    return this->header_->GetKeyID();
                }

                inline std::string GetPWK() const noexcept {
                    return this->header_->GetPWK();
                }

                inline std::string GetX5U() const noexcept {
                    return this->header_->GetX5U();
                }

                inline atomic_unordered_map<std::string, std::string> GetHeaderCustomFields() const noexcept {
                    return this->header_->GetCustomFields();
                }

                inline std::string GetHeaderCustomField(const std::string& key) const noexcept {
                    return this->header_->GetCustomField(key);
                }

                inline std::optional<::google::protobuf::Any> GetCustomHeader() const noexcept {
                    return this->header_->GetCustomHeader();
                }

                inline std::string GetIssuer() const noexcept {
                    return this->payload_->GetIssuer();
                }

                inline std::string GetSubject() const noexcept {
                    return this->payload_->GetSubject();
                }

                inline std::string GetAudience() const noexcept {
                    return this->payload_->GetAudience();
                }

                inline std::vector<std::string> GetAudiences() const noexcept {
                    return this->payload_->GetAudiences();
                }

                inline std::optional<::google::protobuf::Timestamp> GetExpirationTime() const noexcept {
                    return this->payload_->GetExpirationTime();
                }

                inline std::string GetExpirationTimeStr() const noexcept {
                    if (!this->payload_->GetExpirationTime().has_value()) {
                        return std::string();
                    }
                    return ::wind::utils::time::TimestampToString(this->payload_->GetExpirationTime().value());
                }

                inline std::optional<::google::protobuf::Timestamp> GetNotBeforeTime() const noexcept {
                    return this->payload_->GetNotBeforeTime();
                }

                inline std::string GetNotBeforeTimeStr() const noexcept {
                    if (!this->payload_->GetNotBeforeTime().has_value()) {
                        return std::string();
                    }
                    return ::wind::utils::time::TimestampToString(this->payload_->GetNotBeforeTime().value());
                }

                inline std::optional<::google::protobuf::Timestamp> GetIssuedAtTime() const noexcept {
                    return this->payload_->GetIssuedAtTime();
                }

                inline std::string GetIssuedAtTimeStr() const noexcept {
                    if (!this->payload_->GetIssuedAtTime().has_value()) {
                        return std::string();
                    }
                    return ::wind::utils::time::TimestampToString(this->payload_->GetIssuedAtTime().value());
                }

                inline atomic_unordered_map<std::string, std::string> GetPayloadCustomFields() const noexcept {
                    return this->payload_->GetCustomFields();
                }

                inline std::string GetPayloadCustomField(const std::string& key) const noexcept {
                    return this->payload_->GetCustomField(key);
                }

                inline std::optional<::google::protobuf::Any> GetCustomPayload() const noexcept {
                    return this->payload_->GetCustomPayload();
                }

                /**
                 * @brief Copy the algorithm from other.
                 *
                 * @param other Another PWTInstance.
                 */
                inline PWTInstance& CopyAlgorithm(const PWTInstance& other) noexcept {
                    if (this == &other) {
                        return *this;
                    }
                    std::shared_lock lock(other.crypto_mutex_);
                    std::unique_lock lock2(this->crypto_mutex_);
                    this->crypto_ = other.crypto_->Clone();
                    return *this;
                }

                inline PWTInstance& CopyAlgorithm(const std::shared_ptr<PWTInstance>& other) noexcept {
                    if (this == other.get()) {
                        return *this;
                    }
                    std::shared_lock lock(other->crypto_mutex_);
                    std::unique_lock lock2(this->crypto_mutex_);
                    this->crypto_ = other->crypto_->Clone();
                    return *this;
                }

                /**
                 * @brief Clone a PWTInstance.
                 *
                 * @return PWTInstance A new PWTInstance.
                 */
                inline PWTInstance Clone() const noexcept {
                    std::shared_lock lock(this->mutex_);
                    PWTInstance tmp;
                    tmp.header_ = this->header_->Clone();
                    tmp.payload_ = this->payload_->Clone();
                    tmp.crypto_ = this->crypto_->Clone();
                    return tmp;
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
             * @example
             * auto pwt = wind::utils::pwt::CreatePWTInstance();
             * auto pwt = wind::utils::pwt::CreatePWTInstance().SetTyp("PWT").Encode();
             */
            template <typename Header = PWTHeaderBase, typename Payload = PWTPayloadBase, typename Algorithm = ::wind::utils::encrypt::AlgorithmBase>
            inline PWTInstance<Header, Payload, Algorithm> CreatePWTInstance() noexcept {
                return PWTInstance<Header, Payload, Algorithm>();
            }

            /**
             * @brief A high-performance thread-safe pool of PWTInstance that
             * manages instances with the same header, payload, and algorithm.
             * The pool automatically creates and removes PWTInstance instances as needed,
             * and reuses them to minimize resource utilization and increase throughput.
             * It utilizes a highly efficient caching mechanism to speed up
             * instance creation and removal, further improving performance.
             * Additionally, the pool supports copying the algorithm from another pool
             * to avoid unnecessary initialization and setup, further enhancing performance.
             *
             * @tparam Header The template parameter of PWTInstance, which must be derived from PWTHeader.
             * @tparam Payload The template parameter of PWTInstance, which must be derived from PWTPayload.
             * @tparam Algorithm The template parameter of PWTInstance, which must be derived from Algorithm.
             *
             * @note For optimal performance, it is recommended to configure the pool
             * with an appropriate min and max size based on expected usage patterns.
             *
             * @todo Some functions of brief are not implemented.
             */
            template <typename Header = PWTHeaderBase, typename Payload = PWTPayloadBase, typename Algorithm = ::wind::utils::encrypt::AlgorithmBase>
            class PWTPool {
            private:
                using PWTInstanceType = PWTInstance<Header, Payload, Algorithm>;
                using PWTInstancePtr = std::shared_ptr<PWTInstanceType>;
                // Template PWT instance
                PWTInstanceType template_instance_;
                // Cache of PWT instances
                atomic_unordered_map<PWTInstancePtr, bool> used_instances_;
                atomic_unordered_map<PWTInstancePtr, bool> available_instances_;
                std::atomic_size_t max_size_;
                std::atomic_size_t current_size_;
                std::condition_variable cv_;
                std::shared_mutex mutex_;
                std::mutex cv_mutex_;

            public:
                inline explicit PWTPool(const size_t& max_size = 100) noexcept
                    : max_size_(max_size), current_size_(max_size / 2) {
                    static_assert(std::is_base_of_v<PWTHeader, Header>, "Header must be derived from PWTHeader");
                    static_assert(std::is_base_of_v<PWTPayload, Payload>, "Payload must be derived from PWTPayload");
                    static_assert(std::is_base_of_v<::wind::utils::encrypt::Algorithm, Algorithm>, "Algorithm must be derived from AlgorithmBase");
                    for (size_t i = 0; i < this->current_size_.load(); i++) {
                        this->available_instances_.insert(std::make_shared<PWTInstanceType>(template_instance_), true);
                    }
                }

                /**
                 * @brief Get a PWTInstance from the pool.
                 *
                 * @return PWTInstancePtr A shared pointer to the PWTInstance object.
                 */
                inline PWTInstancePtr Get() noexcept {
                    // Get the lock of the copy algorithm operation.
                    std::shared_lock lock(this->mutex_);
                    // If no available instances, check if the pool is full.
                    if (this->available_instances_.empty()) {
                        // If the pool is not full, create a new instance.
                        if (this->current_size_.fetch_add(1, std::memory_order_acquire) < this->max_size_.load(std::memory_order_acquire)) {
                            auto tmp = std::make_shared<PWTInstanceType>(template_instance_);
                            this->used_instances_.insert(tmp, true);
                            return tmp;
                        }
                        // Sub 1 if the pool is full.
                        this->current_size_.fetch_sub(1, std::memory_order_acquire);
                    }
                    // Try to get an available instance.
                    PWTInstancePtr tmp = this->available_instances_.pair_begin().first;
                    // If no available instance, wait for a signal.
                    while (!tmp) {
                        std::unique_lock lock_cv(this->cv_mutex_);
                        this->cv_.wait(lock_cv, [this]() {
                            return !this->available_instances_.empty();
                        });
                        lock_cv.unlock();
                        // Try to get an available instance again.
                        tmp = this->available_instances_.pair_begin().first;
                    }
                    this->used_instances_.insert(tmp, true);
                    return tmp;
                }

                /**
                 * @brief Put a PWTInstance back to the pool.
                 *
                 * @param instance A shared pointer to the PWTInstance object.
                 */
                inline PWTPool& Put(PWTInstancePtr& instance) noexcept {
                    // Get the lock of the copy algorithm operation.
                    std::shared_lock lock(this->mutex_);
                    // If the instance is not in the used_instances_ map, return.
                    if (!instance || !this->used_instances_.contains(instance)) {
                        return *this;
                    }
                    // Try to remove the instance from the used_instances_ map.
                    try {
                        this->used_instances_.erase(instance);
                    } catch (...) {
                        return *this;
                    }
                    // Add the instance to the available_instances_ map.
                    this->available_instances_.insert(instance, true);
                    // Notify the waiting threads.
                    this->cv_.notify_one();

                    return *this;
                }

                /**
                 * @brief Copy the algorithm from a PWTInstance.
                 *
                 * @param tmp A PWTInstance object.
                 *
                 * @note This will only be copied for available instances, make sure this function is called when all
                 * instances are available. This function will block all Get() and Put() operations until the copy is complete.
                 */
                inline PWTPool& CopyAlgorithm(const PWTInstancePtr& tmp) noexcept {
                    std::unique_lock lock(this->mutex_);
                    this->available_instances_.range([&](auto instance, auto _) {
                        instance->CopyAlgorithm(tmp);
                    });

                    return *this;
                }

                inline size_t GetMaxSize() const noexcept {
                    return this->max_size_.load();
                }

                inline size_t GetCurrentSize() const noexcept {
                    return this->current_size_.load();
                }

                inline size_t GetAvailableSize() const noexcept {
                    return this->available_instances_.size();
                }

                inline size_t GetUsedSize() const noexcept {
                    return this->used_instances_.size();
                }
            };
        }  // namespace pwt
    }      // namespace utils
}  // namespace wind