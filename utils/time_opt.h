/**
 * @file time_opt.h
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

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/time_util.h>

#include <chrono>
#include <ctime>
#include <string>

namespace wind {
    namespace utils {
        namespace time {
            /**
             * @brief Get a Timestamp object
             *
             * @param seconds The number of seconds to add to the current time
             * @return const ::google::protobuf::Timestamp
             */
            inline const ::google::protobuf::Timestamp GetTimestamp(const unsigned& seconds = 0) noexcept {
                const auto now = std::chrono::system_clock::now() + std::chrono::seconds(seconds);
                ::google::protobuf::Timestamp timestamp;
                timestamp.set_seconds(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
                timestamp.set_nanos(std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count() % 1000000000);

                return timestamp;
            }

            /**
             * @brief Convert a Timestamp object to a string
             *
             * @param timestamp The Timestamp object to be converted
             * @param remain The number of digits to remain after the decimal point
             * @return const std::string
             */
            inline const std::string TimestampToString(const ::google::protobuf::Timestamp& timestamp, size_t remain = 3) noexcept {
                std::time_t time = timestamp.seconds();

                char buffer[20];
                std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::gmtime(&time));

                std::string result(buffer);
                auto nanos = std::to_string(timestamp.nanos());
                if (nanos.size() > remain) {
                    nanos = nanos.substr(nanos.size() - remain);
                }
                std::string zeros(remain - nanos.size(), '0');
                result += "." + zeros + nanos;

                return result;
            }

            /**
             * @brief Get the Timestamp String object
             *
             * @param seconds The number of seconds to add to the current time
             * @param remain The number of digits to remain after the decimal point
             * @return const std::string
             *
             * @note Sample output: xxxx-xx-xx 00:00:00.000
             */
            inline const std::string GetTimestampString(const unsigned& seconds = 0, size_t remain = 3) noexcept {
                return TimestampToString(GetTimestamp(seconds), remain);
            }
        }  // namespace time
    }      // namespace utils
}  // namespace wind