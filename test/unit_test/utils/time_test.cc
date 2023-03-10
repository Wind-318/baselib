#include <gtest/gtest.h>

#include "time_opt.h"

TEST(GetTimestampTest, ReturnsValidTimestamp) {
    ASSERT_NO_THROW(::wind::utils::time::GetTimestamp());
}

TEST(GetTimestampTest, ReturnsValidTimestamp2) {
    ASSERT_NO_THROW(::wind::utils::time::GetTimestampString());
}

TEST(GetTimestampTest, ReturnsValidTimestamp3) {
    ASSERT_NO_THROW(::wind::utils::time::TimestampToString(::wind::utils::time::GetTimestamp()));
}