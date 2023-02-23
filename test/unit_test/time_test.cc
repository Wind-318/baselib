#include <gtest/gtest.h>

#include "time_opt.h"

TEST(GetTimestampTest, ReturnsValidTimestamp) {
    EXPECT_NO_THROW(::wind::utils::time::GetTimestamp());
}

TEST(GetTimestampTest, ReturnsValidTimestamp2) {
    EXPECT_NO_THROW(::wind::utils::time::GetTimestampString());
}

TEST(GetTimestampTest, ReturnsValidTimestamp3) {
    EXPECT_NO_THROW(::wind::utils::time::TimestampToString(::wind::utils::time::GetTimestamp()));
}