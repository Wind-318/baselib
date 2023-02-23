#include "encrypt.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

TEST(EncryptTest, GenerateRandomStringTest) {
    EXPECT_NO_THROW(::wind::utils::encrypt::GenerateRandomString());
    EXPECT_NO_THROW(::wind::utils::encrypt::GenerateRandomString(12));
}

TEST(EncryptTest, AlgorithmBaseTest) {
    ::wind::utils::encrypt::AlgorithmBase alg;
    ::wind::utils::encrypt::AlgorithmBase alg1("data");
    ::wind::utils::encrypt::AlgorithmBase alg2(alg1);
    ::wind::utils::encrypt::AlgorithmBase alg3(std::move(alg2));
    auto alg4 = alg3;
    auto alg5 = std::move(alg4);
    EXPECT_THROW(alg.Encrypt(), std::invalid_argument);
    EXPECT_THROW(::wind::utils::encrypt::GenerateRandomString(0), std::invalid_argument);
    alg.key_ = "";
    EXPECT_THROW(alg.Encrypt(), std::invalid_argument);
}