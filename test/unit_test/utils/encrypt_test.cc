#include "encrypt.h"

#include <gtest/gtest.h>

TEST(EncryptTest, GenerateRandomString) {
    std::string str = wind::utils::encrypt::GenerateRandomString();
    ASSERT_EQ(str.size(), 64);
    ASSERT_THROW(wind::utils::encrypt::GenerateRandomString(0), std::invalid_argument);
}

TEST(EncryptTest, AlgorithmBase) {
    wind::utils::encrypt::AlgorithmBase algorithm;
    ASSERT_NE(algorithm.GetKey(), "");
    ASSERT_NE(algorithm.GetIV(), "");
    ASSERT_NE(algorithm.GetSalt(), "");
    algorithm.SetKey("key");
    algorithm.SetIV("iv");
    algorithm.SetSalt("salt");
    ASSERT_EQ(algorithm.GetKey(), "key");
    ASSERT_EQ(algorithm.GetIV(), "iv");
    ASSERT_EQ(algorithm.GetSalt(), "salt");
    wind::utils::encrypt::AlgorithmBase algorithm2(algorithm);
    ASSERT_EQ(algorithm2.GetKey(), "key");
    ASSERT_EQ(algorithm2.GetIV(), "iv");
    ASSERT_EQ(algorithm2.GetSalt(), "salt");
    wind::utils::encrypt::AlgorithmBase algorithm3(std::move(algorithm));
    ASSERT_EQ(algorithm3.GetKey(), "key");
    ASSERT_EQ(algorithm3.GetIV(), "iv");
    ASSERT_EQ(algorithm3.GetSalt(), "salt");
    algorithm2 = algorithm2;
    algorithm2 = std::move(algorithm2);
    algorithm2 = algorithm3;
    ASSERT_EQ(algorithm2.GetKey(), "key");
    ASSERT_EQ(algorithm2.GetIV(), "iv");
    ASSERT_EQ(algorithm2.GetSalt(), "salt");
    auto algorithm4 = algorithm3;
    algorithm2 = std::move(algorithm3);
    ASSERT_EQ(algorithm2.GetKey(), "key");
    ASSERT_EQ(algorithm2.GetIV(), "iv");
    ASSERT_EQ(algorithm2.GetSalt(), "salt");
}

TEST(EncryptTest, Encrypt) {
    wind::utils::encrypt::AlgorithmBase algorithm;
    ASSERT_NO_THROW(algorithm.Encrypt("test"));
    ASSERT_THROW(algorithm.Encrypt(""), std::invalid_argument);
    algorithm.SetKey("");
    ASSERT_THROW(algorithm.Encrypt("test"), std::invalid_argument);
}