#include "pwt.h"

#include <google/protobuf/any.h>
#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/json_util.h>
#include <gtest/gtest.h>

#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "encrypt.h"
#include "pwt_test.pb.h"

TEST(PWTTest, TestPWTHeader) {
    ::wind::utils::pwt::PWTHeaderBase header1;
    ::wind::utils::pwt::PWTHeaderBase header2(std::string("asd"), std::string("qwe"), std::string("zxc"), std::string("ggg"), std::unordered_map<std::string, std::string>({{"userid", "123456"}, {"username", "wind"}}), ::google::protobuf::Any());
    ::wind::utils::pwt::PWTHeaderBase header3(header2);
    EXPECT_NO_THROW(header1.Encode(););
    EXPECT_NO_THROW(header1 = header3;);
    header1 = header1;

    try {
        auto s = header1.Encode();
        if (!header1.Decode(s)) {
            std::cout << "decode failed" << std::endl;
        }
        std::cout << s << std::endl;
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }

    header1.custom_headers_ = std::nullopt;
    header2 = header1;
}

TEST(PWTTest, TestPWTPayload) {
    ::wind::utils::pwt::PWTPayloadBase payload1;
    ::wind::utils::pwt::PWTPayloadBase payload2(std::string("test1"), std::string("test2"), std::string("aud"), ::google::protobuf::Any(), 3600, 0, 0);
    ::wind::utils::pwt::PWTPayloadBase payload4(std::string("test1"), std::string("test2"), std::vector<std::string>{"aud1", "aud2", "aud3"}, ::google::protobuf::Any(), 3600, 0, 0);
    ::wind::utils::pwt::PWTPayloadBase payload3(payload2);
    payload3 = payload3;
    EXPECT_NO_THROW(payload1.Encode(););
    EXPECT_NO_THROW(payload1 = payload4;);

    try {
        auto s = payload1.Encode();
        if (!payload1.Decode(s)) {
            std::cout << "decode failed" << std::endl;
        }
        std::cout << s << std::endl;
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }

    payload1.custom_payloads_ = std::nullopt;
    ::wind::utils::pwt::PWTPayloadBase payload7(std::string("test1"), std::string("test2"), std::string("aud"), ::google::protobuf::Any(), 0, 3600, 3600);
    ::wind::utils::pwt::PWTPayloadBase payload8(std::string("test1"), std::string("test2"), std::vector<std::string>{"aud1", "aud2", "aud3"}, ::google::protobuf::Any(), 0, 3600, 0);
    payload1.exp_ = std::nullopt;
    payload1.IsExpired();
}

TEST(PWTTest, TestPWT) {
    ::wind::utils::pwt::PWTInstance pwt_ist1;
    auto header = std::make_unique<::wind::utils::pwt::PWTHeaderBase>();
    auto payload = std::make_unique<::wind::utils::pwt::PWTPayloadBase>();
    auto crypto = std::make_unique<::wind::utils::encrypt::AlgorithmBase>();
    ::wind::utils::pwt::PWTInstance pwt_ist2(std::move(header), std::move(payload), std::move(crypto));
    auto pwt_ist3(pwt_ist2);
    pwt_ist3 = pwt_ist2;
    pwt_ist3 = pwt_ist3;
    auto pwt_ist4(std::move(pwt_ist2));
    pwt_ist4 = std::move(pwt_ist3);
    auto pwt_ist5 = pwt_ist4.Clone();

    PWTMessageTest pwt_message;
    pwt_message.set_userid("123456");
    auto any = ::google::protobuf::Any();
    any.PackFrom(pwt_message);
    pwt_ist5.SetCustomPayload(any);
    auto s = pwt_ist5.Encode();
    std::cout << s << std::endl;
    if (!pwt_ist5.Decode(s)) {
        std::cout << "decode failed" << std::endl;
    }
    std::cout << pwt_ist5.IsExpired() << std::endl;
    std::cout << pwt_ist5.IsTokenValid(s) << std::endl;
    pwt_ist5.CopyAlgorithm(pwt_ist3);
    pwt_ist5.CopyAlgorithm(pwt_ist4);
    pwt_ist5.SetHeader(std::move(std::make_unique<::wind::utils::pwt::PWTHeaderBase>()));
    pwt_ist5.SetPayload(std::move(std::make_unique<::wind::utils::pwt::PWTPayloadBase>()));
    pwt_ist5.SetCrypto(std::move(std::make_unique<::wind::utils::encrypt::AlgorithmBase>()));
    pwt_ist5.SetCustomHeader(::google::protobuf::Any());
    pwt_ist5.SetCustomPayload(::google::protobuf::Any());

    try {
        std::cout << ::wind::utils::pwt::CreatePWTInstance()
                         .SetAud("aud")
                         .AddAud("aud1")
                         .SetAud("aud2")
                         .AddAud("aud3")
                         .AddAud(std::vector<std::string>{"aud4", "aud5"})
                         .AddAud("aud6")
                         .AddAud(std::vector<std::string>{"aud7", "aud8"})
                         .SetAud("aud9")
                         .AddAud(std::vector<std::string>{"aud10", "aud11"})
                         .SetExp(3600)
                         .AddHeaderCustomField("key1", "value1")
                         .AddPayloadCustomField("key2", "value2")
                         .SetX5u("x5u")
                         .SetTyp("typ")
                         .SetSub("sub")
                         .SetPwk("pwk")
                         .SetPayloadCutsomField(std::unordered_map<std::string, std::string>({{"key3", "value3"}, {"key4", "value4"}}))
                         .SetHeaderCustomField(std::unordered_map<std::string, std::string>({{"key5", "value5"}, {"key6", "value6"}}))
                         .SetNbf(0)
                         .SetKid("kid")
                         .SetIss("iss")
                         .SetIat(0)
                         .SetCustomPayload(any)
                         .SetCustomHeader(any)
                         .Encode();
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }

    auto algg = ::wind::utils::encrypt::AlgorithmBase();
    algg.data_ = "";
    pwt_ist5.SetCrypto(std::move(std::make_unique<::wind::utils::encrypt::AlgorithmBase>(algg)));
    pwt_ist5.Encode();
    pwt_ist5.SetCrypto(nullptr);
    EXPECT_THROW(pwt_ist5.Encode(), std::invalid_argument);
    pwt_ist5.SetHeader(nullptr);
    EXPECT_THROW(pwt_ist5.Encode(), std::invalid_argument);
    pwt_ist5.SetPayload(nullptr);
    EXPECT_THROW(pwt_ist5.Encode(), std::invalid_argument);
    pwt_ist5.Decode("");
    pwt_ist5.IsExpired();
    EXPECT_THROW(pwt_ist5.IsTokenValid(""), std::invalid_argument);
    pwt_ist5 = pwt_ist5;

    pwt_ist1.GetAud();
    pwt_ist1.GetExp();
    pwt_ist1.GetHeaderCustomField("key");
    pwt_ist1.GetPayloadCustomField("key");
    pwt_ist1.GetX5u();
    pwt_ist1.GetTyp();
    pwt_ist1.GetSub();
    pwt_ist1.GetPwk();
    pwt_ist1.GetNbf();
    pwt_ist1.GetKid();
    pwt_ist1.GetIss();
    pwt_ist1.GetIat();
    pwt_ist1.GetCustomPayload();
    pwt_ist1.GetCustomHeader();
    pwt_ist1.GetHeader();
    pwt_ist1.GetPayload();
    pwt_ist1.GetCrypto();
    pwt_ist1.GetHeaderCustomFields();
    pwt_ist1.GetPayloadCustomFields();

    try {
        std::cout << ::wind::utils::pwt::CreatePWTInstance()
                         .Encode();
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
}