#include <encrypt.h>
#include <google/protobuf/any.h>
#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/json_util.h>
#include <gtest/gtest.h>
#include <jwt-cpp/jwt.h>
#include <pwt.h>

#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

#include "pwt_test.pb.h"

TEST(PWTTest, Test1) {
    std::unordered_map<std::string, std::string> claims;
    claims["userid"] = "123456";
    ::google::protobuf::Any any;
    PWTMessageTest pwt_message_test;
    try {
        pwt_message_test.set_password("123456");
        pwt_message_test.set_userid("123456");
        pwt_message_test.set_username("wind");

        auto timestamp = ::google::protobuf::Timestamp();
        pwt_message_test.set_allocated_timestamp(&timestamp);
        any.PackFrom(pwt_message_test);
        auto _ = pwt_message_test.release_timestamp();
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }

    auto tmp = ::wind::utils::pwt::CreatePWTInstance();
    auto s = tmp.SetHeaderCustomField(claims)
                 .AddHeaderCustomField("alg", "HS256")
                 .SetPayloadCutsomField(claims)
                 .AddPayloadCustomField("alg", "HS256")
                 .SetCustomHeader(any)
                 .SetCustomPayload(any)
                 .SetExp(3600)
                 .SetIat(0)
                 .SetIss("wind")
                 .SetSub("wind")
                 .SetAud("wind")
                 .SetNbf(0)
                 .AddAud("wind")
                 .SetAud("wind")
                 .AddAud("wind")
                 .SetAud("wind")
                 .AddAud(std::vector<std::string>())
                 .SetKid("wind")
                 .SetPwk("wind")
                 .SetTyp("wind")
                 .SetX5u("wind")
                 .Encode();
    EXPECT_NO_THROW(tmp.IsTokenValid(s));
    EXPECT_NO_THROW(tmp.IsTokenValid(std::string("data")));

    EXPECT_NO_THROW(::wind::utils::pwt::PWTHeaderBase());
    auto header = ::wind::utils::pwt::PWTHeaderBase();
    EXPECT_NO_THROW(::wind::utils::pwt::PWTHeaderBase(header));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTHeaderBase(std::move(header)));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTHeaderBase(std::string("data"), std::string("data"), std::string("data"), std::string("data")));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTPayloadBase());
    auto payload = ::wind::utils::pwt::PWTPayloadBase();
    EXPECT_NO_THROW(::wind::utils::pwt::PWTPayloadBase(payload));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTPayloadBase(std::move(payload)));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTPayloadBase(std::string("data"), std::string("data"), std::string("data")));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTPayloadBase(std::string("data"), std::string("data"), std::vector<std::string>()));

    auto hd = std::make_unique<::wind::utils::pwt::PWTHeaderBase>(std::string("data"), std::string("data"), std::string("data"), std::string("data"));
    auto pl = std::make_unique<::wind::utils::pwt::PWTPayloadBase>(std::string("data"), std::string("data"), std::string("data"));
    auto ct = std::make_unique<::wind::utils::encrypt::AlgorithmBase>(std::string(), std::string("data"), std::string("data"), std::string("data"));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTInstance(std::move(hd), std::move(pl), std::move(ct)));

    auto PWTI = ::wind::utils::pwt::PWTInstance();
    EXPECT_NO_THROW(::wind::utils::pwt::PWTInstance(PWTI));
    EXPECT_NO_THROW(::wind::utils::pwt::PWTInstance(std::move(PWTI)));
    EXPECT_NO_THROW(PWTI = ::wind::utils::pwt::PWTInstance());
    EXPECT_NO_THROW(PWTI = std::move(::wind::utils::pwt::PWTInstance()));

    auto PWTH = ::wind::utils::pwt::PWTHeaderBase();
    EXPECT_NO_THROW(PWTH = ::wind::utils::pwt::PWTHeaderBase());
}

TEST(PWTTest, Test3) {
    auto pp = ::wind::utils::pwt::CreatePWTInstance();
    auto ppp = ::wind::utils::pwt::CreatePWTInstance();
    pp = std::move(ppp);  // This was the bug
    auto ppTmp2 = std::move(ppp);
    auto tmp1 = ::wind::utils::pwt::PWTHeaderBase();
    auto tmp2 = ::wind::utils::pwt::PWTPayloadBase();
    auto tmp3 = tmp1;
    auto tmp33 = tmp1;
    tmp3 = std::move(tmp33);
    auto tmp4 = tmp2;
    auto tmp44 = tmp2;
    tmp4 = std::move(tmp44);
    auto tmp5 = std::move(tmp1);
    auto tmp6 = std::move(tmp2);
    auto tmp7(std::move(tmp5));
    auto tmp8(std::move(tmp6));
    auto tmp9(std::move(pp));
    pp.GetTyp();
    pp.GetKid();
    pp.GetPwk();
    pp.GetX5u();
    pp.GetHeader();
    pp.GetPayload();
    pp.GetCustomHeader();
    pp.GetCustomPayload();
    pp.GetCustomHeader();
    pp.GetCustomPayload();
    pp.GetHeaderCustomFields();
    pp.GetHeaderCustomField("key");
    pp.GetPayloadCustomFields();
    pp.GetPayloadCustomField("key");
    pp.GetIss();
    pp.GetSub();
    pp.GetAud();
    pp.GetAuds();
    pp.GetExp();
    pp.GetNbf();
    pp.GetIat();
    pp.GetExpStr();
    pp.GetNbfStr();
    pp.GetIatStr();
    auto tmp = ::wind::utils::pwt::CreatePWTInstance();
    auto algg = tmp.GetCrypto();
    auto alg = std::make_unique<::wind::utils::encrypt::AlgorithmBase>(std::string(), algg->key_, algg->iv_, algg->salt_);
    pp.SetCrypto(std::move(alg));
    pp.CopyAlgorithm(tmp);
    auto s = tmp.Encode();
    auto f = pp.Decode(s);
    auto headers = pp.GetHeader();
    auto payloads = pp.GetPayload();
    auto custom_header = pp.GetCustomHeader();
    auto custom_payload = pp.GetCustomPayload();

    auto pwt_msg_test = PWTMessageTest();
    if (custom_header.has_value()) {
        custom_header->UnpackTo(&pwt_msg_test);
    }
}