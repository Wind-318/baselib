#include "pwt.h"

#include <google/protobuf/any.h>
#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/util/json_util.h>
#include <gtest/gtest.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "encrypt.h"
#include "pwt_test.pb.h"

class PWTPoolTest : public testing::Test {
public:
    ::wind::utils::pwt::PWTPool<::wind::utils::pwt::PWTHeaderBase, ::wind::utils::pwt::PWTPayloadBase, ::wind::utils::encrypt::AlgorithmBase> pool_;
};

TEST_F(PWTPoolTest, BasicMethods) {
    // Test basic methods of PWT
    auto pwt = pool_.Get();
    ASSERT_NE(pwt, nullptr);
    pwt->SetAudience("audience");
    ASSERT_EQ(pwt->GetAudience(), "audience");
    pwt->SetAudience(std::vector<std::string>{"audience1", "audience2"});
    pwt->SetIssuer("issuer");
    ASSERT_EQ(pwt->GetIssuer(), "issuer");
    pwt->SetSubject("subject");
    ASSERT_EQ(pwt->GetSubject(), "subject");
    pwt->SetExpirationTime(123);
    ASSERT_EQ(pwt->GetExpirationTimeStr(), ::wind::utils::time::TimestampToString(pwt->GetExpirationTime().value()));
    pwt->SetIssuedAtTime(123);
    ASSERT_EQ(pwt->GetIssuedAtTimeStr(), ::wind::utils::time::TimestampToString(pwt->GetIssuedAtTime().value()));
    pwt->SetNotBeforeTime(123);
    ASSERT_EQ(pwt->GetNotBeforeTimeStr(), ::wind::utils::time::TimestampToString(pwt->GetNotBeforeTime().value()));
    pwt->SetX5U("x5u");
    ASSERT_EQ(pwt->GetX5U(), "x5u");
    pwt->SetType("type");
    ASSERT_EQ(pwt->GetType(), "type");
    pwt->SetPWK("pwk");
    ASSERT_EQ(pwt->GetPWK(), "pwk");
    pwt->SetKeyID("key_id");
    ASSERT_EQ(pwt->GetKeyID(), "key_id");

    auto custom_msg = PWTMessageTest();
    custom_msg.set_userid("userid");
    custom_msg.set_username("username");
    custom_msg.set_password("password");
    auto any = google::protobuf::Any();
    any.PackFrom(custom_msg);
    pwt->SetCustomHeader(any);
    ASSERT_EQ(pwt->GetCustomHeader().value().type_url(), "type.googleapis.com/PWTMessageTest");
    ASSERT_EQ(pwt->GetCustomHeader().value().UnpackTo(&custom_msg), true);
    ASSERT_EQ(custom_msg.userid(), "userid");
    ASSERT_EQ(custom_msg.username(), "username");
    ASSERT_EQ(custom_msg.password(), "password");
    pwt->SetCustomPayload(any);
    ASSERT_EQ(pwt->GetCustomPayload().value().type_url(), "type.googleapis.com/PWTMessageTest");
    ASSERT_EQ(pwt->GetCustomPayload().value().UnpackTo(&custom_msg), true);
    ASSERT_EQ(custom_msg.userid(), "userid");
    ASSERT_EQ(custom_msg.username(), "username");
    ASSERT_EQ(custom_msg.password(), "password");

    pwt->SetHeaderCustomFields({{"key1", "value1"}, {"key2", "value2"}});
    ASSERT_EQ(pwt->GetHeaderCustomFields().size(), 2);
    ASSERT_EQ(pwt->GetHeaderCustomFields().at("key1"), "value1");
    pwt->SetPayloadCutsomFields({{"key1", "value1"}, {"key2", "value2"}});
    ASSERT_EQ(pwt->GetPayloadCustomFields().size(), 2);
    pwt->AddHeaderCustomField("key3", "value3");
    ASSERT_EQ(pwt->GetHeaderCustomFields().size(), 3);
    pwt->AddPayloadCustomField("key3", "value3");
    ASSERT_EQ(pwt->GetPayloadCustomFields().size(), 3);

    pwt->AddAudience("audience");
    pwt->AddAudience("audience2");
    pwt->AddAudience(std::vector<std::string>({"audience3", "audience4"}));
    pwt->AddAudience("audience5");
    auto pwt2 = pool_.Get();
    ASSERT_NE(pwt2, nullptr);
    std::string token;
    try {
        token = pwt->Encode();
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
    }
    ASSERT_EQ(pwt2->Decode(token), true);
    ASSERT_EQ(pwt2->GetAudience(), pwt->GetAudience());
    ASSERT_EQ(pwt2->GetIssuer(), pwt->GetIssuer());
    ASSERT_EQ(pwt2->GetSubject(), pwt->GetSubject());
    ASSERT_EQ(pwt2->GetExpirationTime(), pwt->GetExpirationTime());
    ASSERT_EQ(pwt2->GetIssuedAtTime(), pwt->GetIssuedAtTime());
    ASSERT_EQ(pwt2->GetNotBeforeTime(), pwt->GetNotBeforeTime());
    ASSERT_EQ(pwt2->GetX5U(), pwt->GetX5U());
    ASSERT_EQ(pwt2->GetType(), pwt->GetType());
    ASSERT_EQ(pwt2->GetPWK(), pwt->GetPWK());
    ASSERT_EQ(pwt2->GetKeyID(), pwt->GetKeyID());
    ASSERT_EQ(pwt2->GetCustomHeader().value().type_url(), pwt->GetCustomHeader().value().type_url());
    ASSERT_EQ(pwt2->GetCustomHeader().value().UnpackTo(&custom_msg), true);
    ASSERT_EQ(custom_msg.userid(), "userid");
    ASSERT_EQ(custom_msg.username(), "username");
    ASSERT_EQ(custom_msg.password(), "password");
    ASSERT_EQ(pwt2->GetCustomPayload().value().type_url(), pwt->GetCustomPayload().value().type_url());
    ASSERT_EQ(pwt2->GetCustomPayload().value().UnpackTo(&custom_msg), true);
    ASSERT_EQ(custom_msg.userid(), "userid");
    ASSERT_EQ(custom_msg.username(), "username");
    ASSERT_EQ(custom_msg.password(), "password");
    ASSERT_EQ(pwt2->GetHeaderCustomFields().size(), pwt->GetHeaderCustomFields().size());
    ASSERT_EQ(pwt2->GetPayloadCustomFields().size(), pwt->GetPayloadCustomFields().size());
    ASSERT_EQ(pwt2->Decode(""), false);
    auto pwt3 = pool_.Get();
    ASSERT_NE(pwt3, nullptr);
    auto pwt4 = pool_.Get();
    ASSERT_NE(pwt4, nullptr);
    pwt3 = pwt3;
    pwt3 = std::move(pwt3);
    pwt3 = pwt2;
    auto tmp = pwt2->Clone();
    tmp = std::move(pwt2->Clone());
    ASSERT_EQ(pwt4->GetAudience(), "");
    ASSERT_EQ(pwt4->IsExpired(), false);
    ASSERT_EQ(pwt3->IsExpired(), false);
    ASSERT_EQ(pwt3->IsTokenValid(pwt->Encode()), true);
    ASSERT_EQ(pwt3->IsTokenValid(""), false);

    pool_.Put(pwt);
    pool_.Put(pwt2);
    pool_.Put(pwt3);
    pool_.Put(pwt4);
}

TEST_F(PWTPoolTest, GetAndPut) {
    // Check that the initial size of the pool is correct
    ASSERT_EQ(pool_.GetMaxSize(), 100);
    ASSERT_EQ(pool_.GetCurrentSize(), 50);
    ASSERT_EQ(pool_.GetAvailableSize(), 50);
    ASSERT_EQ(pool_.GetUsedSize(), 0);

    // Test Get() and Put() functions
    auto instance = pool_.Get();
    ASSERT_NE(instance, nullptr);
    ASSERT_EQ(pool_.GetCurrentSize(), 50);
    ASSERT_EQ(pool_.GetAvailableSize(), 49);
    ASSERT_EQ(pool_.GetUsedSize(), 1);

    pool_.Put(instance);
    ASSERT_EQ(pool_.GetCurrentSize(), 50);
    ASSERT_EQ(pool_.GetAvailableSize(), 50);
    ASSERT_EQ(pool_.GetUsedSize(), 0);

    instance = pool_.Get();
    ASSERT_NE(instance, nullptr);
    ASSERT_EQ(pool_.GetCurrentSize(), 50);
    ASSERT_EQ(pool_.GetAvailableSize(), 49);
    ASSERT_EQ(pool_.GetUsedSize(), 1);
}

TEST_F(PWTPoolTest, CopyAlgorithm) {
    // Test CopyAlgorithm() function
    ::wind::utils::pwt::PWTPool<::wind::utils::pwt::PWTHeaderBase, ::wind::utils::pwt::PWTPayloadBase, ::wind::utils::encrypt::AlgorithmBase> pool2(20);
    auto instance = pool_.Get();
    auto instance2 = pool2.Get();
    pool2.CopyAlgorithm(instance);
    pool2.Put(instance2);
    pool_.Put(instance);
}

TEST_F(PWTPoolTest, CreateNew) {
    std::vector<std::shared_ptr<wind::utils::pwt::PWTInstance<wind::utils::pwt::PWTHeaderBase, wind::utils::pwt::PWTPayloadBase, wind::utils::encrypt::AlgorithmBase>>> v;
    for (int i = 0; i < 100; i++) {
        auto tmp = pool_.Get();
        ASSERT_NE(tmp, nullptr);
        v.emplace_back(tmp);
    }
    ASSERT_EQ(pool_.GetCurrentSize(), 100);
    ASSERT_EQ(pool_.GetAvailableSize(), 0);
    ASSERT_EQ(pool_.GetUsedSize(), 100);

    // New thread to get instance
    std::thread t([&]() {
        auto tmp = pool_.Get();
        ASSERT_NE(tmp, nullptr);
        pool_.Put(tmp);
    });

    // New thread to put instance
    std::thread t2([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        for (auto& i : v) {
            pool_.Put(i);
        }
    });

    t.join();
    t2.join();

    ASSERT_EQ(pool_.GetCurrentSize(), 100);
    ASSERT_EQ(pool_.GetAvailableSize(), 100);
    ASSERT_EQ(pool_.GetUsedSize(), 0);
}

// Test multi-threading
TEST_F(PWTPoolTest, Multithreading) {
    ::wind::atomic_unordered_map<std::shared_ptr<wind::utils::pwt::PWTInstance<wind::utils::pwt::PWTHeaderBase, wind::utils::pwt::PWTPayloadBase, wind::utils::encrypt::AlgorithmBase>>, int> map;

    // 4 threads to get instance
    std::vector<std::thread> v1;
    for (int i = 0; i < 3; i++) {
        v1.emplace_back([&]() {
            for (int i = 0; i < 50; i++) {
                auto tmp = pool_.Get();
                ASSERT_NE(tmp, nullptr);
                map.insert(tmp, i);
            }
        });
    }

    // 4 threads to put instance
    std::vector<std::thread> v2;
    for (int i = 0; i < 3; i++) {
        v2.emplace_back([&]() {
            for (int i = 0; i < 10; i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
                while (!map.empty()) {
                    auto tmp = map.pair_begin();
                    std::string token;
                    ASSERT_NO_THROW(token = tmp.first->Encode());
                    ASSERT_EQ(tmp.first->Decode(token), true);
                    pool_.Put(tmp.first);
                }
            }
        });
    }

    for (auto& i : v1) {
        i.join();
    }
    for (auto& i : v2) {
        i.join();
    }
    while (!map.empty()) {
        auto tmp = map.pair_begin();
        pool_.Put(tmp.first);
    }

    ASSERT_LE(pool_.GetCurrentSize(), 100);
    ASSERT_EQ(pool_.GetAvailableSize(), pool_.GetCurrentSize());
    ASSERT_EQ(pool_.GetUsedSize(), 0);
}