// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: pwt_test.proto

#include "pwt_test.pb.h"

#include <algorithm>
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/extension_set.h"
#include "google/protobuf/wire_format_lite.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/generated_message_reflection.h"
#include "google/protobuf/reflection_ops.h"
#include "google/protobuf/wire_format.h"
#include "google/protobuf/generated_message_tctable_impl.h"
// @@protoc_insertion_point(includes)

// Must be included last.
#include "google/protobuf/port_def.inc"
PROTOBUF_PRAGMA_INIT_SEG
namespace _pb = ::google::protobuf;
namespace _pbi = ::google::protobuf::internal;
namespace _fl = ::google::protobuf::internal::field_layout;
        template <typename>
PROTOBUF_CONSTEXPR PWTMessageTest::PWTMessageTest(::_pbi::ConstantInitialized)
    : _impl_{
      /*decltype(_impl_._has_bits_)*/ {},
      /*decltype(_impl_._cached_size_)*/ {},
      /*decltype(_impl_.userid_)*/ {
          &::_pbi::fixed_address_empty_string,
          ::_pbi::ConstantInitialized{},
      },
      /*decltype(_impl_.username_)*/ {
          &::_pbi::fixed_address_empty_string,
          ::_pbi::ConstantInitialized{},
      },
      /*decltype(_impl_.password_)*/ {
          &::_pbi::fixed_address_empty_string,
          ::_pbi::ConstantInitialized{},
      },
      /*decltype(_impl_.timestamp_)*/ nullptr,
    } {}
struct PWTMessageTestDefaultTypeInternal {
  PROTOBUF_CONSTEXPR PWTMessageTestDefaultTypeInternal() : _instance(::_pbi::ConstantInitialized{}) {}
  ~PWTMessageTestDefaultTypeInternal() {}
  union {
    PWTMessageTest _instance;
  };
};

PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT
    PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 PWTMessageTestDefaultTypeInternal _PWTMessageTest_default_instance_;
static ::_pb::Metadata file_level_metadata_pwt_5ftest_2eproto[1];
static constexpr const ::_pb::EnumDescriptor**
    file_level_enum_descriptors_pwt_5ftest_2eproto = nullptr;
static constexpr const ::_pb::ServiceDescriptor**
    file_level_service_descriptors_pwt_5ftest_2eproto = nullptr;
const ::uint32_t TableStruct_pwt_5ftest_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(
    protodesc_cold) = {
    PROTOBUF_FIELD_OFFSET(::PWTMessageTest, _impl_._has_bits_),
    PROTOBUF_FIELD_OFFSET(::PWTMessageTest, _internal_metadata_),
    ~0u,  // no _extensions_
    ~0u,  // no _oneof_case_
    ~0u,  // no _weak_field_map_
    ~0u,  // no _inlined_string_donated_
    ~0u,  // no _split_
    ~0u,  // no sizeof(Split)
    PROTOBUF_FIELD_OFFSET(::PWTMessageTest, _impl_.userid_),
    PROTOBUF_FIELD_OFFSET(::PWTMessageTest, _impl_.username_),
    PROTOBUF_FIELD_OFFSET(::PWTMessageTest, _impl_.password_),
    PROTOBUF_FIELD_OFFSET(::PWTMessageTest, _impl_.timestamp_),
    ~0u,
    ~0u,
    ~0u,
    0,
};

static const ::_pbi::MigrationSchema
    schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
        {0, 12, -1, sizeof(::PWTMessageTest)},
};

static const ::_pb::Message* const file_default_instances[] = {
    &::_PWTMessageTest_default_instance_._instance,
};
const char descriptor_table_protodef_pwt_5ftest_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
    "\n\016pwt_test.proto\032\037google/protobuf/timest"
    "amp.proto\"s\n\016PWTMessageTest\022\016\n\006userid\030\001 "
    "\001(\t\022\020\n\010username\030\002 \001(\t\022\020\n\010password\030\003 \001(\t\022"
    "-\n\ttimestamp\030\004 \001(\0132\032.google.protobuf.Tim"
    "estampb\006proto3"
};
static const ::_pbi::DescriptorTable* const descriptor_table_pwt_5ftest_2eproto_deps[1] =
    {
        &::descriptor_table_google_2fprotobuf_2ftimestamp_2eproto,
};
static ::absl::once_flag descriptor_table_pwt_5ftest_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_pwt_5ftest_2eproto = {
    false,
    false,
    174,
    descriptor_table_protodef_pwt_5ftest_2eproto,
    "pwt_test.proto",
    &descriptor_table_pwt_5ftest_2eproto_once,
    descriptor_table_pwt_5ftest_2eproto_deps,
    1,
    1,
    schemas,
    file_default_instances,
    TableStruct_pwt_5ftest_2eproto::offsets,
    file_level_metadata_pwt_5ftest_2eproto,
    file_level_enum_descriptors_pwt_5ftest_2eproto,
    file_level_service_descriptors_pwt_5ftest_2eproto,
};

// This function exists to be marked as weak.
// It can significantly speed up compilation by breaking up LLVM's SCC
// in the .pb.cc translation units. Large translation units see a
// reduction of more than 35% of walltime for optimized builds. Without
// the weak attribute all the messages in the file, including all the
// vtables and everything they use become part of the same SCC through
// a cycle like:
// GetMetadata -> descriptor table -> default instances ->
//   vtables -> GetMetadata
// By adding a weak function here we break the connection from the
// individual vtables back into the descriptor table.
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_pwt_5ftest_2eproto_getter() {
  return &descriptor_table_pwt_5ftest_2eproto;
}
// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2
static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_pwt_5ftest_2eproto(&descriptor_table_pwt_5ftest_2eproto);
// ===================================================================

class PWTMessageTest::_Internal {
 public:
  using HasBits = decltype(std::declval<PWTMessageTest>()._impl_._has_bits_);
  static constexpr ::int32_t kHasBitsOffset =
    8 * PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_._has_bits_);
  static const ::google::protobuf::Timestamp& timestamp(const PWTMessageTest* msg);
  static void set_has_timestamp(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
};

const ::google::protobuf::Timestamp& PWTMessageTest::_Internal::timestamp(const PWTMessageTest* msg) {
  return *msg->_impl_.timestamp_;
}
void PWTMessageTest::clear_timestamp() {
  if (_impl_.timestamp_ != nullptr) _impl_.timestamp_->Clear();
  _impl_._has_bits_[0] &= ~0x00000001u;
}
PWTMessageTest::PWTMessageTest(::google::protobuf::Arena* arena)
    : ::google::protobuf::Message(arena) {
  SharedCtor(arena);
  // @@protoc_insertion_point(arena_constructor:PWTMessageTest)
}
PWTMessageTest::PWTMessageTest(const PWTMessageTest& from) : ::google::protobuf::Message() {
  PWTMessageTest* const _this = this;
  (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){from._impl_._has_bits_},
      /*decltype(_impl_._cached_size_)*/ {},
      decltype(_impl_.userid_){},
      decltype(_impl_.username_){},
      decltype(_impl_.password_){},
      decltype(_impl_.timestamp_){nullptr},
  };
  _internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(
      from._internal_metadata_);
  _impl_.userid_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        _impl_.userid_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_userid().empty()) {
    _this->_impl_.userid_.Set(from._internal_userid(), _this->GetArenaForAllocation());
  }
  _impl_.username_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        _impl_.username_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_username().empty()) {
    _this->_impl_.username_.Set(from._internal_username(), _this->GetArenaForAllocation());
  }
  _impl_.password_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        _impl_.password_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_password().empty()) {
    _this->_impl_.password_.Set(from._internal_password(), _this->GetArenaForAllocation());
  }
  if ((from._impl_._has_bits_[0] & 0x00000001u) != 0) {
    _this->_impl_.timestamp_ = new ::google::protobuf::Timestamp(*from._impl_.timestamp_);
  }

  // @@protoc_insertion_point(copy_constructor:PWTMessageTest)
}
inline void PWTMessageTest::SharedCtor(::_pb::Arena* arena) {
  (void)arena;
  new (&_impl_) Impl_{
      decltype(_impl_._has_bits_){},
      /*decltype(_impl_._cached_size_)*/ {},
      decltype(_impl_.userid_){},
      decltype(_impl_.username_){},
      decltype(_impl_.password_){},
      decltype(_impl_.timestamp_){nullptr},
  };
  _impl_.userid_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        _impl_.userid_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.username_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        _impl_.username_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  _impl_.password_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
        _impl_.password_.Set("", GetArenaForAllocation());
  #endif  // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}
PWTMessageTest::~PWTMessageTest() {
  // @@protoc_insertion_point(destructor:PWTMessageTest)
  _internal_metadata_.Delete<::google::protobuf::UnknownFieldSet>();
  SharedDtor();
}
inline void PWTMessageTest::SharedDtor() {
  ABSL_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.userid_.Destroy();
  _impl_.username_.Destroy();
  _impl_.password_.Destroy();
  if (this != internal_default_instance()) delete _impl_.timestamp_;
}
void PWTMessageTest::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

PROTOBUF_NOINLINE void PWTMessageTest::Clear() {
// @@protoc_insertion_point(message_clear_start:PWTMessageTest)
  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.userid_.ClearToEmpty();
  _impl_.username_.ClearToEmpty();
  _impl_.password_.ClearToEmpty();
  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    ABSL_DCHECK(_impl_.timestamp_ != nullptr);
    _impl_.timestamp_->Clear();
  }
  _impl_._has_bits_.Clear();
  _internal_metadata_.Clear<::google::protobuf::UnknownFieldSet>();
}

const char* PWTMessageTest::_InternalParse(
    const char* ptr, ::_pbi::ParseContext* ctx) {
  ptr = ::_pbi::TcParser::ParseLoop(this, ptr, ctx, &_table_.header);
  return ptr;
}


PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1
const ::_pbi::TcParseTable<2, 4, 1, 45, 2> PWTMessageTest::_table_ = {
  {
    PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_._has_bits_),
    0, // no _extensions_
    4, 24,  // max_field_number, fast_idx_mask
    offsetof(decltype(_table_), field_lookup_table),
    4294967280,  // skipmap
    offsetof(decltype(_table_), field_entries),
    4,  // num_field_entries
    1,  // num_aux_entries
    offsetof(decltype(_table_), aux_entries),
    &_PWTMessageTest_default_instance_._instance,
    ::_pbi::TcParser::GenericFallback,  // fallback
  }, {{
    // .google.protobuf.Timestamp timestamp = 4;
    {::_pbi::TcParser::FastMtS1,
     {34, 0, 0, PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.timestamp_)}},
    // string userid = 1;
    {::_pbi::TcParser::FastUS1,
     {10, 63, 0, PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.userid_)}},
    // string username = 2;
    {::_pbi::TcParser::FastUS1,
     {18, 63, 0, PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.username_)}},
    // string password = 3;
    {::_pbi::TcParser::FastUS1,
     {26, 63, 0, PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.password_)}},
  }}, {{
    65535, 65535
  }}, {{
    // string userid = 1;
    {PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.userid_), -1, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
    // string username = 2;
    {PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.username_), -1, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
    // string password = 3;
    {PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.password_), -1, 0,
    (0 | ::_fl::kFcSingular | ::_fl::kUtf8String | ::_fl::kRepAString)},
    // .google.protobuf.Timestamp timestamp = 4;
    {PROTOBUF_FIELD_OFFSET(PWTMessageTest, _impl_.timestamp_), _Internal::kHasBitsOffset + 0, 0,
    (0 | ::_fl::kFcOptional | ::_fl::kMessage | ::_fl::kTvTable)},
  }}, {{
    {::_pbi::TcParser::GetTable<::google::protobuf::Timestamp>()},
  }}, {{
    "\16\6\10\10\0\0\0\0"
    "PWTMessageTest"
    "userid"
    "username"
    "password"
  }},
};

::uint8_t* PWTMessageTest::_InternalSerialize(
    ::uint8_t* target,
    ::google::protobuf::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:PWTMessageTest)
  ::uint32_t cached_has_bits = 0;
  (void)cached_has_bits;

  // string userid = 1;
  if (!this->_internal_userid().empty()) {
    const std::string& _s = this->_internal_userid();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "PWTMessageTest.userid");
    target = stream->WriteStringMaybeAliased(1, _s, target);
  }

  // string username = 2;
  if (!this->_internal_username().empty()) {
    const std::string& _s = this->_internal_username();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "PWTMessageTest.username");
    target = stream->WriteStringMaybeAliased(2, _s, target);
  }

  // string password = 3;
  if (!this->_internal_password().empty()) {
    const std::string& _s = this->_internal_password();
    ::google::protobuf::internal::WireFormatLite::VerifyUtf8String(
        _s.data(), static_cast<int>(_s.length()), ::google::protobuf::internal::WireFormatLite::SERIALIZE, "PWTMessageTest.password");
    target = stream->WriteStringMaybeAliased(3, _s, target);
  }

  cached_has_bits = _impl_._has_bits_[0];
  // .google.protobuf.Timestamp timestamp = 4;
  if (cached_has_bits & 0x00000001u) {
    target = ::google::protobuf::internal::WireFormatLite::
      InternalWriteMessage(4, _Internal::timestamp(this),
        _Internal::timestamp(this).GetCachedSize(), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target =
        ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
            _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:PWTMessageTest)
  return target;
}

::size_t PWTMessageTest::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:PWTMessageTest)
  ::size_t total_size = 0;

  ::uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string userid = 1;
  if (!this->_internal_userid().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_userid());
  }

  // string username = 2;
  if (!this->_internal_username().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_username());
  }

  // string password = 3;
  if (!this->_internal_password().empty()) {
    total_size += 1 + ::google::protobuf::internal::WireFormatLite::StringSize(
                                    this->_internal_password());
  }

  // .google.protobuf.Timestamp timestamp = 4;
  cached_has_bits = _impl_._has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::MessageSize(
        *_impl_.timestamp_);
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::google::protobuf::Message::ClassData PWTMessageTest::_class_data_ = {
    ::google::protobuf::Message::CopyWithSourceCheck,
    PWTMessageTest::MergeImpl
};
const ::google::protobuf::Message::ClassData*PWTMessageTest::GetClassData() const { return &_class_data_; }


void PWTMessageTest::MergeImpl(::google::protobuf::Message& to_msg, const ::google::protobuf::Message& from_msg) {
  auto* const _this = static_cast<PWTMessageTest*>(&to_msg);
  auto& from = static_cast<const PWTMessageTest&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:PWTMessageTest)
  ABSL_DCHECK_NE(&from, _this);
  ::uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_userid().empty()) {
    _this->_internal_set_userid(from._internal_userid());
  }
  if (!from._internal_username().empty()) {
    _this->_internal_set_username(from._internal_username());
  }
  if (!from._internal_password().empty()) {
    _this->_internal_set_password(from._internal_password());
  }
  if ((from._impl_._has_bits_[0] & 0x00000001u) != 0) {
    _this->_internal_mutable_timestamp()->::google::protobuf::Timestamp::MergeFrom(
        from._internal_timestamp());
  }
  _this->_internal_metadata_.MergeFrom<::google::protobuf::UnknownFieldSet>(from._internal_metadata_);
}

void PWTMessageTest::CopyFrom(const PWTMessageTest& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:PWTMessageTest)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

PROTOBUF_NOINLINE bool PWTMessageTest::IsInitialized() const {
  return true;
}

void PWTMessageTest::InternalSwap(PWTMessageTest* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_._has_bits_[0], other->_impl_._has_bits_[0]);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.userid_, lhs_arena,
                                       &other->_impl_.userid_, rhs_arena);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.username_, lhs_arena,
                                       &other->_impl_.username_, rhs_arena);
  ::_pbi::ArenaStringPtr::InternalSwap(&_impl_.password_, lhs_arena,
                                       &other->_impl_.password_, rhs_arena);
  swap(_impl_.timestamp_, other->_impl_.timestamp_);
}

::google::protobuf::Metadata PWTMessageTest::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_pwt_5ftest_2eproto_getter, &descriptor_table_pwt_5ftest_2eproto_once,
      file_level_metadata_pwt_5ftest_2eproto[0]);
}
// @@protoc_insertion_point(namespace_scope)
namespace google {
namespace protobuf {
}  // namespace protobuf
}  // namespace google
// @@protoc_insertion_point(global_scope)
#include "google/protobuf/port_undef.inc"
