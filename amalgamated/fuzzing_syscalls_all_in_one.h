#ifndef CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_
#define CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_

/* CKB script visible fuzzing APIs */
/* Start of fuzzing_syscalls.h */
#ifndef CKB_FUZZING_SYSCALLS_H_
#define CKB_FUZZING_SYSCALLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CKB_C_STDLIB_CKB_SYSCALLS_H_) || \
    defined(CKB_C_STDLIB_CKB_RAW_SYSCALLS_H_)
#error \
    "fuzzing_syscalls.h cannot be used with ckb_syscalls.h, please use ckb_syscall_apis.h instead."
#endif

/* main function in actual CKB script will be rewritten to this name. */
#ifndef CKB_FUZZING_ENTRYPOINT
#define CKB_FUZZING_ENTRYPOINT _ckb_fuzzing_entrypoint
#endif

/* A special error code used by fuzzing engine. */
#ifndef CKB_FUZZING_UNEXPECTED
#define CKB_FUZZING_UNEXPECTED 19
#endif

/* Start of ckb_consts.h */
#ifndef CKB_C_STDLIB_CKB_CONSTS_H_
#define CKB_C_STDLIB_CKB_CONSTS_H_

#define SYS_exit 93
#define SYS_ckb_vm_version 2041
#define SYS_ckb_current_cycles 2042
#define SYS_ckb_exec 2043
#define SYS_ckb_load_transaction 2051
#define SYS_ckb_load_script 2052
#define SYS_ckb_load_tx_hash 2061
#define SYS_ckb_load_script_hash 2062
#define SYS_ckb_load_cell 2071
#define SYS_ckb_load_header 2072
#define SYS_ckb_load_input 2073
#define SYS_ckb_load_witness 2074
#define SYS_ckb_load_cell_by_field 2081
#define SYS_ckb_load_header_by_field 2082
#define SYS_ckb_load_input_by_field 2083
#define SYS_ckb_load_cell_data_as_code 2091
#define SYS_ckb_load_cell_data 2092
#define SYS_ckb_debug 2177
#define SYS_ckb_load_block_extension 2104
#define SYS_ckb_spawn 2601
#define SYS_ckb_wait 2602
#define SYS_ckb_process_id 2603
#define SYS_ckb_pipe 2604
#define SYS_ckb_write 2605
#define SYS_ckb_read 2606
#define SYS_ckb_inherited_fds 2607
#define SYS_ckb_close 2608

#define CKB_SUCCESS 0
#define CKB_INDEX_OUT_OF_BOUND 1
#define CKB_ITEM_MISSING 2
#define CKB_LENGTH_NOT_ENOUGH 3
#define CKB_INVALID_DATA 4
#define CKB_WAIT_FAILURE 5
#define CKB_INVALID_FD 6
#define CKB_OTHER_END_CLOSED 7
#define CKB_MAX_VMS_SPAWNED 8
#define CKB_MAX_FDS_CREATED 9

#define CKB_SOURCE_INPUT 1
#define CKB_SOURCE_OUTPUT 2
#define CKB_SOURCE_CELL_DEP 3
#define CKB_SOURCE_HEADER_DEP 4
#define CKB_SOURCE_GROUP_INPUT 0x0100000000000001
#define CKB_SOURCE_GROUP_OUTPUT 0x0100000000000002

#define CKB_CELL_FIELD_CAPACITY 0
#define CKB_CELL_FIELD_DATA_HASH 1
#define CKB_CELL_FIELD_LOCK 2
#define CKB_CELL_FIELD_LOCK_HASH 3
#define CKB_CELL_FIELD_TYPE 4
#define CKB_CELL_FIELD_TYPE_HASH 5
#define CKB_CELL_FIELD_OCCUPIED_CAPACITY 6

#define CKB_HEADER_FIELD_EPOCH_NUMBER 0
#define CKB_HEADER_FIELD_EPOCH_START_BLOCK_NUMBER 1
#define CKB_HEADER_FIELD_EPOCH_LENGTH 2

#define CKB_INPUT_FIELD_OUT_POINT 0
#define CKB_INPUT_FIELD_SINCE 1

#endif /* CKB_C_STDLIB_CKB_CONSTS_H_ */
/* End of ckb_consts.h */
/* Start of ckb_syscall_apis.h */
#ifndef CKB_C_STDLIB_CKB_SYSCALL_APIS_H_
#define CKB_C_STDLIB_CKB_SYSCALL_APIS_H_

/*
 * Syscall related APIs that will be shared and used in all CKB
 * smart contract environments
 */

#include <stddef.h>
#include <stdint.h>

/* Raw APIs */

/* VM version 0 APIs */
int ckb_exit(int8_t code);
int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_transaction(void* addr, uint64_t* len, size_t offset);
int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_script(void* addr, uint64_t* len, size_t offset);
int ckb_debug(const char* s);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);
int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);
int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);
int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source);
int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);
int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);
int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);
int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source);
int ckb_load_cell_data_as_code(void* addr, size_t memory_size,
                               size_t content_offset, size_t content_size,
                               size_t index, size_t source);

/* VM version 1 APIs */
int ckb_vm_version();
uint64_t ckb_current_cycles();
int ckb_exec(size_t index, size_t source, size_t place, size_t bounds, int argc,
             const char* argv[]);

/* VM version 2 APIs */
typedef struct spawn_args_t {
  size_t argc;
  const char** argv;
  /* Spawned VM process ID */
  uint64_t* process_id;
  /* A list of file descriptor, 0 indicates end of array */
  const uint64_t* inherited_fds;
} spawn_args_t;

int ckb_spawn(size_t index, size_t source, size_t place, size_t bounds,
              spawn_args_t* spawn_args);

int ckb_wait(uint64_t pid, int8_t* exit_code);

uint64_t ckb_process_id();

int ckb_pipe(uint64_t fds[2]);

int ckb_read(uint64_t fd, void* buffer, size_t* length);

int ckb_write(uint64_t fd, const void* buffer, size_t* length);

int ckb_inherited_fds(uint64_t* fds, size_t* length);

int ckb_close(uint64_t fd);

int ckb_load_block_extension(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source);

/* Handy utilities */
int ckb_exec_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                  uint32_t length, int argc, const char* argv[]);
int ckb_spawn_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                   uint32_t length, spawn_args_t* spawn_args);
int ckb_checked_load_tx_hash(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_cell(void* addr, uint64_t* len, size_t offset,
                          size_t index, size_t source);
int ckb_checked_load_input(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source);
int ckb_checked_load_header(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source);
int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source);
int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_transaction(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field);
int ckb_checked_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                                     size_t index, size_t source, size_t field);
int ckb_checked_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                                    size_t index, size_t source, size_t field);
int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source);
/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify
   input/output.
 */
int ckb_load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                                 size_t* type_source);
/* calculate inputs length */
int ckb_calculate_inputs_len();
/*
 * Look for a dep cell with specific code hash, code_hash should be a buffer
 * with 32 bytes.
 */
int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index);
/*
 * Deprecated, please use ckb_look_for_dep_with_hash2 instead.
 */
int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

/*
 * Those 2 are in fact implemented by ckb_dlfcn.h, which is not a direct
 * CKB syscall(or simple wrapper on a syscall), but rather a whole dynamic
 * linking solution. However for compatibility reasons, we are still keeping
 * those APIs in this file so as not to break existing code.
 */
int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size);
void* ckb_dlsym(void* handle, const char* symbol);

#endif /* CKB_C_STDLIB_CKB_SYSCALL_APIS_H_ */
/* End of ckb_syscall_apis.h */

extern int CKB_FUZZING_ENTRYPOINT(int argc, char* argv[]);

/*
 * !!!!!!!!!!!!!!!!!!!!!!!IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !Any reference to main will be rewritten in the actual code!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define main CKB_FUZZING_ENTRYPOINT

#ifdef __cplusplus
}
#endif

#endif /* CKB_FUZZING_SYSCALLS_H_ */
/* End of fuzzing_syscalls.h */

/*
 * Actual implementations, macros are provided to tweak single header
 * behaviors. Some like it, but some do not.
 */
#ifdef CKB_FUZZING_SINGLE_HEADER_MODE
#define CKB_FUZZING_INCLUDE_PROTOBUF_IMPL
#define CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL
#endif

/* Internal definitions, this must live outside any ifdefs */
#if defined(CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL) ||    \
    defined(CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE) || \
    defined(CKB_FUZZING_DEFINE_FILENAME_INTERFACE)
/* Start of fuzzing_syscalls_internal.h */
#ifndef CKB_FUZZING_SYSCALLS_INTERNAL_H_
#define CKB_FUZZING_SYSCALLS_INTERNAL_H_

/* fuzzing_syscalls.h has already been included. */
/* Start of traces.pb.h */
// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: traces.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_traces_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_traces_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3021000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3021012 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_bases.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/map.h>  // IWYU pragma: export
#include <google/protobuf/map_entry.h>
#include <google/protobuf/map_field_inl.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_traces_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_traces_2eproto {
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_traces_2eproto;
namespace generated {
namespace traces {
class Fds;
struct FdsDefaultTypeInternal;
extern FdsDefaultTypeInternal _Fds_default_instance_;
class IoData;
struct IoDataDefaultTypeInternal;
extern IoDataDefaultTypeInternal _IoData_default_instance_;
class Parts;
struct PartsDefaultTypeInternal;
extern PartsDefaultTypeInternal _Parts_default_instance_;
class Parts_ReadDataEntry_DoNotUse;
struct Parts_ReadDataEntry_DoNotUseDefaultTypeInternal;
extern Parts_ReadDataEntry_DoNotUseDefaultTypeInternal _Parts_ReadDataEntry_DoNotUse_default_instance_;
class Root;
struct RootDefaultTypeInternal;
extern RootDefaultTypeInternal _Root_default_instance_;
class Syscall;
struct SyscallDefaultTypeInternal;
extern SyscallDefaultTypeInternal _Syscall_default_instance_;
class Syscalls;
struct SyscallsDefaultTypeInternal;
extern SyscallsDefaultTypeInternal _Syscalls_default_instance_;
class Terminated;
struct TerminatedDefaultTypeInternal;
extern TerminatedDefaultTypeInternal _Terminated_default_instance_;
}  // namespace traces
}  // namespace generated
PROTOBUF_NAMESPACE_OPEN
template<> ::generated::traces::Fds* Arena::CreateMaybeMessage<::generated::traces::Fds>(Arena*);
template<> ::generated::traces::IoData* Arena::CreateMaybeMessage<::generated::traces::IoData>(Arena*);
template<> ::generated::traces::Parts* Arena::CreateMaybeMessage<::generated::traces::Parts>(Arena*);
template<> ::generated::traces::Parts_ReadDataEntry_DoNotUse* Arena::CreateMaybeMessage<::generated::traces::Parts_ReadDataEntry_DoNotUse>(Arena*);
template<> ::generated::traces::Root* Arena::CreateMaybeMessage<::generated::traces::Root>(Arena*);
template<> ::generated::traces::Syscall* Arena::CreateMaybeMessage<::generated::traces::Syscall>(Arena*);
template<> ::generated::traces::Syscalls* Arena::CreateMaybeMessage<::generated::traces::Syscalls>(Arena*);
template<> ::generated::traces::Terminated* Arena::CreateMaybeMessage<::generated::traces::Terminated>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace generated {
namespace traces {

// ===================================================================

class Terminated final :
    public ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase /* @@protoc_insertion_point(class_definition:generated.traces.Terminated) */ {
 public:
  inline Terminated() : Terminated(nullptr) {}
  explicit PROTOBUF_CONSTEXPR Terminated(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Terminated(const Terminated& from);
  Terminated(Terminated&& from) noexcept
    : Terminated() {
    *this = ::std::move(from);
  }

  inline Terminated& operator=(const Terminated& from) {
    CopyFrom(from);
    return *this;
  }
  inline Terminated& operator=(Terminated&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Terminated& default_instance() {
    return *internal_default_instance();
  }
  static inline const Terminated* internal_default_instance() {
    return reinterpret_cast<const Terminated*>(
               &_Terminated_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(Terminated& a, Terminated& b) {
    a.Swap(&b);
  }
  inline void Swap(Terminated* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Terminated* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  Terminated* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<Terminated>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase::CopyFrom;
  inline void CopyFrom(const Terminated& from) {
    ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase::CopyImpl(*this, from);
  }
  using ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase::MergeFrom;
  void MergeFrom(const Terminated& from) {
    ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase::MergeImpl(*this, from);
  }
  public:

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.Terminated";
  }
  protected:
  explicit Terminated(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // @@protoc_insertion_point(class_scope:generated.traces.Terminated)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
  };
  friend struct ::TableStruct_traces_2eproto;
};
// -------------------------------------------------------------------

class IoData final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:generated.traces.IoData) */ {
 public:
  inline IoData() : IoData(nullptr) {}
  ~IoData() override;
  explicit PROTOBUF_CONSTEXPR IoData(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  IoData(const IoData& from);
  IoData(IoData&& from) noexcept
    : IoData() {
    *this = ::std::move(from);
  }

  inline IoData& operator=(const IoData& from) {
    CopyFrom(from);
    return *this;
  }
  inline IoData& operator=(IoData&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const IoData& default_instance() {
    return *internal_default_instance();
  }
  static inline const IoData* internal_default_instance() {
    return reinterpret_cast<const IoData*>(
               &_IoData_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  friend void swap(IoData& a, IoData& b) {
    a.Swap(&b);
  }
  inline void Swap(IoData* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(IoData* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  IoData* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<IoData>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const IoData& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const IoData& from) {
    IoData::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(IoData* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.IoData";
  }
  protected:
  explicit IoData(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kAvailableDataFieldNumber = 1,
    kAdditionalLengthFieldNumber = 2,
  };
  // bytes available_data = 1;
  void clear_available_data();
  const std::string& available_data() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_available_data(ArgT0&& arg0, ArgT... args);
  std::string* mutable_available_data();
  PROTOBUF_NODISCARD std::string* release_available_data();
  void set_allocated_available_data(std::string* available_data);
  private:
  const std::string& _internal_available_data() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_available_data(const std::string& value);
  std::string* _internal_mutable_available_data();
  public:

  // uint64 additional_length = 2;
  void clear_additional_length();
  uint64_t additional_length() const;
  void set_additional_length(uint64_t value);
  private:
  uint64_t _internal_additional_length() const;
  void _internal_set_additional_length(uint64_t value);
  public:

  // @@protoc_insertion_point(class_scope:generated.traces.IoData)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr available_data_;
    uint64_t additional_length_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_traces_2eproto;
};
// -------------------------------------------------------------------

class Fds final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:generated.traces.Fds) */ {
 public:
  inline Fds() : Fds(nullptr) {}
  ~Fds() override;
  explicit PROTOBUF_CONSTEXPR Fds(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Fds(const Fds& from);
  Fds(Fds&& from) noexcept
    : Fds() {
    *this = ::std::move(from);
  }

  inline Fds& operator=(const Fds& from) {
    CopyFrom(from);
    return *this;
  }
  inline Fds& operator=(Fds&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Fds& default_instance() {
    return *internal_default_instance();
  }
  static inline const Fds* internal_default_instance() {
    return reinterpret_cast<const Fds*>(
               &_Fds_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    2;

  friend void swap(Fds& a, Fds& b) {
    a.Swap(&b);
  }
  inline void Swap(Fds* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Fds* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  Fds* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<Fds>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const Fds& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const Fds& from) {
    Fds::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Fds* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.Fds";
  }
  protected:
  explicit Fds(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kFdsFieldNumber = 1,
  };
  // repeated uint64 fds = 1;
  int fds_size() const;
  private:
  int _internal_fds_size() const;
  public:
  void clear_fds();
  private:
  uint64_t _internal_fds(int index) const;
  const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
      _internal_fds() const;
  void _internal_add_fds(uint64_t value);
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
      _internal_mutable_fds();
  public:
  uint64_t fds(int index) const;
  void set_fds(int index, uint64_t value);
  void add_fds(uint64_t value);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
      fds() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
      mutable_fds();

  // @@protoc_insertion_point(class_scope:generated.traces.Fds)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t > fds_;
    mutable std::atomic<int> _fds_cached_byte_size_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_traces_2eproto;
};
// -------------------------------------------------------------------

class Syscall final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:generated.traces.Syscall) */ {
 public:
  inline Syscall() : Syscall(nullptr) {}
  ~Syscall() override;
  explicit PROTOBUF_CONSTEXPR Syscall(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Syscall(const Syscall& from);
  Syscall(Syscall&& from) noexcept
    : Syscall() {
    *this = ::std::move(from);
  }

  inline Syscall& operator=(const Syscall& from) {
    CopyFrom(from);
    return *this;
  }
  inline Syscall& operator=(Syscall&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Syscall& default_instance() {
    return *internal_default_instance();
  }
  enum ValueCase {
    kReturnWithCode = 1,
    kSuccessOutputData = 2,
    kIoData = 3,
    kTerminated = 4,
    kFds = 5,
    VALUE_NOT_SET = 0,
  };

  static inline const Syscall* internal_default_instance() {
    return reinterpret_cast<const Syscall*>(
               &_Syscall_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    3;

  friend void swap(Syscall& a, Syscall& b) {
    a.Swap(&b);
  }
  inline void Swap(Syscall* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Syscall* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  Syscall* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<Syscall>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const Syscall& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const Syscall& from) {
    Syscall::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Syscall* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.Syscall";
  }
  protected:
  explicit Syscall(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kReturnWithCodeFieldNumber = 1,
    kSuccessOutputDataFieldNumber = 2,
    kIoDataFieldNumber = 3,
    kTerminatedFieldNumber = 4,
    kFdsFieldNumber = 5,
  };
  // int64 return_with_code = 1;
  bool has_return_with_code() const;
  private:
  bool _internal_has_return_with_code() const;
  public:
  void clear_return_with_code();
  int64_t return_with_code() const;
  void set_return_with_code(int64_t value);
  private:
  int64_t _internal_return_with_code() const;
  void _internal_set_return_with_code(int64_t value);
  public:

  // uint64 success_output_data = 2;
  bool has_success_output_data() const;
  private:
  bool _internal_has_success_output_data() const;
  public:
  void clear_success_output_data();
  uint64_t success_output_data() const;
  void set_success_output_data(uint64_t value);
  private:
  uint64_t _internal_success_output_data() const;
  void _internal_set_success_output_data(uint64_t value);
  public:

  // .generated.traces.IoData io_data = 3;
  bool has_io_data() const;
  private:
  bool _internal_has_io_data() const;
  public:
  void clear_io_data();
  const ::generated::traces::IoData& io_data() const;
  PROTOBUF_NODISCARD ::generated::traces::IoData* release_io_data();
  ::generated::traces::IoData* mutable_io_data();
  void set_allocated_io_data(::generated::traces::IoData* io_data);
  private:
  const ::generated::traces::IoData& _internal_io_data() const;
  ::generated::traces::IoData* _internal_mutable_io_data();
  public:
  void unsafe_arena_set_allocated_io_data(
      ::generated::traces::IoData* io_data);
  ::generated::traces::IoData* unsafe_arena_release_io_data();

  // .generated.traces.Terminated terminated = 4;
  bool has_terminated() const;
  private:
  bool _internal_has_terminated() const;
  public:
  void clear_terminated();
  const ::generated::traces::Terminated& terminated() const;
  PROTOBUF_NODISCARD ::generated::traces::Terminated* release_terminated();
  ::generated::traces::Terminated* mutable_terminated();
  void set_allocated_terminated(::generated::traces::Terminated* terminated);
  private:
  const ::generated::traces::Terminated& _internal_terminated() const;
  ::generated::traces::Terminated* _internal_mutable_terminated();
  public:
  void unsafe_arena_set_allocated_terminated(
      ::generated::traces::Terminated* terminated);
  ::generated::traces::Terminated* unsafe_arena_release_terminated();

  // .generated.traces.Fds fds = 5;
  bool has_fds() const;
  private:
  bool _internal_has_fds() const;
  public:
  void clear_fds();
  const ::generated::traces::Fds& fds() const;
  PROTOBUF_NODISCARD ::generated::traces::Fds* release_fds();
  ::generated::traces::Fds* mutable_fds();
  void set_allocated_fds(::generated::traces::Fds* fds);
  private:
  const ::generated::traces::Fds& _internal_fds() const;
  ::generated::traces::Fds* _internal_mutable_fds();
  public:
  void unsafe_arena_set_allocated_fds(
      ::generated::traces::Fds* fds);
  ::generated::traces::Fds* unsafe_arena_release_fds();

  void clear_value();
  ValueCase value_case() const;
  // @@protoc_insertion_point(class_scope:generated.traces.Syscall)
 private:
  class _Internal;
  void set_has_return_with_code();
  void set_has_success_output_data();
  void set_has_io_data();
  void set_has_terminated();
  void set_has_fds();

  inline bool has_value() const;
  inline void clear_has_value();

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    union ValueUnion {
      constexpr ValueUnion() : _constinit_{} {}
        ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized _constinit_;
      int64_t return_with_code_;
      uint64_t success_output_data_;
      ::generated::traces::IoData* io_data_;
      ::generated::traces::Terminated* terminated_;
      ::generated::traces::Fds* fds_;
    } value_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
    uint32_t _oneof_case_[1];

  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_traces_2eproto;
};
// -------------------------------------------------------------------

class Syscalls final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:generated.traces.Syscalls) */ {
 public:
  inline Syscalls() : Syscalls(nullptr) {}
  ~Syscalls() override;
  explicit PROTOBUF_CONSTEXPR Syscalls(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Syscalls(const Syscalls& from);
  Syscalls(Syscalls&& from) noexcept
    : Syscalls() {
    *this = ::std::move(from);
  }

  inline Syscalls& operator=(const Syscalls& from) {
    CopyFrom(from);
    return *this;
  }
  inline Syscalls& operator=(Syscalls&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Syscalls& default_instance() {
    return *internal_default_instance();
  }
  static inline const Syscalls* internal_default_instance() {
    return reinterpret_cast<const Syscalls*>(
               &_Syscalls_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    4;

  friend void swap(Syscalls& a, Syscalls& b) {
    a.Swap(&b);
  }
  inline void Swap(Syscalls* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Syscalls* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  Syscalls* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<Syscalls>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const Syscalls& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const Syscalls& from) {
    Syscalls::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Syscalls* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.Syscalls";
  }
  protected:
  explicit Syscalls(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kSyscallsFieldNumber = 1,
    kArgsFieldNumber = 2,
  };
  // repeated .generated.traces.Syscall syscalls = 1;
  int syscalls_size() const;
  private:
  int _internal_syscalls_size() const;
  public:
  void clear_syscalls();
  ::generated::traces::Syscall* mutable_syscalls(int index);
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::generated::traces::Syscall >*
      mutable_syscalls();
  private:
  const ::generated::traces::Syscall& _internal_syscalls(int index) const;
  ::generated::traces::Syscall* _internal_add_syscalls();
  public:
  const ::generated::traces::Syscall& syscalls(int index) const;
  ::generated::traces::Syscall* add_syscalls();
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::generated::traces::Syscall >&
      syscalls() const;

  // repeated bytes args = 2;
  int args_size() const;
  private:
  int _internal_args_size() const;
  public:
  void clear_args();
  const std::string& args(int index) const;
  std::string* mutable_args(int index);
  void set_args(int index, const std::string& value);
  void set_args(int index, std::string&& value);
  void set_args(int index, const char* value);
  void set_args(int index, const void* value, size_t size);
  std::string* add_args();
  void add_args(const std::string& value);
  void add_args(std::string&& value);
  void add_args(const char* value);
  void add_args(const void* value, size_t size);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>& args() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>* mutable_args();
  private:
  const std::string& _internal_args(int index) const;
  std::string* _internal_add_args();
  public:

  // @@protoc_insertion_point(class_scope:generated.traces.Syscalls)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::generated::traces::Syscall > syscalls_;
    ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string> args_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_traces_2eproto;
};
// -------------------------------------------------------------------

class Parts_ReadDataEntry_DoNotUse : public ::PROTOBUF_NAMESPACE_ID::internal::MapEntry<Parts_ReadDataEntry_DoNotUse, 
    uint64_t, std::string,
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_UINT64,
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_BYTES> {
public:
  typedef ::PROTOBUF_NAMESPACE_ID::internal::MapEntry<Parts_ReadDataEntry_DoNotUse, 
    uint64_t, std::string,
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_UINT64,
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_BYTES> SuperType;
  Parts_ReadDataEntry_DoNotUse();
  explicit PROTOBUF_CONSTEXPR Parts_ReadDataEntry_DoNotUse(
      ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);
  explicit Parts_ReadDataEntry_DoNotUse(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  void MergeFrom(const Parts_ReadDataEntry_DoNotUse& other);
  static const Parts_ReadDataEntry_DoNotUse* internal_default_instance() { return reinterpret_cast<const Parts_ReadDataEntry_DoNotUse*>(&_Parts_ReadDataEntry_DoNotUse_default_instance_); }
  static bool ValidateKey(void*) { return true; }
  static bool ValidateValue(void*) { return true; }
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;
  friend struct ::TableStruct_traces_2eproto;
};

// -------------------------------------------------------------------

class Parts final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:generated.traces.Parts) */ {
 public:
  inline Parts() : Parts(nullptr) {}
  ~Parts() override;
  explicit PROTOBUF_CONSTEXPR Parts(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Parts(const Parts& from);
  Parts(Parts&& from) noexcept
    : Parts() {
    *this = ::std::move(from);
  }

  inline Parts& operator=(const Parts& from) {
    CopyFrom(from);
    return *this;
  }
  inline Parts& operator=(Parts&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Parts& default_instance() {
    return *internal_default_instance();
  }
  static inline const Parts* internal_default_instance() {
    return reinterpret_cast<const Parts*>(
               &_Parts_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    6;

  friend void swap(Parts& a, Parts& b) {
    a.Swap(&b);
  }
  inline void Swap(Parts* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Parts* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  Parts* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<Parts>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const Parts& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const Parts& from) {
    Parts::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Parts* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.Parts";
  }
  protected:
  explicit Parts(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  private:
  static void ArenaDtor(void* object);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------


  // accessors -------------------------------------------------------

  enum : int {
    kInputCellsFieldNumber = 2,
    kInputCellDataFieldNumber = 3,
    kWitnessesFieldNumber = 4,
    kInheritedFdsFieldNumber = 5,
    kReadDataFieldNumber = 6,
    kTxHashFieldNumber = 1,
    kOtherSyscallsFieldNumber = 7,
  };
  // repeated bytes input_cells = 2;
  int input_cells_size() const;
  private:
  int _internal_input_cells_size() const;
  public:
  void clear_input_cells();
  const std::string& input_cells(int index) const;
  std::string* mutable_input_cells(int index);
  void set_input_cells(int index, const std::string& value);
  void set_input_cells(int index, std::string&& value);
  void set_input_cells(int index, const char* value);
  void set_input_cells(int index, const void* value, size_t size);
  std::string* add_input_cells();
  void add_input_cells(const std::string& value);
  void add_input_cells(std::string&& value);
  void add_input_cells(const char* value);
  void add_input_cells(const void* value, size_t size);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>& input_cells() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>* mutable_input_cells();
  private:
  const std::string& _internal_input_cells(int index) const;
  std::string* _internal_add_input_cells();
  public:

  // repeated bytes input_cell_data = 3;
  int input_cell_data_size() const;
  private:
  int _internal_input_cell_data_size() const;
  public:
  void clear_input_cell_data();
  const std::string& input_cell_data(int index) const;
  std::string* mutable_input_cell_data(int index);
  void set_input_cell_data(int index, const std::string& value);
  void set_input_cell_data(int index, std::string&& value);
  void set_input_cell_data(int index, const char* value);
  void set_input_cell_data(int index, const void* value, size_t size);
  std::string* add_input_cell_data();
  void add_input_cell_data(const std::string& value);
  void add_input_cell_data(std::string&& value);
  void add_input_cell_data(const char* value);
  void add_input_cell_data(const void* value, size_t size);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>& input_cell_data() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>* mutable_input_cell_data();
  private:
  const std::string& _internal_input_cell_data(int index) const;
  std::string* _internal_add_input_cell_data();
  public:

  // repeated bytes witnesses = 4;
  int witnesses_size() const;
  private:
  int _internal_witnesses_size() const;
  public:
  void clear_witnesses();
  const std::string& witnesses(int index) const;
  std::string* mutable_witnesses(int index);
  void set_witnesses(int index, const std::string& value);
  void set_witnesses(int index, std::string&& value);
  void set_witnesses(int index, const char* value);
  void set_witnesses(int index, const void* value, size_t size);
  std::string* add_witnesses();
  void add_witnesses(const std::string& value);
  void add_witnesses(std::string&& value);
  void add_witnesses(const char* value);
  void add_witnesses(const void* value, size_t size);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>& witnesses() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>* mutable_witnesses();
  private:
  const std::string& _internal_witnesses(int index) const;
  std::string* _internal_add_witnesses();
  public:

  // repeated uint64 inherited_fds = 5;
  int inherited_fds_size() const;
  private:
  int _internal_inherited_fds_size() const;
  public:
  void clear_inherited_fds();
  private:
  uint64_t _internal_inherited_fds(int index) const;
  const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
      _internal_inherited_fds() const;
  void _internal_add_inherited_fds(uint64_t value);
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
      _internal_mutable_inherited_fds();
  public:
  uint64_t inherited_fds(int index) const;
  void set_inherited_fds(int index, uint64_t value);
  void add_inherited_fds(uint64_t value);
  const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
      inherited_fds() const;
  ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
      mutable_inherited_fds();

  // map<uint64, bytes> read_data = 6;
  int read_data_size() const;
  private:
  int _internal_read_data_size() const;
  public:
  void clear_read_data();
  private:
  const ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >&
      _internal_read_data() const;
  ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >*
      _internal_mutable_read_data();
  public:
  const ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >&
      read_data() const;
  ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >*
      mutable_read_data();

  // bytes tx_hash = 1;
  void clear_tx_hash();
  const std::string& tx_hash() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_tx_hash(ArgT0&& arg0, ArgT... args);
  std::string* mutable_tx_hash();
  PROTOBUF_NODISCARD std::string* release_tx_hash();
  void set_allocated_tx_hash(std::string* tx_hash);
  private:
  const std::string& _internal_tx_hash() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_tx_hash(const std::string& value);
  std::string* _internal_mutable_tx_hash();
  public:

  // .generated.traces.Syscalls other_syscalls = 7;
  bool has_other_syscalls() const;
  private:
  bool _internal_has_other_syscalls() const;
  public:
  void clear_other_syscalls();
  const ::generated::traces::Syscalls& other_syscalls() const;
  PROTOBUF_NODISCARD ::generated::traces::Syscalls* release_other_syscalls();
  ::generated::traces::Syscalls* mutable_other_syscalls();
  void set_allocated_other_syscalls(::generated::traces::Syscalls* other_syscalls);
  private:
  const ::generated::traces::Syscalls& _internal_other_syscalls() const;
  ::generated::traces::Syscalls* _internal_mutable_other_syscalls();
  public:
  void unsafe_arena_set_allocated_other_syscalls(
      ::generated::traces::Syscalls* other_syscalls);
  ::generated::traces::Syscalls* unsafe_arena_release_other_syscalls();

  // @@protoc_insertion_point(class_scope:generated.traces.Parts)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string> input_cells_;
    ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string> input_cell_data_;
    ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string> witnesses_;
    ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t > inherited_fds_;
    mutable std::atomic<int> _inherited_fds_cached_byte_size_;
    ::PROTOBUF_NAMESPACE_ID::internal::MapField<
        Parts_ReadDataEntry_DoNotUse,
        uint64_t, std::string,
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_UINT64,
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::TYPE_BYTES> read_data_;
    ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr tx_hash_;
    ::generated::traces::Syscalls* other_syscalls_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_traces_2eproto;
};
// -------------------------------------------------------------------

class Root final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:generated.traces.Root) */ {
 public:
  inline Root() : Root(nullptr) {}
  ~Root() override;
  explicit PROTOBUF_CONSTEXPR Root(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  Root(const Root& from);
  Root(Root&& from) noexcept
    : Root() {
    *this = ::std::move(from);
  }

  inline Root& operator=(const Root& from) {
    CopyFrom(from);
    return *this;
  }
  inline Root& operator=(Root&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const Root& default_instance() {
    return *internal_default_instance();
  }
  enum ValueCase {
    kParts = 1,
    kSyscalls = 3,
    VALUE_NOT_SET = 0,
  };

  static inline const Root* internal_default_instance() {
    return reinterpret_cast<const Root*>(
               &_Root_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    7;

  friend void swap(Root& a, Root& b) {
    a.Swap(&b);
  }
  inline void Swap(Root* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(Root* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  Root* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<Root>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const Root& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom( const Root& from) {
    Root::MergeImpl(*this, from);
  }
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::PROTOBUF_NAMESPACE_ID::Arena* arena, bool is_message_owned);
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(Root* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "generated.traces.Root";
  }
  protected:
  explicit Root(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kPartsFieldNumber = 1,
    kSyscallsFieldNumber = 3,
  };
  // .generated.traces.Parts parts = 1;
  bool has_parts() const;
  private:
  bool _internal_has_parts() const;
  public:
  void clear_parts();
  const ::generated::traces::Parts& parts() const;
  PROTOBUF_NODISCARD ::generated::traces::Parts* release_parts();
  ::generated::traces::Parts* mutable_parts();
  void set_allocated_parts(::generated::traces::Parts* parts);
  private:
  const ::generated::traces::Parts& _internal_parts() const;
  ::generated::traces::Parts* _internal_mutable_parts();
  public:
  void unsafe_arena_set_allocated_parts(
      ::generated::traces::Parts* parts);
  ::generated::traces::Parts* unsafe_arena_release_parts();

  // .generated.traces.Syscalls syscalls = 3;
  bool has_syscalls() const;
  private:
  bool _internal_has_syscalls() const;
  public:
  void clear_syscalls();
  const ::generated::traces::Syscalls& syscalls() const;
  PROTOBUF_NODISCARD ::generated::traces::Syscalls* release_syscalls();
  ::generated::traces::Syscalls* mutable_syscalls();
  void set_allocated_syscalls(::generated::traces::Syscalls* syscalls);
  private:
  const ::generated::traces::Syscalls& _internal_syscalls() const;
  ::generated::traces::Syscalls* _internal_mutable_syscalls();
  public:
  void unsafe_arena_set_allocated_syscalls(
      ::generated::traces::Syscalls* syscalls);
  ::generated::traces::Syscalls* unsafe_arena_release_syscalls();

  void clear_value();
  ValueCase value_case() const;
  // @@protoc_insertion_point(class_scope:generated.traces.Root)
 private:
  class _Internal;
  void set_has_parts();
  void set_has_syscalls();

  inline bool has_value() const;
  inline void clear_has_value();

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  struct Impl_ {
    union ValueUnion {
      constexpr ValueUnion() : _constinit_{} {}
        ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized _constinit_;
      ::generated::traces::Parts* parts_;
      ::generated::traces::Syscalls* syscalls_;
    } value_;
    mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
    uint32_t _oneof_case_[1];

  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_traces_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// Terminated

// -------------------------------------------------------------------

// IoData

// bytes available_data = 1;
inline void IoData::clear_available_data() {
  _impl_.available_data_.ClearToEmpty();
}
inline const std::string& IoData::available_data() const {
  // @@protoc_insertion_point(field_get:generated.traces.IoData.available_data)
  return _internal_available_data();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void IoData::set_available_data(ArgT0&& arg0, ArgT... args) {
 
 _impl_.available_data_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:generated.traces.IoData.available_data)
}
inline std::string* IoData::mutable_available_data() {
  std::string* _s = _internal_mutable_available_data();
  // @@protoc_insertion_point(field_mutable:generated.traces.IoData.available_data)
  return _s;
}
inline const std::string& IoData::_internal_available_data() const {
  return _impl_.available_data_.Get();
}
inline void IoData::_internal_set_available_data(const std::string& value) {
  
  _impl_.available_data_.Set(value, GetArenaForAllocation());
}
inline std::string* IoData::_internal_mutable_available_data() {
  
  return _impl_.available_data_.Mutable(GetArenaForAllocation());
}
inline std::string* IoData::release_available_data() {
  // @@protoc_insertion_point(field_release:generated.traces.IoData.available_data)
  return _impl_.available_data_.Release();
}
inline void IoData::set_allocated_available_data(std::string* available_data) {
  if (available_data != nullptr) {
    
  } else {
    
  }
  _impl_.available_data_.SetAllocated(available_data, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.available_data_.IsDefault()) {
    _impl_.available_data_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:generated.traces.IoData.available_data)
}

// uint64 additional_length = 2;
inline void IoData::clear_additional_length() {
  _impl_.additional_length_ = uint64_t{0u};
}
inline uint64_t IoData::_internal_additional_length() const {
  return _impl_.additional_length_;
}
inline uint64_t IoData::additional_length() const {
  // @@protoc_insertion_point(field_get:generated.traces.IoData.additional_length)
  return _internal_additional_length();
}
inline void IoData::_internal_set_additional_length(uint64_t value) {
  
  _impl_.additional_length_ = value;
}
inline void IoData::set_additional_length(uint64_t value) {
  _internal_set_additional_length(value);
  // @@protoc_insertion_point(field_set:generated.traces.IoData.additional_length)
}

// -------------------------------------------------------------------

// Fds

// repeated uint64 fds = 1;
inline int Fds::_internal_fds_size() const {
  return _impl_.fds_.size();
}
inline int Fds::fds_size() const {
  return _internal_fds_size();
}
inline void Fds::clear_fds() {
  _impl_.fds_.Clear();
}
inline uint64_t Fds::_internal_fds(int index) const {
  return _impl_.fds_.Get(index);
}
inline uint64_t Fds::fds(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Fds.fds)
  return _internal_fds(index);
}
inline void Fds::set_fds(int index, uint64_t value) {
  _impl_.fds_.Set(index, value);
  // @@protoc_insertion_point(field_set:generated.traces.Fds.fds)
}
inline void Fds::_internal_add_fds(uint64_t value) {
  _impl_.fds_.Add(value);
}
inline void Fds::add_fds(uint64_t value) {
  _internal_add_fds(value);
  // @@protoc_insertion_point(field_add:generated.traces.Fds.fds)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
Fds::_internal_fds() const {
  return _impl_.fds_;
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
Fds::fds() const {
  // @@protoc_insertion_point(field_list:generated.traces.Fds.fds)
  return _internal_fds();
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
Fds::_internal_mutable_fds() {
  return &_impl_.fds_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
Fds::mutable_fds() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Fds.fds)
  return _internal_mutable_fds();
}

// -------------------------------------------------------------------

// Syscall

// int64 return_with_code = 1;
inline bool Syscall::_internal_has_return_with_code() const {
  return value_case() == kReturnWithCode;
}
inline bool Syscall::has_return_with_code() const {
  return _internal_has_return_with_code();
}
inline void Syscall::set_has_return_with_code() {
  _impl_._oneof_case_[0] = kReturnWithCode;
}
inline void Syscall::clear_return_with_code() {
  if (_internal_has_return_with_code()) {
    _impl_.value_.return_with_code_ = int64_t{0};
    clear_has_value();
  }
}
inline int64_t Syscall::_internal_return_with_code() const {
  if (_internal_has_return_with_code()) {
    return _impl_.value_.return_with_code_;
  }
  return int64_t{0};
}
inline void Syscall::_internal_set_return_with_code(int64_t value) {
  if (!_internal_has_return_with_code()) {
    clear_value();
    set_has_return_with_code();
  }
  _impl_.value_.return_with_code_ = value;
}
inline int64_t Syscall::return_with_code() const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscall.return_with_code)
  return _internal_return_with_code();
}
inline void Syscall::set_return_with_code(int64_t value) {
  _internal_set_return_with_code(value);
  // @@protoc_insertion_point(field_set:generated.traces.Syscall.return_with_code)
}

// uint64 success_output_data = 2;
inline bool Syscall::_internal_has_success_output_data() const {
  return value_case() == kSuccessOutputData;
}
inline bool Syscall::has_success_output_data() const {
  return _internal_has_success_output_data();
}
inline void Syscall::set_has_success_output_data() {
  _impl_._oneof_case_[0] = kSuccessOutputData;
}
inline void Syscall::clear_success_output_data() {
  if (_internal_has_success_output_data()) {
    _impl_.value_.success_output_data_ = uint64_t{0u};
    clear_has_value();
  }
}
inline uint64_t Syscall::_internal_success_output_data() const {
  if (_internal_has_success_output_data()) {
    return _impl_.value_.success_output_data_;
  }
  return uint64_t{0u};
}
inline void Syscall::_internal_set_success_output_data(uint64_t value) {
  if (!_internal_has_success_output_data()) {
    clear_value();
    set_has_success_output_data();
  }
  _impl_.value_.success_output_data_ = value;
}
inline uint64_t Syscall::success_output_data() const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscall.success_output_data)
  return _internal_success_output_data();
}
inline void Syscall::set_success_output_data(uint64_t value) {
  _internal_set_success_output_data(value);
  // @@protoc_insertion_point(field_set:generated.traces.Syscall.success_output_data)
}

// .generated.traces.IoData io_data = 3;
inline bool Syscall::_internal_has_io_data() const {
  return value_case() == kIoData;
}
inline bool Syscall::has_io_data() const {
  return _internal_has_io_data();
}
inline void Syscall::set_has_io_data() {
  _impl_._oneof_case_[0] = kIoData;
}
inline void Syscall::clear_io_data() {
  if (_internal_has_io_data()) {
    if (GetArenaForAllocation() == nullptr) {
      delete _impl_.value_.io_data_;
    }
    clear_has_value();
  }
}
inline ::generated::traces::IoData* Syscall::release_io_data() {
  // @@protoc_insertion_point(field_release:generated.traces.Syscall.io_data)
  if (_internal_has_io_data()) {
    clear_has_value();
    ::generated::traces::IoData* temp = _impl_.value_.io_data_;
    if (GetArenaForAllocation() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    _impl_.value_.io_data_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::generated::traces::IoData& Syscall::_internal_io_data() const {
  return _internal_has_io_data()
      ? *_impl_.value_.io_data_
      : reinterpret_cast< ::generated::traces::IoData&>(::generated::traces::_IoData_default_instance_);
}
inline const ::generated::traces::IoData& Syscall::io_data() const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscall.io_data)
  return _internal_io_data();
}
inline ::generated::traces::IoData* Syscall::unsafe_arena_release_io_data() {
  // @@protoc_insertion_point(field_unsafe_arena_release:generated.traces.Syscall.io_data)
  if (_internal_has_io_data()) {
    clear_has_value();
    ::generated::traces::IoData* temp = _impl_.value_.io_data_;
    _impl_.value_.io_data_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void Syscall::unsafe_arena_set_allocated_io_data(::generated::traces::IoData* io_data) {
  clear_value();
  if (io_data) {
    set_has_io_data();
    _impl_.value_.io_data_ = io_data;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:generated.traces.Syscall.io_data)
}
inline ::generated::traces::IoData* Syscall::_internal_mutable_io_data() {
  if (!_internal_has_io_data()) {
    clear_value();
    set_has_io_data();
    _impl_.value_.io_data_ = CreateMaybeMessage< ::generated::traces::IoData >(GetArenaForAllocation());
  }
  return _impl_.value_.io_data_;
}
inline ::generated::traces::IoData* Syscall::mutable_io_data() {
  ::generated::traces::IoData* _msg = _internal_mutable_io_data();
  // @@protoc_insertion_point(field_mutable:generated.traces.Syscall.io_data)
  return _msg;
}

// .generated.traces.Terminated terminated = 4;
inline bool Syscall::_internal_has_terminated() const {
  return value_case() == kTerminated;
}
inline bool Syscall::has_terminated() const {
  return _internal_has_terminated();
}
inline void Syscall::set_has_terminated() {
  _impl_._oneof_case_[0] = kTerminated;
}
inline void Syscall::clear_terminated() {
  if (_internal_has_terminated()) {
    if (GetArenaForAllocation() == nullptr) {
      delete _impl_.value_.terminated_;
    }
    clear_has_value();
  }
}
inline ::generated::traces::Terminated* Syscall::release_terminated() {
  // @@protoc_insertion_point(field_release:generated.traces.Syscall.terminated)
  if (_internal_has_terminated()) {
    clear_has_value();
    ::generated::traces::Terminated* temp = _impl_.value_.terminated_;
    if (GetArenaForAllocation() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    _impl_.value_.terminated_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::generated::traces::Terminated& Syscall::_internal_terminated() const {
  return _internal_has_terminated()
      ? *_impl_.value_.terminated_
      : reinterpret_cast< ::generated::traces::Terminated&>(::generated::traces::_Terminated_default_instance_);
}
inline const ::generated::traces::Terminated& Syscall::terminated() const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscall.terminated)
  return _internal_terminated();
}
inline ::generated::traces::Terminated* Syscall::unsafe_arena_release_terminated() {
  // @@protoc_insertion_point(field_unsafe_arena_release:generated.traces.Syscall.terminated)
  if (_internal_has_terminated()) {
    clear_has_value();
    ::generated::traces::Terminated* temp = _impl_.value_.terminated_;
    _impl_.value_.terminated_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void Syscall::unsafe_arena_set_allocated_terminated(::generated::traces::Terminated* terminated) {
  clear_value();
  if (terminated) {
    set_has_terminated();
    _impl_.value_.terminated_ = terminated;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:generated.traces.Syscall.terminated)
}
inline ::generated::traces::Terminated* Syscall::_internal_mutable_terminated() {
  if (!_internal_has_terminated()) {
    clear_value();
    set_has_terminated();
    _impl_.value_.terminated_ = CreateMaybeMessage< ::generated::traces::Terminated >(GetArenaForAllocation());
  }
  return _impl_.value_.terminated_;
}
inline ::generated::traces::Terminated* Syscall::mutable_terminated() {
  ::generated::traces::Terminated* _msg = _internal_mutable_terminated();
  // @@protoc_insertion_point(field_mutable:generated.traces.Syscall.terminated)
  return _msg;
}

// .generated.traces.Fds fds = 5;
inline bool Syscall::_internal_has_fds() const {
  return value_case() == kFds;
}
inline bool Syscall::has_fds() const {
  return _internal_has_fds();
}
inline void Syscall::set_has_fds() {
  _impl_._oneof_case_[0] = kFds;
}
inline void Syscall::clear_fds() {
  if (_internal_has_fds()) {
    if (GetArenaForAllocation() == nullptr) {
      delete _impl_.value_.fds_;
    }
    clear_has_value();
  }
}
inline ::generated::traces::Fds* Syscall::release_fds() {
  // @@protoc_insertion_point(field_release:generated.traces.Syscall.fds)
  if (_internal_has_fds()) {
    clear_has_value();
    ::generated::traces::Fds* temp = _impl_.value_.fds_;
    if (GetArenaForAllocation() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    _impl_.value_.fds_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::generated::traces::Fds& Syscall::_internal_fds() const {
  return _internal_has_fds()
      ? *_impl_.value_.fds_
      : reinterpret_cast< ::generated::traces::Fds&>(::generated::traces::_Fds_default_instance_);
}
inline const ::generated::traces::Fds& Syscall::fds() const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscall.fds)
  return _internal_fds();
}
inline ::generated::traces::Fds* Syscall::unsafe_arena_release_fds() {
  // @@protoc_insertion_point(field_unsafe_arena_release:generated.traces.Syscall.fds)
  if (_internal_has_fds()) {
    clear_has_value();
    ::generated::traces::Fds* temp = _impl_.value_.fds_;
    _impl_.value_.fds_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void Syscall::unsafe_arena_set_allocated_fds(::generated::traces::Fds* fds) {
  clear_value();
  if (fds) {
    set_has_fds();
    _impl_.value_.fds_ = fds;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:generated.traces.Syscall.fds)
}
inline ::generated::traces::Fds* Syscall::_internal_mutable_fds() {
  if (!_internal_has_fds()) {
    clear_value();
    set_has_fds();
    _impl_.value_.fds_ = CreateMaybeMessage< ::generated::traces::Fds >(GetArenaForAllocation());
  }
  return _impl_.value_.fds_;
}
inline ::generated::traces::Fds* Syscall::mutable_fds() {
  ::generated::traces::Fds* _msg = _internal_mutable_fds();
  // @@protoc_insertion_point(field_mutable:generated.traces.Syscall.fds)
  return _msg;
}

inline bool Syscall::has_value() const {
  return value_case() != VALUE_NOT_SET;
}
inline void Syscall::clear_has_value() {
  _impl_._oneof_case_[0] = VALUE_NOT_SET;
}
inline Syscall::ValueCase Syscall::value_case() const {
  return Syscall::ValueCase(_impl_._oneof_case_[0]);
}
// -------------------------------------------------------------------

// Syscalls

// repeated .generated.traces.Syscall syscalls = 1;
inline int Syscalls::_internal_syscalls_size() const {
  return _impl_.syscalls_.size();
}
inline int Syscalls::syscalls_size() const {
  return _internal_syscalls_size();
}
inline void Syscalls::clear_syscalls() {
  _impl_.syscalls_.Clear();
}
inline ::generated::traces::Syscall* Syscalls::mutable_syscalls(int index) {
  // @@protoc_insertion_point(field_mutable:generated.traces.Syscalls.syscalls)
  return _impl_.syscalls_.Mutable(index);
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::generated::traces::Syscall >*
Syscalls::mutable_syscalls() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Syscalls.syscalls)
  return &_impl_.syscalls_;
}
inline const ::generated::traces::Syscall& Syscalls::_internal_syscalls(int index) const {
  return _impl_.syscalls_.Get(index);
}
inline const ::generated::traces::Syscall& Syscalls::syscalls(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscalls.syscalls)
  return _internal_syscalls(index);
}
inline ::generated::traces::Syscall* Syscalls::_internal_add_syscalls() {
  return _impl_.syscalls_.Add();
}
inline ::generated::traces::Syscall* Syscalls::add_syscalls() {
  ::generated::traces::Syscall* _add = _internal_add_syscalls();
  // @@protoc_insertion_point(field_add:generated.traces.Syscalls.syscalls)
  return _add;
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField< ::generated::traces::Syscall >&
Syscalls::syscalls() const {
  // @@protoc_insertion_point(field_list:generated.traces.Syscalls.syscalls)
  return _impl_.syscalls_;
}

// repeated bytes args = 2;
inline int Syscalls::_internal_args_size() const {
  return _impl_.args_.size();
}
inline int Syscalls::args_size() const {
  return _internal_args_size();
}
inline void Syscalls::clear_args() {
  _impl_.args_.Clear();
}
inline std::string* Syscalls::add_args() {
  std::string* _s = _internal_add_args();
  // @@protoc_insertion_point(field_add_mutable:generated.traces.Syscalls.args)
  return _s;
}
inline const std::string& Syscalls::_internal_args(int index) const {
  return _impl_.args_.Get(index);
}
inline const std::string& Syscalls::args(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Syscalls.args)
  return _internal_args(index);
}
inline std::string* Syscalls::mutable_args(int index) {
  // @@protoc_insertion_point(field_mutable:generated.traces.Syscalls.args)
  return _impl_.args_.Mutable(index);
}
inline void Syscalls::set_args(int index, const std::string& value) {
  _impl_.args_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set:generated.traces.Syscalls.args)
}
inline void Syscalls::set_args(int index, std::string&& value) {
  _impl_.args_.Mutable(index)->assign(std::move(value));
  // @@protoc_insertion_point(field_set:generated.traces.Syscalls.args)
}
inline void Syscalls::set_args(int index, const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.args_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set_char:generated.traces.Syscalls.args)
}
inline void Syscalls::set_args(int index, const void* value, size_t size) {
  _impl_.args_.Mutable(index)->assign(
    reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_set_pointer:generated.traces.Syscalls.args)
}
inline std::string* Syscalls::_internal_add_args() {
  return _impl_.args_.Add();
}
inline void Syscalls::add_args(const std::string& value) {
  _impl_.args_.Add()->assign(value);
  // @@protoc_insertion_point(field_add:generated.traces.Syscalls.args)
}
inline void Syscalls::add_args(std::string&& value) {
  _impl_.args_.Add(std::move(value));
  // @@protoc_insertion_point(field_add:generated.traces.Syscalls.args)
}
inline void Syscalls::add_args(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.args_.Add()->assign(value);
  // @@protoc_insertion_point(field_add_char:generated.traces.Syscalls.args)
}
inline void Syscalls::add_args(const void* value, size_t size) {
  _impl_.args_.Add()->assign(reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_add_pointer:generated.traces.Syscalls.args)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>&
Syscalls::args() const {
  // @@protoc_insertion_point(field_list:generated.traces.Syscalls.args)
  return _impl_.args_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>*
Syscalls::mutable_args() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Syscalls.args)
  return &_impl_.args_;
}

// -------------------------------------------------------------------

// -------------------------------------------------------------------

// Parts

// bytes tx_hash = 1;
inline void Parts::clear_tx_hash() {
  _impl_.tx_hash_.ClearToEmpty();
}
inline const std::string& Parts::tx_hash() const {
  // @@protoc_insertion_point(field_get:generated.traces.Parts.tx_hash)
  return _internal_tx_hash();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void Parts::set_tx_hash(ArgT0&& arg0, ArgT... args) {
 
 _impl_.tx_hash_.SetBytes(static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:generated.traces.Parts.tx_hash)
}
inline std::string* Parts::mutable_tx_hash() {
  std::string* _s = _internal_mutable_tx_hash();
  // @@protoc_insertion_point(field_mutable:generated.traces.Parts.tx_hash)
  return _s;
}
inline const std::string& Parts::_internal_tx_hash() const {
  return _impl_.tx_hash_.Get();
}
inline void Parts::_internal_set_tx_hash(const std::string& value) {
  
  _impl_.tx_hash_.Set(value, GetArenaForAllocation());
}
inline std::string* Parts::_internal_mutable_tx_hash() {
  
  return _impl_.tx_hash_.Mutable(GetArenaForAllocation());
}
inline std::string* Parts::release_tx_hash() {
  // @@protoc_insertion_point(field_release:generated.traces.Parts.tx_hash)
  return _impl_.tx_hash_.Release();
}
inline void Parts::set_allocated_tx_hash(std::string* tx_hash) {
  if (tx_hash != nullptr) {
    
  } else {
    
  }
  _impl_.tx_hash_.SetAllocated(tx_hash, GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (_impl_.tx_hash_.IsDefault()) {
    _impl_.tx_hash_.Set("", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Parts.tx_hash)
}

// repeated bytes input_cells = 2;
inline int Parts::_internal_input_cells_size() const {
  return _impl_.input_cells_.size();
}
inline int Parts::input_cells_size() const {
  return _internal_input_cells_size();
}
inline void Parts::clear_input_cells() {
  _impl_.input_cells_.Clear();
}
inline std::string* Parts::add_input_cells() {
  std::string* _s = _internal_add_input_cells();
  // @@protoc_insertion_point(field_add_mutable:generated.traces.Parts.input_cells)
  return _s;
}
inline const std::string& Parts::_internal_input_cells(int index) const {
  return _impl_.input_cells_.Get(index);
}
inline const std::string& Parts::input_cells(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Parts.input_cells)
  return _internal_input_cells(index);
}
inline std::string* Parts::mutable_input_cells(int index) {
  // @@protoc_insertion_point(field_mutable:generated.traces.Parts.input_cells)
  return _impl_.input_cells_.Mutable(index);
}
inline void Parts::set_input_cells(int index, const std::string& value) {
  _impl_.input_cells_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set:generated.traces.Parts.input_cells)
}
inline void Parts::set_input_cells(int index, std::string&& value) {
  _impl_.input_cells_.Mutable(index)->assign(std::move(value));
  // @@protoc_insertion_point(field_set:generated.traces.Parts.input_cells)
}
inline void Parts::set_input_cells(int index, const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.input_cells_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set_char:generated.traces.Parts.input_cells)
}
inline void Parts::set_input_cells(int index, const void* value, size_t size) {
  _impl_.input_cells_.Mutable(index)->assign(
    reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_set_pointer:generated.traces.Parts.input_cells)
}
inline std::string* Parts::_internal_add_input_cells() {
  return _impl_.input_cells_.Add();
}
inline void Parts::add_input_cells(const std::string& value) {
  _impl_.input_cells_.Add()->assign(value);
  // @@protoc_insertion_point(field_add:generated.traces.Parts.input_cells)
}
inline void Parts::add_input_cells(std::string&& value) {
  _impl_.input_cells_.Add(std::move(value));
  // @@protoc_insertion_point(field_add:generated.traces.Parts.input_cells)
}
inline void Parts::add_input_cells(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.input_cells_.Add()->assign(value);
  // @@protoc_insertion_point(field_add_char:generated.traces.Parts.input_cells)
}
inline void Parts::add_input_cells(const void* value, size_t size) {
  _impl_.input_cells_.Add()->assign(reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_add_pointer:generated.traces.Parts.input_cells)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>&
Parts::input_cells() const {
  // @@protoc_insertion_point(field_list:generated.traces.Parts.input_cells)
  return _impl_.input_cells_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>*
Parts::mutable_input_cells() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Parts.input_cells)
  return &_impl_.input_cells_;
}

// repeated bytes input_cell_data = 3;
inline int Parts::_internal_input_cell_data_size() const {
  return _impl_.input_cell_data_.size();
}
inline int Parts::input_cell_data_size() const {
  return _internal_input_cell_data_size();
}
inline void Parts::clear_input_cell_data() {
  _impl_.input_cell_data_.Clear();
}
inline std::string* Parts::add_input_cell_data() {
  std::string* _s = _internal_add_input_cell_data();
  // @@protoc_insertion_point(field_add_mutable:generated.traces.Parts.input_cell_data)
  return _s;
}
inline const std::string& Parts::_internal_input_cell_data(int index) const {
  return _impl_.input_cell_data_.Get(index);
}
inline const std::string& Parts::input_cell_data(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Parts.input_cell_data)
  return _internal_input_cell_data(index);
}
inline std::string* Parts::mutable_input_cell_data(int index) {
  // @@protoc_insertion_point(field_mutable:generated.traces.Parts.input_cell_data)
  return _impl_.input_cell_data_.Mutable(index);
}
inline void Parts::set_input_cell_data(int index, const std::string& value) {
  _impl_.input_cell_data_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set:generated.traces.Parts.input_cell_data)
}
inline void Parts::set_input_cell_data(int index, std::string&& value) {
  _impl_.input_cell_data_.Mutable(index)->assign(std::move(value));
  // @@protoc_insertion_point(field_set:generated.traces.Parts.input_cell_data)
}
inline void Parts::set_input_cell_data(int index, const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.input_cell_data_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set_char:generated.traces.Parts.input_cell_data)
}
inline void Parts::set_input_cell_data(int index, const void* value, size_t size) {
  _impl_.input_cell_data_.Mutable(index)->assign(
    reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_set_pointer:generated.traces.Parts.input_cell_data)
}
inline std::string* Parts::_internal_add_input_cell_data() {
  return _impl_.input_cell_data_.Add();
}
inline void Parts::add_input_cell_data(const std::string& value) {
  _impl_.input_cell_data_.Add()->assign(value);
  // @@protoc_insertion_point(field_add:generated.traces.Parts.input_cell_data)
}
inline void Parts::add_input_cell_data(std::string&& value) {
  _impl_.input_cell_data_.Add(std::move(value));
  // @@protoc_insertion_point(field_add:generated.traces.Parts.input_cell_data)
}
inline void Parts::add_input_cell_data(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.input_cell_data_.Add()->assign(value);
  // @@protoc_insertion_point(field_add_char:generated.traces.Parts.input_cell_data)
}
inline void Parts::add_input_cell_data(const void* value, size_t size) {
  _impl_.input_cell_data_.Add()->assign(reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_add_pointer:generated.traces.Parts.input_cell_data)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>&
Parts::input_cell_data() const {
  // @@protoc_insertion_point(field_list:generated.traces.Parts.input_cell_data)
  return _impl_.input_cell_data_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>*
Parts::mutable_input_cell_data() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Parts.input_cell_data)
  return &_impl_.input_cell_data_;
}

// repeated bytes witnesses = 4;
inline int Parts::_internal_witnesses_size() const {
  return _impl_.witnesses_.size();
}
inline int Parts::witnesses_size() const {
  return _internal_witnesses_size();
}
inline void Parts::clear_witnesses() {
  _impl_.witnesses_.Clear();
}
inline std::string* Parts::add_witnesses() {
  std::string* _s = _internal_add_witnesses();
  // @@protoc_insertion_point(field_add_mutable:generated.traces.Parts.witnesses)
  return _s;
}
inline const std::string& Parts::_internal_witnesses(int index) const {
  return _impl_.witnesses_.Get(index);
}
inline const std::string& Parts::witnesses(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Parts.witnesses)
  return _internal_witnesses(index);
}
inline std::string* Parts::mutable_witnesses(int index) {
  // @@protoc_insertion_point(field_mutable:generated.traces.Parts.witnesses)
  return _impl_.witnesses_.Mutable(index);
}
inline void Parts::set_witnesses(int index, const std::string& value) {
  _impl_.witnesses_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set:generated.traces.Parts.witnesses)
}
inline void Parts::set_witnesses(int index, std::string&& value) {
  _impl_.witnesses_.Mutable(index)->assign(std::move(value));
  // @@protoc_insertion_point(field_set:generated.traces.Parts.witnesses)
}
inline void Parts::set_witnesses(int index, const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.witnesses_.Mutable(index)->assign(value);
  // @@protoc_insertion_point(field_set_char:generated.traces.Parts.witnesses)
}
inline void Parts::set_witnesses(int index, const void* value, size_t size) {
  _impl_.witnesses_.Mutable(index)->assign(
    reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_set_pointer:generated.traces.Parts.witnesses)
}
inline std::string* Parts::_internal_add_witnesses() {
  return _impl_.witnesses_.Add();
}
inline void Parts::add_witnesses(const std::string& value) {
  _impl_.witnesses_.Add()->assign(value);
  // @@protoc_insertion_point(field_add:generated.traces.Parts.witnesses)
}
inline void Parts::add_witnesses(std::string&& value) {
  _impl_.witnesses_.Add(std::move(value));
  // @@protoc_insertion_point(field_add:generated.traces.Parts.witnesses)
}
inline void Parts::add_witnesses(const char* value) {
  GOOGLE_DCHECK(value != nullptr);
  _impl_.witnesses_.Add()->assign(value);
  // @@protoc_insertion_point(field_add_char:generated.traces.Parts.witnesses)
}
inline void Parts::add_witnesses(const void* value, size_t size) {
  _impl_.witnesses_.Add()->assign(reinterpret_cast<const char*>(value), size);
  // @@protoc_insertion_point(field_add_pointer:generated.traces.Parts.witnesses)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>&
Parts::witnesses() const {
  // @@protoc_insertion_point(field_list:generated.traces.Parts.witnesses)
  return _impl_.witnesses_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedPtrField<std::string>*
Parts::mutable_witnesses() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Parts.witnesses)
  return &_impl_.witnesses_;
}

// repeated uint64 inherited_fds = 5;
inline int Parts::_internal_inherited_fds_size() const {
  return _impl_.inherited_fds_.size();
}
inline int Parts::inherited_fds_size() const {
  return _internal_inherited_fds_size();
}
inline void Parts::clear_inherited_fds() {
  _impl_.inherited_fds_.Clear();
}
inline uint64_t Parts::_internal_inherited_fds(int index) const {
  return _impl_.inherited_fds_.Get(index);
}
inline uint64_t Parts::inherited_fds(int index) const {
  // @@protoc_insertion_point(field_get:generated.traces.Parts.inherited_fds)
  return _internal_inherited_fds(index);
}
inline void Parts::set_inherited_fds(int index, uint64_t value) {
  _impl_.inherited_fds_.Set(index, value);
  // @@protoc_insertion_point(field_set:generated.traces.Parts.inherited_fds)
}
inline void Parts::_internal_add_inherited_fds(uint64_t value) {
  _impl_.inherited_fds_.Add(value);
}
inline void Parts::add_inherited_fds(uint64_t value) {
  _internal_add_inherited_fds(value);
  // @@protoc_insertion_point(field_add:generated.traces.Parts.inherited_fds)
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
Parts::_internal_inherited_fds() const {
  return _impl_.inherited_fds_;
}
inline const ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >&
Parts::inherited_fds() const {
  // @@protoc_insertion_point(field_list:generated.traces.Parts.inherited_fds)
  return _internal_inherited_fds();
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
Parts::_internal_mutable_inherited_fds() {
  return &_impl_.inherited_fds_;
}
inline ::PROTOBUF_NAMESPACE_ID::RepeatedField< uint64_t >*
Parts::mutable_inherited_fds() {
  // @@protoc_insertion_point(field_mutable_list:generated.traces.Parts.inherited_fds)
  return _internal_mutable_inherited_fds();
}

// map<uint64, bytes> read_data = 6;
inline int Parts::_internal_read_data_size() const {
  return _impl_.read_data_.size();
}
inline int Parts::read_data_size() const {
  return _internal_read_data_size();
}
inline void Parts::clear_read_data() {
  _impl_.read_data_.Clear();
}
inline const ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >&
Parts::_internal_read_data() const {
  return _impl_.read_data_.GetMap();
}
inline const ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >&
Parts::read_data() const {
  // @@protoc_insertion_point(field_map:generated.traces.Parts.read_data)
  return _internal_read_data();
}
inline ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >*
Parts::_internal_mutable_read_data() {
  return _impl_.read_data_.MutableMap();
}
inline ::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >*
Parts::mutable_read_data() {
  // @@protoc_insertion_point(field_mutable_map:generated.traces.Parts.read_data)
  return _internal_mutable_read_data();
}

// .generated.traces.Syscalls other_syscalls = 7;
inline bool Parts::_internal_has_other_syscalls() const {
  return this != internal_default_instance() && _impl_.other_syscalls_ != nullptr;
}
inline bool Parts::has_other_syscalls() const {
  return _internal_has_other_syscalls();
}
inline void Parts::clear_other_syscalls() {
  if (GetArenaForAllocation() == nullptr && _impl_.other_syscalls_ != nullptr) {
    delete _impl_.other_syscalls_;
  }
  _impl_.other_syscalls_ = nullptr;
}
inline const ::generated::traces::Syscalls& Parts::_internal_other_syscalls() const {
  const ::generated::traces::Syscalls* p = _impl_.other_syscalls_;
  return p != nullptr ? *p : reinterpret_cast<const ::generated::traces::Syscalls&>(
      ::generated::traces::_Syscalls_default_instance_);
}
inline const ::generated::traces::Syscalls& Parts::other_syscalls() const {
  // @@protoc_insertion_point(field_get:generated.traces.Parts.other_syscalls)
  return _internal_other_syscalls();
}
inline void Parts::unsafe_arena_set_allocated_other_syscalls(
    ::generated::traces::Syscalls* other_syscalls) {
  if (GetArenaForAllocation() == nullptr) {
    delete reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(_impl_.other_syscalls_);
  }
  _impl_.other_syscalls_ = other_syscalls;
  if (other_syscalls) {
    
  } else {
    
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:generated.traces.Parts.other_syscalls)
}
inline ::generated::traces::Syscalls* Parts::release_other_syscalls() {
  
  ::generated::traces::Syscalls* temp = _impl_.other_syscalls_;
  _impl_.other_syscalls_ = nullptr;
#ifdef PROTOBUF_FORCE_COPY_IN_RELEASE
  auto* old =  reinterpret_cast<::PROTOBUF_NAMESPACE_ID::MessageLite*>(temp);
  temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  if (GetArenaForAllocation() == nullptr) { delete old; }
#else  // PROTOBUF_FORCE_COPY_IN_RELEASE
  if (GetArenaForAllocation() != nullptr) {
    temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
  }
#endif  // !PROTOBUF_FORCE_COPY_IN_RELEASE
  return temp;
}
inline ::generated::traces::Syscalls* Parts::unsafe_arena_release_other_syscalls() {
  // @@protoc_insertion_point(field_release:generated.traces.Parts.other_syscalls)
  
  ::generated::traces::Syscalls* temp = _impl_.other_syscalls_;
  _impl_.other_syscalls_ = nullptr;
  return temp;
}
inline ::generated::traces::Syscalls* Parts::_internal_mutable_other_syscalls() {
  
  if (_impl_.other_syscalls_ == nullptr) {
    auto* p = CreateMaybeMessage<::generated::traces::Syscalls>(GetArenaForAllocation());
    _impl_.other_syscalls_ = p;
  }
  return _impl_.other_syscalls_;
}
inline ::generated::traces::Syscalls* Parts::mutable_other_syscalls() {
  ::generated::traces::Syscalls* _msg = _internal_mutable_other_syscalls();
  // @@protoc_insertion_point(field_mutable:generated.traces.Parts.other_syscalls)
  return _msg;
}
inline void Parts::set_allocated_other_syscalls(::generated::traces::Syscalls* other_syscalls) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  if (message_arena == nullptr) {
    delete _impl_.other_syscalls_;
  }
  if (other_syscalls) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
        ::PROTOBUF_NAMESPACE_ID::Arena::InternalGetOwningArena(other_syscalls);
    if (message_arena != submessage_arena) {
      other_syscalls = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, other_syscalls, submessage_arena);
    }
    
  } else {
    
  }
  _impl_.other_syscalls_ = other_syscalls;
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Parts.other_syscalls)
}

// -------------------------------------------------------------------

// Root

// .generated.traces.Parts parts = 1;
inline bool Root::_internal_has_parts() const {
  return value_case() == kParts;
}
inline bool Root::has_parts() const {
  return _internal_has_parts();
}
inline void Root::set_has_parts() {
  _impl_._oneof_case_[0] = kParts;
}
inline void Root::clear_parts() {
  if (_internal_has_parts()) {
    if (GetArenaForAllocation() == nullptr) {
      delete _impl_.value_.parts_;
    }
    clear_has_value();
  }
}
inline ::generated::traces::Parts* Root::release_parts() {
  // @@protoc_insertion_point(field_release:generated.traces.Root.parts)
  if (_internal_has_parts()) {
    clear_has_value();
    ::generated::traces::Parts* temp = _impl_.value_.parts_;
    if (GetArenaForAllocation() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    _impl_.value_.parts_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::generated::traces::Parts& Root::_internal_parts() const {
  return _internal_has_parts()
      ? *_impl_.value_.parts_
      : reinterpret_cast< ::generated::traces::Parts&>(::generated::traces::_Parts_default_instance_);
}
inline const ::generated::traces::Parts& Root::parts() const {
  // @@protoc_insertion_point(field_get:generated.traces.Root.parts)
  return _internal_parts();
}
inline ::generated::traces::Parts* Root::unsafe_arena_release_parts() {
  // @@protoc_insertion_point(field_unsafe_arena_release:generated.traces.Root.parts)
  if (_internal_has_parts()) {
    clear_has_value();
    ::generated::traces::Parts* temp = _impl_.value_.parts_;
    _impl_.value_.parts_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void Root::unsafe_arena_set_allocated_parts(::generated::traces::Parts* parts) {
  clear_value();
  if (parts) {
    set_has_parts();
    _impl_.value_.parts_ = parts;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:generated.traces.Root.parts)
}
inline ::generated::traces::Parts* Root::_internal_mutable_parts() {
  if (!_internal_has_parts()) {
    clear_value();
    set_has_parts();
    _impl_.value_.parts_ = CreateMaybeMessage< ::generated::traces::Parts >(GetArenaForAllocation());
  }
  return _impl_.value_.parts_;
}
inline ::generated::traces::Parts* Root::mutable_parts() {
  ::generated::traces::Parts* _msg = _internal_mutable_parts();
  // @@protoc_insertion_point(field_mutable:generated.traces.Root.parts)
  return _msg;
}

// .generated.traces.Syscalls syscalls = 3;
inline bool Root::_internal_has_syscalls() const {
  return value_case() == kSyscalls;
}
inline bool Root::has_syscalls() const {
  return _internal_has_syscalls();
}
inline void Root::set_has_syscalls() {
  _impl_._oneof_case_[0] = kSyscalls;
}
inline void Root::clear_syscalls() {
  if (_internal_has_syscalls()) {
    if (GetArenaForAllocation() == nullptr) {
      delete _impl_.value_.syscalls_;
    }
    clear_has_value();
  }
}
inline ::generated::traces::Syscalls* Root::release_syscalls() {
  // @@protoc_insertion_point(field_release:generated.traces.Root.syscalls)
  if (_internal_has_syscalls()) {
    clear_has_value();
    ::generated::traces::Syscalls* temp = _impl_.value_.syscalls_;
    if (GetArenaForAllocation() != nullptr) {
      temp = ::PROTOBUF_NAMESPACE_ID::internal::DuplicateIfNonNull(temp);
    }
    _impl_.value_.syscalls_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline const ::generated::traces::Syscalls& Root::_internal_syscalls() const {
  return _internal_has_syscalls()
      ? *_impl_.value_.syscalls_
      : reinterpret_cast< ::generated::traces::Syscalls&>(::generated::traces::_Syscalls_default_instance_);
}
inline const ::generated::traces::Syscalls& Root::syscalls() const {
  // @@protoc_insertion_point(field_get:generated.traces.Root.syscalls)
  return _internal_syscalls();
}
inline ::generated::traces::Syscalls* Root::unsafe_arena_release_syscalls() {
  // @@protoc_insertion_point(field_unsafe_arena_release:generated.traces.Root.syscalls)
  if (_internal_has_syscalls()) {
    clear_has_value();
    ::generated::traces::Syscalls* temp = _impl_.value_.syscalls_;
    _impl_.value_.syscalls_ = nullptr;
    return temp;
  } else {
    return nullptr;
  }
}
inline void Root::unsafe_arena_set_allocated_syscalls(::generated::traces::Syscalls* syscalls) {
  clear_value();
  if (syscalls) {
    set_has_syscalls();
    _impl_.value_.syscalls_ = syscalls;
  }
  // @@protoc_insertion_point(field_unsafe_arena_set_allocated:generated.traces.Root.syscalls)
}
inline ::generated::traces::Syscalls* Root::_internal_mutable_syscalls() {
  if (!_internal_has_syscalls()) {
    clear_value();
    set_has_syscalls();
    _impl_.value_.syscalls_ = CreateMaybeMessage< ::generated::traces::Syscalls >(GetArenaForAllocation());
  }
  return _impl_.value_.syscalls_;
}
inline ::generated::traces::Syscalls* Root::mutable_syscalls() {
  ::generated::traces::Syscalls* _msg = _internal_mutable_syscalls();
  // @@protoc_insertion_point(field_mutable:generated.traces.Root.syscalls)
  return _msg;
}

inline bool Root::has_value() const {
  return value_case() != VALUE_NOT_SET;
}
inline void Root::clear_has_value() {
  _impl_._oneof_case_[0] = VALUE_NOT_SET;
}
inline Root::ValueCase Root::value_case() const {
  return Root::ValueCase(_impl_._oneof_case_[0]);
}
#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------

// -------------------------------------------------------------------

// -------------------------------------------------------------------

// -------------------------------------------------------------------

// -------------------------------------------------------------------

// -------------------------------------------------------------------

// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace traces
}  // namespace generated

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_traces_2eproto
/* End of traces.pb.h */

int ckb_fuzzing_start_syscall_flavor(
    const generated::traces::Syscalls* syscalls);

#endif /* CKB_FUZZING_SYSCALLS_INTERNAL_H_ */
/* End of fuzzing_syscalls_internal.h */
#endif /* CKB_FUZZING_INCLUDE_INTERNAL_DEFS */

/* Extra syscall utilities that can be handy */
#ifdef CKB_FUZZING_INCLUDE_SYSCALL_UTILS
/* Start of ckb_syscall_utils.h */
#ifndef CKB_C_STDLIB_CKB_SYSCALL_UTILS_H_
#define CKB_C_STDLIB_CKB_SYSCALL_UTILS_H_

#include <string.h>

/* ckb_consts.h has already been included. */
/* ckb_syscall_apis.h has already been included. */

#ifndef CKB_STDLIB_NO_SYSCALL_IMPL

int ckb_checked_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_tx_hash(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script_hash(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_cell(void* addr, uint64_t* len, size_t offset,
                          size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_input(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_input(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_header(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_header(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_witness(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_transaction(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_transaction(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                                     size_t index, size_t source,
                                     size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_header_by_field(addr, len, offset, index, source, field);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                                    size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_input_by_field(addr, len, offset, index, source, field);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_data(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                                 size_t* type_source) {
  *type_source = CKB_SOURCE_GROUP_INPUT;
  uint64_t tmp_len = 0;
  if (ckb_load_cell_by_field(NULL, &tmp_len, 0, 0, CKB_SOURCE_GROUP_INPUT,
                             CKB_CELL_FIELD_CAPACITY) ==
      CKB_INDEX_OUT_OF_BOUND) {
    *type_source = CKB_SOURCE_GROUP_OUTPUT;
  }

  return ckb_checked_load_witness(buf, len, 0, index, *type_source);
}

int ckb_calculate_inputs_len() {
  uint64_t len = 0;
  /* lower bound, at least tx has one input */
  int lo = 0;
  /* higher bound */
  int hi = 4;
  int ret;
  /* try to load input until failing to increase lo and hi */
  while (1) {
    ret = ckb_load_input_by_field(NULL, &len, 0, hi, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = hi;
      hi *= 2;
    } else {
      break;
    }
  }

  /* now we get our lower bound and higher bound,
   count number of inputs by binary search */
  int i;
  while (lo + 1 != hi) {
    i = (lo + hi) / 2;
    ret = ckb_load_input_by_field(NULL, &len, 0, i, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = i;
    } else {
      hi = i;
    }
  }
  /* now lo is last input index and hi is length of inputs */
  return hi;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  size_t current = 0;
  size_t field =
      (hash_type == 1) ? CKB_CELL_FIELD_TYPE_HASH : CKB_CELL_FIELD_DATA_HASH;
  while (current < SIZE_MAX) {
    uint64_t len = 32;
    uint8_t hash[32];

    int ret = ckb_load_cell_by_field(hash, &len, 0, current,
                                     CKB_SOURCE_CELL_DEP, field);
    switch (ret) {
      case CKB_ITEM_MISSING:
        break;
      case CKB_SUCCESS:
        if (memcmp(code_hash, hash, 32) == 0) {
          /* Found a match */
          *index = current;
          return CKB_SUCCESS;
        }
        break;
      default:
        return CKB_INDEX_OUT_OF_BOUND;
    }
    current++;
  }
  return CKB_INDEX_OUT_OF_BOUND;
}

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index) {
  return ckb_look_for_dep_with_hash2(data_hash, 0, index);
}

int ckb_exec_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                  uint32_t length, int argc, const char* argv[]) {
  size_t index = SIZE_MAX;
  int ret = ckb_look_for_dep_with_hash2(code_hash, hash_type, &index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  size_t bounds = ((size_t)offset << 32) | length;
  return ckb_exec(index, CKB_SOURCE_CELL_DEP, 0, bounds, argc, argv);
}

int ckb_spawn_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                   uint32_t length, spawn_args_t* spawn_args) {
  size_t index = SIZE_MAX;
  int ret = ckb_look_for_dep_with_hash2(code_hash, hash_type, &index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  size_t bounds = ((size_t)offset << 32) | length;
  return ckb_spawn(index, CKB_SOURCE_CELL_DEP, 0, bounds, spawn_args);
}

#endif /* CKB_STDLIB_NO_SYSCALL_IMPL */

#endif /* CKB_C_STDLIB_CKB_SYSCALL_UTILS_H_ */
/* End of ckb_syscall_utils.h */
#endif /* CKB_FUZZING_INCLUDE_SYSCALL_UTILS */

#ifdef CKB_FUZZING_INCLUDE_PROTOBUF_IMPL
/* Start of traces.pb.cc */
// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: traces.proto

/* traces.pb.h has already been included. */

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG

namespace _pb = ::PROTOBUF_NAMESPACE_ID;
namespace _pbi = _pb::internal;

namespace generated {
namespace traces {
PROTOBUF_CONSTEXPR Terminated::Terminated(
    ::_pbi::ConstantInitialized) {}
struct TerminatedDefaultTypeInternal {
  PROTOBUF_CONSTEXPR TerminatedDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~TerminatedDefaultTypeInternal() {}
  union {
    Terminated _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 TerminatedDefaultTypeInternal _Terminated_default_instance_;
PROTOBUF_CONSTEXPR IoData::IoData(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.available_data_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.additional_length_)*/uint64_t{0u}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct IoDataDefaultTypeInternal {
  PROTOBUF_CONSTEXPR IoDataDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~IoDataDefaultTypeInternal() {}
  union {
    IoData _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 IoDataDefaultTypeInternal _IoData_default_instance_;
PROTOBUF_CONSTEXPR Fds::Fds(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.fds_)*/{}
  , /*decltype(_impl_._fds_cached_byte_size_)*/{0}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct FdsDefaultTypeInternal {
  PROTOBUF_CONSTEXPR FdsDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~FdsDefaultTypeInternal() {}
  union {
    Fds _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 FdsDefaultTypeInternal _Fds_default_instance_;
PROTOBUF_CONSTEXPR Syscall::Syscall(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.value_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}
  , /*decltype(_impl_._oneof_case_)*/{}} {}
struct SyscallDefaultTypeInternal {
  PROTOBUF_CONSTEXPR SyscallDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~SyscallDefaultTypeInternal() {}
  union {
    Syscall _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 SyscallDefaultTypeInternal _Syscall_default_instance_;
PROTOBUF_CONSTEXPR Syscalls::Syscalls(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.syscalls_)*/{}
  , /*decltype(_impl_.args_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct SyscallsDefaultTypeInternal {
  PROTOBUF_CONSTEXPR SyscallsDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~SyscallsDefaultTypeInternal() {}
  union {
    Syscalls _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 SyscallsDefaultTypeInternal _Syscalls_default_instance_;
PROTOBUF_CONSTEXPR Parts_ReadDataEntry_DoNotUse::Parts_ReadDataEntry_DoNotUse(
    ::_pbi::ConstantInitialized) {}
struct Parts_ReadDataEntry_DoNotUseDefaultTypeInternal {
  PROTOBUF_CONSTEXPR Parts_ReadDataEntry_DoNotUseDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~Parts_ReadDataEntry_DoNotUseDefaultTypeInternal() {}
  union {
    Parts_ReadDataEntry_DoNotUse _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 Parts_ReadDataEntry_DoNotUseDefaultTypeInternal _Parts_ReadDataEntry_DoNotUse_default_instance_;
PROTOBUF_CONSTEXPR Parts::Parts(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.input_cells_)*/{}
  , /*decltype(_impl_.input_cell_data_)*/{}
  , /*decltype(_impl_.witnesses_)*/{}
  , /*decltype(_impl_.inherited_fds_)*/{}
  , /*decltype(_impl_._inherited_fds_cached_byte_size_)*/{0}
  , /*decltype(_impl_.read_data_)*/{::_pbi::ConstantInitialized()}
  , /*decltype(_impl_.tx_hash_)*/{&::_pbi::fixed_address_empty_string, ::_pbi::ConstantInitialized{}}
  , /*decltype(_impl_.other_syscalls_)*/nullptr
  , /*decltype(_impl_._cached_size_)*/{}} {}
struct PartsDefaultTypeInternal {
  PROTOBUF_CONSTEXPR PartsDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~PartsDefaultTypeInternal() {}
  union {
    Parts _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 PartsDefaultTypeInternal _Parts_default_instance_;
PROTOBUF_CONSTEXPR Root::Root(
    ::_pbi::ConstantInitialized): _impl_{
    /*decltype(_impl_.value_)*/{}
  , /*decltype(_impl_._cached_size_)*/{}
  , /*decltype(_impl_._oneof_case_)*/{}} {}
struct RootDefaultTypeInternal {
  PROTOBUF_CONSTEXPR RootDefaultTypeInternal()
      : _instance(::_pbi::ConstantInitialized{}) {}
  ~RootDefaultTypeInternal() {}
  union {
    Root _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT PROTOBUF_ATTRIBUTE_INIT_PRIORITY1 RootDefaultTypeInternal _Root_default_instance_;
}  // namespace traces
}  // namespace generated
static ::_pb::Metadata file_level_metadata_traces_2eproto[8];
static constexpr ::_pb::EnumDescriptor const** file_level_enum_descriptors_traces_2eproto = nullptr;
static constexpr ::_pb::ServiceDescriptor const** file_level_service_descriptors_traces_2eproto = nullptr;

const uint32_t TableStruct_traces_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Terminated, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::IoData, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::generated::traces::IoData, _impl_.available_data_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::IoData, _impl_.additional_length_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Fds, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Fds, _impl_.fds_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Syscall, _internal_metadata_),
  ~0u,  // no _extensions_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Syscall, _impl_._oneof_case_[0]),
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  ::_pbi::kInvalidFieldOffsetTag,
  ::_pbi::kInvalidFieldOffsetTag,
  ::_pbi::kInvalidFieldOffsetTag,
  ::_pbi::kInvalidFieldOffsetTag,
  ::_pbi::kInvalidFieldOffsetTag,
  PROTOBUF_FIELD_OFFSET(::generated::traces::Syscall, _impl_.value_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Syscalls, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Syscalls, _impl_.syscalls_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Syscalls, _impl_.args_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts_ReadDataEntry_DoNotUse, _has_bits_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts_ReadDataEntry_DoNotUse, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts_ReadDataEntry_DoNotUse, key_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts_ReadDataEntry_DoNotUse, value_),
  0,
  1,
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.tx_hash_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.input_cells_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.input_cell_data_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.witnesses_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.inherited_fds_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.read_data_),
  PROTOBUF_FIELD_OFFSET(::generated::traces::Parts, _impl_.other_syscalls_),
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Root, _internal_metadata_),
  ~0u,  // no _extensions_
  PROTOBUF_FIELD_OFFSET(::generated::traces::Root, _impl_._oneof_case_[0]),
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  ::_pbi::kInvalidFieldOffsetTag,
  ::_pbi::kInvalidFieldOffsetTag,
  PROTOBUF_FIELD_OFFSET(::generated::traces::Root, _impl_.value_),
};
static const ::_pbi::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::generated::traces::Terminated)},
  { 6, -1, -1, sizeof(::generated::traces::IoData)},
  { 14, -1, -1, sizeof(::generated::traces::Fds)},
  { 21, -1, -1, sizeof(::generated::traces::Syscall)},
  { 33, -1, -1, sizeof(::generated::traces::Syscalls)},
  { 41, 49, -1, sizeof(::generated::traces::Parts_ReadDataEntry_DoNotUse)},
  { 51, -1, -1, sizeof(::generated::traces::Parts)},
  { 64, -1, -1, sizeof(::generated::traces::Root)},
};

static const ::_pb::Message* const file_default_instances[] = {
  &::generated::traces::_Terminated_default_instance_._instance,
  &::generated::traces::_IoData_default_instance_._instance,
  &::generated::traces::_Fds_default_instance_._instance,
  &::generated::traces::_Syscall_default_instance_._instance,
  &::generated::traces::_Syscalls_default_instance_._instance,
  &::generated::traces::_Parts_ReadDataEntry_DoNotUse_default_instance_._instance,
  &::generated::traces::_Parts_default_instance_._instance,
  &::generated::traces::_Root_default_instance_._instance,
};

const char descriptor_table_protodef_traces_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\014traces.proto\022\020generated.traces\"\014\n\nTerm"
  "inated\";\n\006IoData\022\026\n\016available_data\030\001 \001(\014"
  "\022\031\n\021additional_length\030\002 \001(\004\"\022\n\003Fds\022\013\n\003fd"
  "s\030\001 \003(\004\"\324\001\n\007Syscall\022\032\n\020return_with_code\030"
  "\001 \001(\003H\000\022\035\n\023success_output_data\030\002 \001(\004H\000\022+"
  "\n\007io_data\030\003 \001(\0132\030.generated.traces.IoDat"
  "aH\000\0222\n\nterminated\030\004 \001(\0132\034.generated.trac"
  "es.TerminatedH\000\022$\n\003fds\030\005 \001(\0132\025.generated"
  ".traces.FdsH\000B\007\n\005value\"E\n\010Syscalls\022+\n\010sy"
  "scalls\030\001 \003(\0132\031.generated.traces.Syscall\022"
  "\014\n\004args\030\002 \003(\014\"\217\002\n\005Parts\022\017\n\007tx_hash\030\001 \001(\014"
  "\022\023\n\013input_cells\030\002 \003(\014\022\027\n\017input_cell_data"
  "\030\003 \003(\014\022\021\n\twitnesses\030\004 \003(\014\022\025\n\rinherited_f"
  "ds\030\005 \003(\004\0228\n\tread_data\030\006 \003(\0132%.generated."
  "traces.Parts.ReadDataEntry\0222\n\016other_sysc"
  "alls\030\007 \001(\0132\032.generated.traces.Syscalls\032/"
  "\n\rReadDataEntry\022\013\n\003key\030\001 \001(\004\022\r\n\005value\030\002 "
  "\001(\014:\0028\001\"i\n\004Root\022(\n\005parts\030\001 \001(\0132\027.generat"
  "ed.traces.PartsH\000\022.\n\010syscalls\030\003 \001(\0132\032.ge"
  "nerated.traces.SyscallsH\000B\007\n\005valueb\006prot"
  "o3"
  ;
static ::_pbi::once_flag descriptor_table_traces_2eproto_once;
const ::_pbi::DescriptorTable descriptor_table_traces_2eproto = {
    false, false, 802, descriptor_table_protodef_traces_2eproto,
    "traces.proto",
    &descriptor_table_traces_2eproto_once, nullptr, 0, 8,
    schemas, file_default_instances, TableStruct_traces_2eproto::offsets,
    file_level_metadata_traces_2eproto, file_level_enum_descriptors_traces_2eproto,
    file_level_service_descriptors_traces_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::_pbi::DescriptorTable* descriptor_table_traces_2eproto_getter() {
  return &descriptor_table_traces_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY2 static ::_pbi::AddDescriptorsRunner dynamic_init_dummy_traces_2eproto(&descriptor_table_traces_2eproto);
namespace generated {
namespace traces {

// ===================================================================

class Terminated::_Internal {
 public:
};

Terminated::Terminated(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase(arena, is_message_owned) {
  // @@protoc_insertion_point(arena_constructor:generated.traces.Terminated)
}
Terminated::Terminated(const Terminated& from)
  : ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase() {
  Terminated* const _this = this; (void)_this;
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:generated.traces.Terminated)
}





const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Terminated::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase::CopyImpl,
    ::PROTOBUF_NAMESPACE_ID::internal::ZeroFieldsBase::MergeImpl,
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Terminated::GetClassData() const { return &_class_data_; }







::PROTOBUF_NAMESPACE_ID::Metadata Terminated::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[0]);
}

// ===================================================================

class IoData::_Internal {
 public:
};

IoData::IoData(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:generated.traces.IoData)
}
IoData::IoData(const IoData& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  IoData* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.available_data_){}
    , decltype(_impl_.additional_length_){}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _impl_.available_data_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.available_data_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_available_data().empty()) {
    _this->_impl_.available_data_.Set(from._internal_available_data(), 
      _this->GetArenaForAllocation());
  }
  _this->_impl_.additional_length_ = from._impl_.additional_length_;
  // @@protoc_insertion_point(copy_constructor:generated.traces.IoData)
}

inline void IoData::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.available_data_){}
    , decltype(_impl_.additional_length_){uint64_t{0u}}
    , /*decltype(_impl_._cached_size_)*/{}
  };
  _impl_.available_data_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.available_data_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

IoData::~IoData() {
  // @@protoc_insertion_point(destructor:generated.traces.IoData)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void IoData::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.available_data_.Destroy();
}

void IoData::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void IoData::Clear() {
// @@protoc_insertion_point(message_clear_start:generated.traces.IoData)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.available_data_.ClearToEmpty();
  _impl_.additional_length_ = uint64_t{0u};
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* IoData::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes available_data = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_available_data();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // uint64 additional_length = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 16)) {
          _impl_.additional_length_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* IoData::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:generated.traces.IoData)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes available_data = 1;
  if (!this->_internal_available_data().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_available_data(), target);
  }

  // uint64 additional_length = 2;
  if (this->_internal_additional_length() != 0) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteUInt64ToArray(2, this->_internal_additional_length(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:generated.traces.IoData)
  return target;
}

size_t IoData::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:generated.traces.IoData)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bytes available_data = 1;
  if (!this->_internal_available_data().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_available_data());
  }

  // uint64 additional_length = 2;
  if (this->_internal_additional_length() != 0) {
    total_size += ::_pbi::WireFormatLite::UInt64SizePlusOne(this->_internal_additional_length());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData IoData::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    IoData::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*IoData::GetClassData() const { return &_class_data_; }


void IoData::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<IoData*>(&to_msg);
  auto& from = static_cast<const IoData&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:generated.traces.IoData)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_available_data().empty()) {
    _this->_internal_set_available_data(from._internal_available_data());
  }
  if (from._internal_additional_length() != 0) {
    _this->_internal_set_additional_length(from._internal_additional_length());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void IoData::CopyFrom(const IoData& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:generated.traces.IoData)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool IoData::IsInitialized() const {
  return true;
}

void IoData::InternalSwap(IoData* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.available_data_, lhs_arena,
      &other->_impl_.available_data_, rhs_arena
  );
  swap(_impl_.additional_length_, other->_impl_.additional_length_);
}

::PROTOBUF_NAMESPACE_ID::Metadata IoData::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[1]);
}

// ===================================================================

class Fds::_Internal {
 public:
};

Fds::Fds(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:generated.traces.Fds)
}
Fds::Fds(const Fds& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  Fds* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.fds_){from._impl_.fds_}
    , /*decltype(_impl_._fds_cached_byte_size_)*/{0}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:generated.traces.Fds)
}

inline void Fds::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.fds_){arena}
    , /*decltype(_impl_._fds_cached_byte_size_)*/{0}
    , /*decltype(_impl_._cached_size_)*/{}
  };
}

Fds::~Fds() {
  // @@protoc_insertion_point(destructor:generated.traces.Fds)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void Fds::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.fds_.~RepeatedField();
}

void Fds::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void Fds::Clear() {
// @@protoc_insertion_point(message_clear_start:generated.traces.Fds)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.fds_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Fds::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated uint64 fds = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::PackedUInt64Parser(_internal_mutable_fds(), ptr, ctx);
          CHK_(ptr);
        } else if (static_cast<uint8_t>(tag) == 8) {
          _internal_add_fds(::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr));
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* Fds::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:generated.traces.Fds)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated uint64 fds = 1;
  {
    int byte_size = _impl_._fds_cached_byte_size_.load(std::memory_order_relaxed);
    if (byte_size > 0) {
      target = stream->WriteUInt64Packed(
          1, _internal_fds(), byte_size, target);
    }
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:generated.traces.Fds)
  return target;
}

size_t Fds::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:generated.traces.Fds)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated uint64 fds = 1;
  {
    size_t data_size = ::_pbi::WireFormatLite::
      UInt64Size(this->_impl_.fds_);
    if (data_size > 0) {
      total_size += 1 +
        ::_pbi::WireFormatLite::Int32Size(static_cast<int32_t>(data_size));
    }
    int cached_size = ::_pbi::ToCachedSize(data_size);
    _impl_._fds_cached_byte_size_.store(cached_size,
                                    std::memory_order_relaxed);
    total_size += data_size;
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Fds::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    Fds::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Fds::GetClassData() const { return &_class_data_; }


void Fds::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<Fds*>(&to_msg);
  auto& from = static_cast<const Fds&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:generated.traces.Fds)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  _this->_impl_.fds_.MergeFrom(from._impl_.fds_);
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Fds::CopyFrom(const Fds& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:generated.traces.Fds)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Fds::IsInitialized() const {
  return true;
}

void Fds::InternalSwap(Fds* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  _impl_.fds_.InternalSwap(&other->_impl_.fds_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Fds::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[2]);
}

// ===================================================================

class Syscall::_Internal {
 public:
  static const ::generated::traces::IoData& io_data(const Syscall* msg);
  static const ::generated::traces::Terminated& terminated(const Syscall* msg);
  static const ::generated::traces::Fds& fds(const Syscall* msg);
};

const ::generated::traces::IoData&
Syscall::_Internal::io_data(const Syscall* msg) {
  return *msg->_impl_.value_.io_data_;
}
const ::generated::traces::Terminated&
Syscall::_Internal::terminated(const Syscall* msg) {
  return *msg->_impl_.value_.terminated_;
}
const ::generated::traces::Fds&
Syscall::_Internal::fds(const Syscall* msg) {
  return *msg->_impl_.value_.fds_;
}
void Syscall::set_allocated_io_data(::generated::traces::IoData* io_data) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  clear_value();
  if (io_data) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      ::PROTOBUF_NAMESPACE_ID::Arena::InternalGetOwningArena(io_data);
    if (message_arena != submessage_arena) {
      io_data = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, io_data, submessage_arena);
    }
    set_has_io_data();
    _impl_.value_.io_data_ = io_data;
  }
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Syscall.io_data)
}
void Syscall::set_allocated_terminated(::generated::traces::Terminated* terminated) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  clear_value();
  if (terminated) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      ::PROTOBUF_NAMESPACE_ID::Arena::InternalGetOwningArena(terminated);
    if (message_arena != submessage_arena) {
      terminated = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, terminated, submessage_arena);
    }
    set_has_terminated();
    _impl_.value_.terminated_ = terminated;
  }
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Syscall.terminated)
}
void Syscall::set_allocated_fds(::generated::traces::Fds* fds) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  clear_value();
  if (fds) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      ::PROTOBUF_NAMESPACE_ID::Arena::InternalGetOwningArena(fds);
    if (message_arena != submessage_arena) {
      fds = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, fds, submessage_arena);
    }
    set_has_fds();
    _impl_.value_.fds_ = fds;
  }
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Syscall.fds)
}
Syscall::Syscall(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:generated.traces.Syscall)
}
Syscall::Syscall(const Syscall& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  Syscall* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.value_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , /*decltype(_impl_._oneof_case_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  clear_has_value();
  switch (from.value_case()) {
    case kReturnWithCode: {
      _this->_internal_set_return_with_code(from._internal_return_with_code());
      break;
    }
    case kSuccessOutputData: {
      _this->_internal_set_success_output_data(from._internal_success_output_data());
      break;
    }
    case kIoData: {
      _this->_internal_mutable_io_data()->::generated::traces::IoData::MergeFrom(
          from._internal_io_data());
      break;
    }
    case kTerminated: {
      _this->_internal_mutable_terminated()->::generated::traces::Terminated::MergeFrom(
          from._internal_terminated());
      break;
    }
    case kFds: {
      _this->_internal_mutable_fds()->::generated::traces::Fds::MergeFrom(
          from._internal_fds());
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  // @@protoc_insertion_point(copy_constructor:generated.traces.Syscall)
}

inline void Syscall::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.value_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , /*decltype(_impl_._oneof_case_)*/{}
  };
  clear_has_value();
}

Syscall::~Syscall() {
  // @@protoc_insertion_point(destructor:generated.traces.Syscall)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void Syscall::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  if (has_value()) {
    clear_value();
  }
}

void Syscall::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void Syscall::clear_value() {
// @@protoc_insertion_point(one_of_clear_start:generated.traces.Syscall)
  switch (value_case()) {
    case kReturnWithCode: {
      // No need to clear
      break;
    }
    case kSuccessOutputData: {
      // No need to clear
      break;
    }
    case kIoData: {
      if (GetArenaForAllocation() == nullptr) {
        delete _impl_.value_.io_data_;
      }
      break;
    }
    case kTerminated: {
      if (GetArenaForAllocation() == nullptr) {
        delete _impl_.value_.terminated_;
      }
      break;
    }
    case kFds: {
      if (GetArenaForAllocation() == nullptr) {
        delete _impl_.value_.fds_;
      }
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  _impl_._oneof_case_[0] = VALUE_NOT_SET;
}


void Syscall::Clear() {
// @@protoc_insertion_point(message_clear_start:generated.traces.Syscall)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  clear_value();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Syscall::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // int64 return_with_code = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 8)) {
          _internal_set_return_with_code(::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr));
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // uint64 success_output_data = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 16)) {
          _internal_set_success_output_data(::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr));
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // .generated.traces.IoData io_data = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 26)) {
          ptr = ctx->ParseMessage(_internal_mutable_io_data(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // .generated.traces.Terminated terminated = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 34)) {
          ptr = ctx->ParseMessage(_internal_mutable_terminated(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // .generated.traces.Fds fds = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 42)) {
          ptr = ctx->ParseMessage(_internal_mutable_fds(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* Syscall::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:generated.traces.Syscall)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // int64 return_with_code = 1;
  if (_internal_has_return_with_code()) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteInt64ToArray(1, this->_internal_return_with_code(), target);
  }

  // uint64 success_output_data = 2;
  if (_internal_has_success_output_data()) {
    target = stream->EnsureSpace(target);
    target = ::_pbi::WireFormatLite::WriteUInt64ToArray(2, this->_internal_success_output_data(), target);
  }

  // .generated.traces.IoData io_data = 3;
  if (_internal_has_io_data()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(3, _Internal::io_data(this),
        _Internal::io_data(this).GetCachedSize(), target, stream);
  }

  // .generated.traces.Terminated terminated = 4;
  if (_internal_has_terminated()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(4, _Internal::terminated(this),
        _Internal::terminated(this).GetCachedSize(), target, stream);
  }

  // .generated.traces.Fds fds = 5;
  if (_internal_has_fds()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(5, _Internal::fds(this),
        _Internal::fds(this).GetCachedSize(), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:generated.traces.Syscall)
  return target;
}

size_t Syscall::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:generated.traces.Syscall)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  switch (value_case()) {
    // int64 return_with_code = 1;
    case kReturnWithCode: {
      total_size += ::_pbi::WireFormatLite::Int64SizePlusOne(this->_internal_return_with_code());
      break;
    }
    // uint64 success_output_data = 2;
    case kSuccessOutputData: {
      total_size += ::_pbi::WireFormatLite::UInt64SizePlusOne(this->_internal_success_output_data());
      break;
    }
    // .generated.traces.IoData io_data = 3;
    case kIoData: {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
          *_impl_.value_.io_data_);
      break;
    }
    // .generated.traces.Terminated terminated = 4;
    case kTerminated: {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
          *_impl_.value_.terminated_);
      break;
    }
    // .generated.traces.Fds fds = 5;
    case kFds: {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
          *_impl_.value_.fds_);
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Syscall::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    Syscall::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Syscall::GetClassData() const { return &_class_data_; }


void Syscall::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<Syscall*>(&to_msg);
  auto& from = static_cast<const Syscall&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:generated.traces.Syscall)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  switch (from.value_case()) {
    case kReturnWithCode: {
      _this->_internal_set_return_with_code(from._internal_return_with_code());
      break;
    }
    case kSuccessOutputData: {
      _this->_internal_set_success_output_data(from._internal_success_output_data());
      break;
    }
    case kIoData: {
      _this->_internal_mutable_io_data()->::generated::traces::IoData::MergeFrom(
          from._internal_io_data());
      break;
    }
    case kTerminated: {
      _this->_internal_mutable_terminated()->::generated::traces::Terminated::MergeFrom(
          from._internal_terminated());
      break;
    }
    case kFds: {
      _this->_internal_mutable_fds()->::generated::traces::Fds::MergeFrom(
          from._internal_fds());
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Syscall::CopyFrom(const Syscall& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:generated.traces.Syscall)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Syscall::IsInitialized() const {
  return true;
}

void Syscall::InternalSwap(Syscall* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_.value_, other->_impl_.value_);
  swap(_impl_._oneof_case_[0], other->_impl_._oneof_case_[0]);
}

::PROTOBUF_NAMESPACE_ID::Metadata Syscall::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[3]);
}

// ===================================================================

class Syscalls::_Internal {
 public:
};

Syscalls::Syscalls(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:generated.traces.Syscalls)
}
Syscalls::Syscalls(const Syscalls& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  Syscalls* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.syscalls_){from._impl_.syscalls_}
    , decltype(_impl_.args_){from._impl_.args_}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:generated.traces.Syscalls)
}

inline void Syscalls::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.syscalls_){arena}
    , decltype(_impl_.args_){arena}
    , /*decltype(_impl_._cached_size_)*/{}
  };
}

Syscalls::~Syscalls() {
  // @@protoc_insertion_point(destructor:generated.traces.Syscalls)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void Syscalls::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.syscalls_.~RepeatedPtrField();
  _impl_.args_.~RepeatedPtrField();
}

void Syscalls::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void Syscalls::Clear() {
// @@protoc_insertion_point(message_clear_start:generated.traces.Syscalls)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.syscalls_.Clear();
  _impl_.args_.Clear();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Syscalls::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // repeated .generated.traces.Syscall syscalls = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_syscalls(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<10>(ptr));
        } else
          goto handle_unusual;
        continue;
      // repeated bytes args = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          ptr -= 1;
          do {
            ptr += 1;
            auto str = _internal_add_args();
            ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<18>(ptr));
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* Syscalls::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:generated.traces.Syscalls)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .generated.traces.Syscall syscalls = 1;
  for (unsigned i = 0,
      n = static_cast<unsigned>(this->_internal_syscalls_size()); i < n; i++) {
    const auto& repfield = this->_internal_syscalls(i);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
        InternalWriteMessage(1, repfield, repfield.GetCachedSize(), target, stream);
  }

  // repeated bytes args = 2;
  for (int i = 0, n = this->_internal_args_size(); i < n; i++) {
    const auto& s = this->_internal_args(i);
    target = stream->WriteBytes(2, s, target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:generated.traces.Syscalls)
  return target;
}

size_t Syscalls::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:generated.traces.Syscalls)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .generated.traces.Syscall syscalls = 1;
  total_size += 1UL * this->_internal_syscalls_size();
  for (const auto& msg : this->_impl_.syscalls_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  // repeated bytes args = 2;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(_impl_.args_.size());
  for (int i = 0, n = _impl_.args_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
      _impl_.args_.Get(i));
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Syscalls::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    Syscalls::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Syscalls::GetClassData() const { return &_class_data_; }


void Syscalls::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<Syscalls*>(&to_msg);
  auto& from = static_cast<const Syscalls&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:generated.traces.Syscalls)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  _this->_impl_.syscalls_.MergeFrom(from._impl_.syscalls_);
  _this->_impl_.args_.MergeFrom(from._impl_.args_);
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Syscalls::CopyFrom(const Syscalls& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:generated.traces.Syscalls)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Syscalls::IsInitialized() const {
  return true;
}

void Syscalls::InternalSwap(Syscalls* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  _impl_.syscalls_.InternalSwap(&other->_impl_.syscalls_);
  _impl_.args_.InternalSwap(&other->_impl_.args_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Syscalls::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[4]);
}

// ===================================================================

Parts_ReadDataEntry_DoNotUse::Parts_ReadDataEntry_DoNotUse() {}
Parts_ReadDataEntry_DoNotUse::Parts_ReadDataEntry_DoNotUse(::PROTOBUF_NAMESPACE_ID::Arena* arena)
    : SuperType(arena) {}
void Parts_ReadDataEntry_DoNotUse::MergeFrom(const Parts_ReadDataEntry_DoNotUse& other) {
  MergeFromInternal(other);
}
::PROTOBUF_NAMESPACE_ID::Metadata Parts_ReadDataEntry_DoNotUse::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[5]);
}

// ===================================================================

class Parts::_Internal {
 public:
  static const ::generated::traces::Syscalls& other_syscalls(const Parts* msg);
};

const ::generated::traces::Syscalls&
Parts::_Internal::other_syscalls(const Parts* msg) {
  return *msg->_impl_.other_syscalls_;
}
Parts::Parts(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  if (arena != nullptr && !is_message_owned) {
    arena->OwnCustomDestructor(this, &Parts::ArenaDtor);
  }
  // @@protoc_insertion_point(arena_constructor:generated.traces.Parts)
}
Parts::Parts(const Parts& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  Parts* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.input_cells_){from._impl_.input_cells_}
    , decltype(_impl_.input_cell_data_){from._impl_.input_cell_data_}
    , decltype(_impl_.witnesses_){from._impl_.witnesses_}
    , decltype(_impl_.inherited_fds_){from._impl_.inherited_fds_}
    , /*decltype(_impl_._inherited_fds_cached_byte_size_)*/{0}
    , /*decltype(_impl_.read_data_)*/{}
    , decltype(_impl_.tx_hash_){}
    , decltype(_impl_.other_syscalls_){nullptr}
    , /*decltype(_impl_._cached_size_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  _this->_impl_.read_data_.MergeFrom(from._impl_.read_data_);
  _impl_.tx_hash_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.tx_hash_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_tx_hash().empty()) {
    _this->_impl_.tx_hash_.Set(from._internal_tx_hash(), 
      _this->GetArenaForAllocation());
  }
  if (from._internal_has_other_syscalls()) {
    _this->_impl_.other_syscalls_ = new ::generated::traces::Syscalls(*from._impl_.other_syscalls_);
  }
  // @@protoc_insertion_point(copy_constructor:generated.traces.Parts)
}

inline void Parts::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.input_cells_){arena}
    , decltype(_impl_.input_cell_data_){arena}
    , decltype(_impl_.witnesses_){arena}
    , decltype(_impl_.inherited_fds_){arena}
    , /*decltype(_impl_._inherited_fds_cached_byte_size_)*/{0}
    , /*decltype(_impl_.read_data_)*/{::_pbi::ArenaInitialized(), arena}
    , decltype(_impl_.tx_hash_){}
    , decltype(_impl_.other_syscalls_){nullptr}
    , /*decltype(_impl_._cached_size_)*/{}
  };
  _impl_.tx_hash_.InitDefault();
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    _impl_.tx_hash_.Set("", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
}

Parts::~Parts() {
  // @@protoc_insertion_point(destructor:generated.traces.Parts)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    ArenaDtor(this);
    return;
  }
  SharedDtor();
}

inline void Parts::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  _impl_.input_cells_.~RepeatedPtrField();
  _impl_.input_cell_data_.~RepeatedPtrField();
  _impl_.witnesses_.~RepeatedPtrField();
  _impl_.inherited_fds_.~RepeatedField();
  _impl_.read_data_.Destruct();
  _impl_.read_data_.~MapField();
  _impl_.tx_hash_.Destroy();
  if (this != internal_default_instance()) delete _impl_.other_syscalls_;
}

void Parts::ArenaDtor(void* object) {
  Parts* _this = reinterpret_cast< Parts* >(object);
  _this->_impl_.read_data_.Destruct();
}
void Parts::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void Parts::Clear() {
// @@protoc_insertion_point(message_clear_start:generated.traces.Parts)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _impl_.input_cells_.Clear();
  _impl_.input_cell_data_.Clear();
  _impl_.witnesses_.Clear();
  _impl_.inherited_fds_.Clear();
  _impl_.read_data_.Clear();
  _impl_.tx_hash_.ClearToEmpty();
  if (GetArenaForAllocation() == nullptr && _impl_.other_syscalls_ != nullptr) {
    delete _impl_.other_syscalls_;
  }
  _impl_.other_syscalls_ = nullptr;
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Parts::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // bytes tx_hash = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_tx_hash();
          ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // repeated bytes input_cells = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 18)) {
          ptr -= 1;
          do {
            ptr += 1;
            auto str = _internal_add_input_cells();
            ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<18>(ptr));
        } else
          goto handle_unusual;
        continue;
      // repeated bytes input_cell_data = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 26)) {
          ptr -= 1;
          do {
            ptr += 1;
            auto str = _internal_add_input_cell_data();
            ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<26>(ptr));
        } else
          goto handle_unusual;
        continue;
      // repeated bytes witnesses = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 34)) {
          ptr -= 1;
          do {
            ptr += 1;
            auto str = _internal_add_witnesses();
            ptr = ::_pbi::InlineGreedyStringParser(str, ptr, ctx);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<34>(ptr));
        } else
          goto handle_unusual;
        continue;
      // repeated uint64 inherited_fds = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 42)) {
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::PackedUInt64Parser(_internal_mutable_inherited_fds(), ptr, ctx);
          CHK_(ptr);
        } else if (static_cast<uint8_t>(tag) == 40) {
          _internal_add_inherited_fds(::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr));
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // map<uint64, bytes> read_data = 6;
      case 6:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 50)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(&_impl_.read_data_, ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<50>(ptr));
        } else
          goto handle_unusual;
        continue;
      // .generated.traces.Syscalls other_syscalls = 7;
      case 7:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 58)) {
          ptr = ctx->ParseMessage(_internal_mutable_other_syscalls(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* Parts::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:generated.traces.Parts)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes tx_hash = 1;
  if (!this->_internal_tx_hash().empty()) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_tx_hash(), target);
  }

  // repeated bytes input_cells = 2;
  for (int i = 0, n = this->_internal_input_cells_size(); i < n; i++) {
    const auto& s = this->_internal_input_cells(i);
    target = stream->WriteBytes(2, s, target);
  }

  // repeated bytes input_cell_data = 3;
  for (int i = 0, n = this->_internal_input_cell_data_size(); i < n; i++) {
    const auto& s = this->_internal_input_cell_data(i);
    target = stream->WriteBytes(3, s, target);
  }

  // repeated bytes witnesses = 4;
  for (int i = 0, n = this->_internal_witnesses_size(); i < n; i++) {
    const auto& s = this->_internal_witnesses(i);
    target = stream->WriteBytes(4, s, target);
  }

  // repeated uint64 inherited_fds = 5;
  {
    int byte_size = _impl_._inherited_fds_cached_byte_size_.load(std::memory_order_relaxed);
    if (byte_size > 0) {
      target = stream->WriteUInt64Packed(
          5, _internal_inherited_fds(), byte_size, target);
    }
  }

  // map<uint64, bytes> read_data = 6;
  if (!this->_internal_read_data().empty()) {
    using MapType = ::_pb::Map<uint64_t, std::string>;
    using WireHelper = Parts_ReadDataEntry_DoNotUse::Funcs;
    const auto& map_field = this->_internal_read_data();

    if (stream->IsSerializationDeterministic() && map_field.size() > 1) {
      for (const auto& entry : ::_pbi::MapSorterFlat<MapType>(map_field)) {
        target = WireHelper::InternalSerialize(6, entry.first, entry.second, target, stream);
      }
    } else {
      for (const auto& entry : map_field) {
        target = WireHelper::InternalSerialize(6, entry.first, entry.second, target, stream);
      }
    }
  }

  // .generated.traces.Syscalls other_syscalls = 7;
  if (this->_internal_has_other_syscalls()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(7, _Internal::other_syscalls(this),
        _Internal::other_syscalls(this).GetCachedSize(), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:generated.traces.Parts)
  return target;
}

size_t Parts::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:generated.traces.Parts)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated bytes input_cells = 2;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(_impl_.input_cells_.size());
  for (int i = 0, n = _impl_.input_cells_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
      _impl_.input_cells_.Get(i));
  }

  // repeated bytes input_cell_data = 3;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(_impl_.input_cell_data_.size());
  for (int i = 0, n = _impl_.input_cell_data_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
      _impl_.input_cell_data_.Get(i));
  }

  // repeated bytes witnesses = 4;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(_impl_.witnesses_.size());
  for (int i = 0, n = _impl_.witnesses_.size(); i < n; i++) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
      _impl_.witnesses_.Get(i));
  }

  // repeated uint64 inherited_fds = 5;
  {
    size_t data_size = ::_pbi::WireFormatLite::
      UInt64Size(this->_impl_.inherited_fds_);
    if (data_size > 0) {
      total_size += 1 +
        ::_pbi::WireFormatLite::Int32Size(static_cast<int32_t>(data_size));
    }
    int cached_size = ::_pbi::ToCachedSize(data_size);
    _impl_._inherited_fds_cached_byte_size_.store(cached_size,
                                    std::memory_order_relaxed);
    total_size += data_size;
  }

  // map<uint64, bytes> read_data = 6;
  total_size += 1 *
      ::PROTOBUF_NAMESPACE_ID::internal::FromIntSize(this->_internal_read_data_size());
  for (::PROTOBUF_NAMESPACE_ID::Map< uint64_t, std::string >::const_iterator
      it = this->_internal_read_data().begin();
      it != this->_internal_read_data().end(); ++it) {
    total_size += Parts_ReadDataEntry_DoNotUse::Funcs::ByteSizeLong(it->first, it->second);
  }

  // bytes tx_hash = 1;
  if (!this->_internal_tx_hash().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_tx_hash());
  }

  // .generated.traces.Syscalls other_syscalls = 7;
  if (this->_internal_has_other_syscalls()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
        *_impl_.other_syscalls_);
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Parts::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    Parts::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Parts::GetClassData() const { return &_class_data_; }


void Parts::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<Parts*>(&to_msg);
  auto& from = static_cast<const Parts&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:generated.traces.Parts)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  _this->_impl_.input_cells_.MergeFrom(from._impl_.input_cells_);
  _this->_impl_.input_cell_data_.MergeFrom(from._impl_.input_cell_data_);
  _this->_impl_.witnesses_.MergeFrom(from._impl_.witnesses_);
  _this->_impl_.inherited_fds_.MergeFrom(from._impl_.inherited_fds_);
  _this->_impl_.read_data_.MergeFrom(from._impl_.read_data_);
  if (!from._internal_tx_hash().empty()) {
    _this->_internal_set_tx_hash(from._internal_tx_hash());
  }
  if (from._internal_has_other_syscalls()) {
    _this->_internal_mutable_other_syscalls()->::generated::traces::Syscalls::MergeFrom(
        from._internal_other_syscalls());
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Parts::CopyFrom(const Parts& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:generated.traces.Parts)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Parts::IsInitialized() const {
  return true;
}

void Parts::InternalSwap(Parts* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  _impl_.input_cells_.InternalSwap(&other->_impl_.input_cells_);
  _impl_.input_cell_data_.InternalSwap(&other->_impl_.input_cell_data_);
  _impl_.witnesses_.InternalSwap(&other->_impl_.witnesses_);
  _impl_.inherited_fds_.InternalSwap(&other->_impl_.inherited_fds_);
  _impl_.read_data_.InternalSwap(&other->_impl_.read_data_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &_impl_.tx_hash_, lhs_arena,
      &other->_impl_.tx_hash_, rhs_arena
  );
  swap(_impl_.other_syscalls_, other->_impl_.other_syscalls_);
}

::PROTOBUF_NAMESPACE_ID::Metadata Parts::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[6]);
}

// ===================================================================

class Root::_Internal {
 public:
  static const ::generated::traces::Parts& parts(const Root* msg);
  static const ::generated::traces::Syscalls& syscalls(const Root* msg);
};

const ::generated::traces::Parts&
Root::_Internal::parts(const Root* msg) {
  return *msg->_impl_.value_.parts_;
}
const ::generated::traces::Syscalls&
Root::_Internal::syscalls(const Root* msg) {
  return *msg->_impl_.value_.syscalls_;
}
void Root::set_allocated_parts(::generated::traces::Parts* parts) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  clear_value();
  if (parts) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      ::PROTOBUF_NAMESPACE_ID::Arena::InternalGetOwningArena(parts);
    if (message_arena != submessage_arena) {
      parts = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, parts, submessage_arena);
    }
    set_has_parts();
    _impl_.value_.parts_ = parts;
  }
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Root.parts)
}
void Root::set_allocated_syscalls(::generated::traces::Syscalls* syscalls) {
  ::PROTOBUF_NAMESPACE_ID::Arena* message_arena = GetArenaForAllocation();
  clear_value();
  if (syscalls) {
    ::PROTOBUF_NAMESPACE_ID::Arena* submessage_arena =
      ::PROTOBUF_NAMESPACE_ID::Arena::InternalGetOwningArena(syscalls);
    if (message_arena != submessage_arena) {
      syscalls = ::PROTOBUF_NAMESPACE_ID::internal::GetOwnedMessage(
          message_arena, syscalls, submessage_arena);
    }
    set_has_syscalls();
    _impl_.value_.syscalls_ = syscalls;
  }
  // @@protoc_insertion_point(field_set_allocated:generated.traces.Root.syscalls)
}
Root::Root(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor(arena, is_message_owned);
  // @@protoc_insertion_point(arena_constructor:generated.traces.Root)
}
Root::Root(const Root& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  Root* const _this = this; (void)_this;
  new (&_impl_) Impl_{
      decltype(_impl_.value_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , /*decltype(_impl_._oneof_case_)*/{}};

  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  clear_has_value();
  switch (from.value_case()) {
    case kParts: {
      _this->_internal_mutable_parts()->::generated::traces::Parts::MergeFrom(
          from._internal_parts());
      break;
    }
    case kSyscalls: {
      _this->_internal_mutable_syscalls()->::generated::traces::Syscalls::MergeFrom(
          from._internal_syscalls());
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  // @@protoc_insertion_point(copy_constructor:generated.traces.Root)
}

inline void Root::SharedCtor(
    ::_pb::Arena* arena, bool is_message_owned) {
  (void)arena;
  (void)is_message_owned;
  new (&_impl_) Impl_{
      decltype(_impl_.value_){}
    , /*decltype(_impl_._cached_size_)*/{}
    , /*decltype(_impl_._oneof_case_)*/{}
  };
  clear_has_value();
}

Root::~Root() {
  // @@protoc_insertion_point(destructor:generated.traces.Root)
  if (auto *arena = _internal_metadata_.DeleteReturnArena<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>()) {
  (void)arena;
    return;
  }
  SharedDtor();
}

inline void Root::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  if (has_value()) {
    clear_value();
  }
}

void Root::SetCachedSize(int size) const {
  _impl_._cached_size_.Set(size);
}

void Root::clear_value() {
// @@protoc_insertion_point(one_of_clear_start:generated.traces.Root)
  switch (value_case()) {
    case kParts: {
      if (GetArenaForAllocation() == nullptr) {
        delete _impl_.value_.parts_;
      }
      break;
    }
    case kSyscalls: {
      if (GetArenaForAllocation() == nullptr) {
        delete _impl_.value_.syscalls_;
      }
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  _impl_._oneof_case_[0] = VALUE_NOT_SET;
}


void Root::Clear() {
// @@protoc_insertion_point(message_clear_start:generated.traces.Root)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  clear_value();
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* Root::_InternalParse(const char* ptr, ::_pbi::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::_pbi::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // .generated.traces.Parts parts = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          ptr = ctx->ParseMessage(_internal_mutable_parts(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // .generated.traces.Syscalls syscalls = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 26)) {
          ptr = ctx->ParseMessage(_internal_mutable_syscalls(), ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* Root::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:generated.traces.Root)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // .generated.traces.Parts parts = 1;
  if (_internal_has_parts()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(1, _Internal::parts(this),
        _Internal::parts(this).GetCachedSize(), target, stream);
  }

  // .generated.traces.Syscalls syscalls = 3;
  if (_internal_has_syscalls()) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(3, _Internal::syscalls(this),
        _Internal::syscalls(this).GetCachedSize(), target, stream);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::_pbi::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:generated.traces.Root)
  return target;
}

size_t Root::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:generated.traces.Root)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  switch (value_case()) {
    // .generated.traces.Parts parts = 1;
    case kParts: {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
          *_impl_.value_.parts_);
      break;
    }
    // .generated.traces.Syscalls syscalls = 3;
    case kSyscalls: {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(
          *_impl_.value_.syscalls_);
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  return MaybeComputeUnknownFieldsSize(total_size, &_impl_._cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData Root::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSourceCheck,
    Root::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*Root::GetClassData() const { return &_class_data_; }


void Root::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message& to_msg, const ::PROTOBUF_NAMESPACE_ID::Message& from_msg) {
  auto* const _this = static_cast<Root*>(&to_msg);
  auto& from = static_cast<const Root&>(from_msg);
  // @@protoc_insertion_point(class_specific_merge_from_start:generated.traces.Root)
  GOOGLE_DCHECK_NE(&from, _this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  switch (from.value_case()) {
    case kParts: {
      _this->_internal_mutable_parts()->::generated::traces::Parts::MergeFrom(
          from._internal_parts());
      break;
    }
    case kSyscalls: {
      _this->_internal_mutable_syscalls()->::generated::traces::Syscalls::MergeFrom(
          from._internal_syscalls());
      break;
    }
    case VALUE_NOT_SET: {
      break;
    }
  }
  _this->_internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void Root::CopyFrom(const Root& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:generated.traces.Root)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Root::IsInitialized() const {
  return true;
}

void Root::InternalSwap(Root* other) {
  using std::swap;
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  swap(_impl_.value_, other->_impl_.value_);
  swap(_impl_._oneof_case_[0], other->_impl_._oneof_case_[0]);
}

::PROTOBUF_NAMESPACE_ID::Metadata Root::GetMetadata() const {
  return ::_pbi::AssignDescriptors(
      &descriptor_table_traces_2eproto_getter, &descriptor_table_traces_2eproto_once,
      file_level_metadata_traces_2eproto[7]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace traces
}  // namespace generated
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::generated::traces::Terminated*
Arena::CreateMaybeMessage< ::generated::traces::Terminated >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Terminated >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::IoData*
Arena::CreateMaybeMessage< ::generated::traces::IoData >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::IoData >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::Fds*
Arena::CreateMaybeMessage< ::generated::traces::Fds >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Fds >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::Syscall*
Arena::CreateMaybeMessage< ::generated::traces::Syscall >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Syscall >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::Syscalls*
Arena::CreateMaybeMessage< ::generated::traces::Syscalls >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Syscalls >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::Parts_ReadDataEntry_DoNotUse*
Arena::CreateMaybeMessage< ::generated::traces::Parts_ReadDataEntry_DoNotUse >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Parts_ReadDataEntry_DoNotUse >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::Parts*
Arena::CreateMaybeMessage< ::generated::traces::Parts >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Parts >(arena);
}
template<> PROTOBUF_NOINLINE ::generated::traces::Root*
Arena::CreateMaybeMessage< ::generated::traces::Root >(Arena* arena) {
  return Arena::CreateMessageInternal< ::generated::traces::Root >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
/* End of traces.pb.cc */
#endif /* CKB_FUZZING_INCLUDE_PROTOBUF_IMPL */

#ifdef CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL
/* Start of fuzzing_syscalls.cc */
/*
 * Mock syscall implementations in fuzzing
 */

/* fuzzing_syscalls_internal.h has already been included. */

#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
  _CKB_FUZZING_SYSCALL_FLAVOR = 1,
} _ckb_fuzzing_flavor_t;

typedef struct {
  _ckb_fuzzing_flavor_t flavor;
  const void* traces;
  int counter;

  jmp_buf buf;
  int exit_code;
} _ckb_fuzzing_context_t;

_ckb_fuzzing_context_t* _CKB_FUZZING_GCONTEXT = NULL;

void _ckb_fuzzing_cleanup() {
  if (_CKB_FUZZING_GCONTEXT != NULL) {
    if (_CKB_FUZZING_GCONTEXT->traces != NULL) {
      assert(_CKB_FUZZING_GCONTEXT->flavor == _CKB_FUZZING_SYSCALL_FLAVOR);

      // traces is passed as a parameter, it should be cleaned up outside
      _CKB_FUZZING_GCONTEXT->traces = NULL;
    }
    free(_CKB_FUZZING_GCONTEXT);
    _CKB_FUZZING_GCONTEXT = NULL;
  }
}

int _ckb_fuzzing_start(const generated::traces::Syscalls* syscalls) {
  // Flatten args in protobuf to plain array
  // At the start, each argv item requires a pointer, plus a NULL pointer
  size_t offset = (syscalls->args_size() + 1) * sizeof(size_t);
  size_t argv_len = offset;
  for (int i = 0; i < syscalls->args_size(); i++) {
    // Each argv is aligned by 8 bytes.
    size_t current_len = syscalls->args(i).length() + 1;
    size_t rounded_len = ((current_len + 7) / 8) * 8;
    argv_len += rounded_len;
  }
  char* flattened_argv = (char*)malloc(argv_len);
  ((size_t*)flattened_argv)[syscalls->args_size()] = 0;
  for (int i = 0; i < syscalls->args_size(); i++) {
    ((size_t*)flattened_argv)[i] = (size_t)(&flattened_argv[offset]);
    strcpy(&flattened_argv[offset], syscalls->args(i).c_str());

    size_t current_len = syscalls->args(i).length() + 1;
    size_t rounded_len = ((current_len + 7) / 8) * 8;
    offset += rounded_len;
  }

  if (!setjmp(_CKB_FUZZING_GCONTEXT->buf)) {
    _CKB_FUZZING_GCONTEXT->exit_code =
        CKB_FUZZING_ENTRYPOINT(syscalls->args_size(), (char**)flattened_argv);
  } else {
    // No action is needed in this branch.
  }
  free(flattened_argv);
  return _CKB_FUZZING_GCONTEXT->exit_code;
}

int ckb_fuzzing_start_syscall_flavor(
    const generated::traces::Syscalls* syscalls) {
  _ckb_fuzzing_cleanup();

  _CKB_FUZZING_GCONTEXT =
      (_ckb_fuzzing_context_t*)malloc(sizeof(_ckb_fuzzing_context_t));
  _CKB_FUZZING_GCONTEXT->flavor = _CKB_FUZZING_SYSCALL_FLAVOR;
  _CKB_FUZZING_GCONTEXT->traces = syscalls;
  _CKB_FUZZING_GCONTEXT->counter = 0;

  return _ckb_fuzzing_start(syscalls);
}

#define FETCH_SYSCALL(syscalls, counter)          \
  if ((counter) >= (syscalls)->syscalls_size()) { \
    return CKB_FUZZING_UNEXPECTED;                \
  }                                               \
  const generated::traces::Syscall& syscall = (syscalls)->syscalls((counter))

int _ckb_fuzzing_io_data(void* addr, uint64_t* len,
                         const generated::traces::Syscalls* syscalls,
                         int* counter) {
  FETCH_SYSCALL(syscalls, *counter);
  if (syscall.has_return_with_code()) {
    *counter += 1;
    return (int)syscall.return_with_code();
  }

  if (!syscall.has_io_data()) {
    return CKB_FUZZING_UNEXPECTED;
  }
  const generated::traces::IoData io_data = syscall.io_data();

  size_t read = *len;
  if (read > io_data.available_data().length()) {
    if (io_data.additional_length() > 0) {
      // There is more data, but the syscall just chooses to hide it.
      return CKB_FUZZING_UNEXPECTED;
    }
    read = io_data.available_data().length();
  }
  if (read > 0) {
    memcpy(addr, io_data.available_data().data(), read);
  }
  *len = io_data.available_data().length() + io_data.additional_length();

  *counter += 1;
  return CKB_SUCCESS;
}

int64_t _ckb_fuzzing_return_code(const generated::traces::Syscalls* syscalls,
                                 int* counter) {
  FETCH_SYSCALL(syscalls, *counter);
  if (!syscall.has_return_with_code()) {
    return CKB_FUZZING_UNEXPECTED;
  }
  *counter += 1;
  return syscall.return_with_code();
}

#define ASSERT_SYSCALL_FLAVOR                                            \
  if (_CKB_FUZZING_GCONTEXT->flavor != _CKB_FUZZING_SYSCALL_FLAVOR) {    \
    return CKB_FUZZING_UNEXPECTED;                                       \
  }                                                                      \
  const generated::traces::Syscalls* syscalls =                          \
      (const generated::traces::Syscalls*)_CKB_FUZZING_GCONTEXT->traces; \
  FETCH_SYSCALL(syscalls, _CKB_FUZZING_GCONTEXT->counter);               \
  if (syscall.has_return_with_code()) {                                  \
    _CKB_FUZZING_GCONTEXT->counter += 1;                                 \
    return (int)syscall.return_with_code();                              \
  }

#define WHEN_SYSCALL_FLAVOR(value)                                           \
  do {                                                                       \
    if (_CKB_FUZZING_GCONTEXT->flavor == _CKB_FUZZING_SYSCALL_FLAVOR) {      \
      const generated::traces::Syscalls* syscalls =                          \
          (const generated::traces::Syscalls*)_CKB_FUZZING_GCONTEXT->traces; \
      int* counter = &_CKB_FUZZING_GCONTEXT->counter;                        \
      return (value);                                                        \
    }                                                                        \
  } while (0)

int ckb_exit(int8_t code) {
  _CKB_FUZZING_GCONTEXT->exit_code = (int)code;
  longjmp(_CKB_FUZZING_GCONTEXT->buf, 1);
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source) {
  (void)offset;
  (void)index;
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source) {
  (void)offset;
  (void)index;
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source) {
  (void)offset;
  (void)index;
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  (void)offset;
  (void)index;
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_transaction(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)field;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)field;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)field;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  (void)offset;
  (void)index;
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_cell_data_as_code(void* addr, size_t memory_size,
                               size_t content_offset, size_t content_size,
                               size_t index, size_t source) {
  fprintf(stderr, "Load cell data as code is not supported!\n");
  abort();
}

int ckb_debug(const char* s) {
  fprintf(stderr, "Script debug message: %s\n", s);
  return CKB_SUCCESS;
}

int ckb_vm_version() {
  WHEN_SYSCALL_FLAVOR((int)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

uint64_t ckb_current_cycles() {
  WHEN_SYSCALL_FLAVOR((uint64_t)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_exec(size_t index, size_t source, size_t place, size_t bounds, int argc,
             const char* argv[]) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_terminated()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    return ckb_exit(0);
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_spawn(size_t index, size_t source, size_t place, size_t bounds,
              spawn_args_t* spawn_args) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    *spawn_args->process_id = syscall.success_output_data();
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_wait(uint64_t pid, int8_t* exit_code) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    *exit_code = (int8_t)syscall.success_output_data();
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

uint64_t ckb_process_id() {
  WHEN_SYSCALL_FLAVOR((uint64_t)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_pipe(uint64_t out_fds[2]) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_fds()) {
    const generated::traces::Fds& fds = syscall.fds();
    if (fds.fds_size() != 2) {
      return CKB_FUZZING_UNEXPECTED;
    }
    _CKB_FUZZING_GCONTEXT->counter += 1;
    out_fds[0] = fds.fds(0);
    out_fds[1] = fds.fds(1);
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_read(uint64_t fd, void* buffer, size_t* length) {
  (void)fd;

  assert(sizeof(size_t) == sizeof(uint64_t));
  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(buffer, (uint64_t*)length, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_write(uint64_t fd, const void* buffer, size_t* length) {
  (void)fd;
  (void)buffer;

  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    *length = (int8_t)syscall.success_output_data();
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_inherited_fds(uint64_t* out_fds, size_t* length) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_fds()) {
    const generated::traces::Fds& fds = syscall.fds();
    if (fds.fds_size() < *length) {
      return CKB_FUZZING_UNEXPECTED;
    }
    size_t count = fds.fds_size();
    if (count > *length) {
      count = *length;
    }
    for (size_t i = 0; i < count; i++) {
      out_fds[i] = fds.fds(i);
    }
    *length = count;
    _CKB_FUZZING_GCONTEXT->counter += 1;
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_close(uint64_t fd) {
  (void)fd;

  WHEN_SYSCALL_FLAVOR((int)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_load_block_extension(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  (void)offset;
  (void)index;
  (void)offset;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

#undef WHEN_SYSCALL_FLAVOR
#undef ASSERT_SYSCALL_FLAVOR
#undef FETCH_SYSCALL
/* End of fuzzing_syscalls.cc */
#endif /* CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL */

/* Fuzzer interfaces */
#ifdef CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE
/* Start of libfuzzer_interface.cc */
/*
 * Entrypoint for LLVM libfuzzer, it requires libprotobuf-mutator:
 *
 * https://github.com/google/libprotobuf-mutator
 */

/* fuzzing_syscalls_internal.h has already been included. */

#include <src/libfuzzer/libfuzzer_macro.h>

#ifdef CKB_FUZZING_USE_TEXT_PROTO
DEFINE_TEXT_PROTO_FUZZER(const generated::traces::Syscalls& syscalls) {
#else
DEFINE_BINARY_PROTO_FUZZER(const generated::traces::Syscalls& syscalls) {
#endif
  ckb_fuzzing_start_syscall_flavor(&syscalls);
}
/* End of libfuzzer_interface.cc */
#endif /* CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_FILENAME_INTERFACE
/* Start of file_interface.cc */
/*
 * A standard entrypoint interface that builds the code into a binary,
 * which then reads from a file for fuzzing input data.
 *
 * This interface should fit honggfuzz, and possibly other fuzzers that
 * only require external tweaking.
 */

/* fuzzing_syscalls_internal.h has already been included. */

#include <google/protobuf/text_format.h>
#include <fstream>
#include <iostream>
using namespace std;

#undef main
int main(int argc, char* argv[]) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if (argc != 2) {
    printf("Usage: %s <INPUT FILE>\n", argv[0]);
    return 1;
  }

  generated::traces::Syscalls syscalls;
  {
    fstream input(argv[1], ios::in | ios::binary);
    google::protobuf::io::IstreamInputStream zinput(&input);
#ifdef CKB_FUZZING_USE_TEXT_PROTO
    if (!google::protobuf::TextFormat::Parse(&zinput, &syscalls)) {
#else
    if (!syscalls.ParseFromZeroCopyStream(&zinput)) {
#endif
      return -1;
    }
  }

  return ckb_fuzzing_start_syscall_flavor(&syscalls);
}
#define main CKB_FUZZING_ENTRYPOINT
/* End of file_interface.cc */
#endif /* CKB_FUZZING_DEFINE_FILENAME_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_AFLXX_INTERFACE
/* Start of aflxx_interface.cc */
/*
 * Entrypoint for AFLplusplus fuzzer
 */

/* fuzzing_syscalls_internal.h has already been included. */

#include <google/protobuf/text_format.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

#undef main
int main() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;

    {
      generated::traces::Syscalls syscalls;
      google::protobuf::io::ArrayInputStream zinput(buf, len);

#ifdef CKB_FUZZING_USE_TEXT_PROTO
      if (!google::protobuf::TextFormat::Parse(&zinput, &syscalls)) {
#else
      if (syscalls.ParseFromZeroCopyStream(&zinput)) {
#endif
        ckb_fuzzing_start_syscall_flavor(&syscalls);
      }
    }
  }

  return 0;
}
#define main CKB_FUZZING_ENTRYPOINT
/* End of aflxx_interface.cc */
#endif /* CKB_FUZZING_DEFINE_AFLXX_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_BINARY_TO_TEXT_CONVERTER
/* Start of binary_to_text_converter.cc */
/*
 * A utility converting protobuf's binary format to text format.
 * Since prost does not support text format, we provide the utility
 * as a component of the toolkit.
 */
/* fuzzing_syscalls_internal.h has already been included. */

#include <google/protobuf/text_format.h>
#include <assert.h>
#include <fstream>
#include <iostream>
using namespace std;

/*
 * Converter is a standalone utility, meaning this shall be a dummy
 * function
 */
int CKB_FUZZING_ENTRYPOINT(int argc, char* argv[]) {
  (void)argc;
  (void)argv;

  assert(false);
  return -1;
}

#undef main
int main(int argc, char* argv[]) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if (argc != 2) {
    printf("Usage: %s <INPUT FILE>\n", argv[0]);
    return 1;
  }

  generated::traces::Syscalls syscalls;
  {
    fstream input(argv[1], ios::in | ios::binary);
    if (!syscalls.ParseFromIstream(&input)) {
      return -1;
    }
  }

  string output;
  google::protobuf::io::OstreamOutputStream out(&cout);
  assert(google::protobuf::TextFormat::Print(syscalls, &out));
  return 0;
}
#define main CKB_FUZZING_ENTRYPOINT
/* End of binary_to_text_converter.cc */
#endif /* CKB_FUZZING_DEFINE_BINARY_TO_TEXT_CONVERTER */

#endif /* CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_ */
