#ifndef CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_
#define CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_

/* CKB script visible fuzzing APIs */
#include "fuzzing_syscalls.h"

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
#include "syscalls/protobuf.h"
#endif /* CKB_FUZZING_INCLUDE_INTERNAL_DEFS */

/* Extra syscall utilities that can be handy */
#ifdef CKB_FUZZING_INCLUDE_SYSCALL_UTILS
#include "ckb_syscall_utils.h"
#endif /* CKB_FUZZING_INCLUDE_SYSCALL_UTILS */

#ifdef CKB_FUZZING_INCLUDE_PROTOBUF_IMPL
#include "traces.pb.cc"
#endif /* CKB_FUZZING_INCLUDE_PROTOBUF_IMPL */

#if defined(CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL) || \
  defined(CKB_FUZZING_INCLUDE_FDP_SYSCALL_IMPL)
#include "syscalls/utils.h"
#endif

#ifdef CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL
#include "syscalls/protobuf.cc"
#endif /* CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL */

#ifdef CKB_FUZZING_INCLUDE_FDP_SYSCALL_IMPL
#include "syscalls/fuzzed_data_provider.cc"
#endif /* CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL */

/* Fuzzer interfaces */
#ifdef CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE
#include "interfaces/libfuzzer.cc"
#endif /* CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_FILENAME_INTERFACE
#include "interfaces/file.cc"
#endif /* CKB_FUZZING_DEFINE_FILENAME_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_AFLXX_INTERFACE
#include "interfaces/aflxx.cc"
#endif /* CKB_FUZZING_DEFINE_AFLXX_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_BINARY_TO_TEXT_CONVERTER
#include "tools/binary_to_text_converter.cc"
#endif /* CKB_FUZZING_DEFINE_BINARY_TO_TEXT_CONVERTER */

#endif /* CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_ */
