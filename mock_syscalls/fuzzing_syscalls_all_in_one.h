#ifndef CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_
#define CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_

#include "fuzzing_syscalls.h"

/* Fuzzer interfaces */

#ifdef CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE
#include "libfuzzer_interface.cc"
#endif /* CKB_FUZZING_DEFINE_LLVM_FUZZER_INTERFACE */

#ifdef CKB_FUZZING_DEFINE_FILENAME_INTERFACE
#include "file_interface.cc"
#endif /* CKB_FUZZING_DEFINE_FILENAME_INTERFACE */

/* Extra syscall utilities that can be handy */
#include "ckb_syscall_utils.h"

/*
 * Actual implementations, macros are provided to tweak single header
 * behaviors. Some like it, but some do not.
 */

#ifdef CKB_FUZZING_SINGLE_HEADER_MODE
#define CKB_FUZZING_INCLUDE_PROTOBUF_IMPL
#define CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL
#endif

#ifdef CKB_FUZZING_INCLUDE_PROTOBUF_IMPL
#include "traces.pb.cc"
#endif /* CKB_FUZZING_INCLUDE_PROTOBUF_IMPL */

#ifdef CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL
#include "fuzzing_syscalls.cc"
#endif /* CKB_FUZZING_INCLUDE_MOCK_SYSCALL_IMPL */

#endif /* CKB_FUZZING_MOCK_SYSCALLS_ALL_IN_ONE_H_ */
