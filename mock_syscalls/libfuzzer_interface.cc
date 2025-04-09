/*
 * Entrypoint for LLVM libfuzzer, it requires libprotobuf-mutator:
 *
 * https://github.com/google/libprotobuf-mutator
 */

#include "fuzzing_syscalls_internal.h"

#include <src/libfuzzer/libfuzzer_macro.h>

#ifdef CKB_FUZZING_USE_TEXT_PROTO
DEFINE_TEXT_PROTO_FUZZER(const generated::traces::Syscalls& syscalls) {
#else
DEFINE_BINARY_PROTO_FUZZER(const generated::traces::Syscalls& syscalls) {
#endif
  ckb_fuzzing_start_syscall_flavor(&syscalls);
}
