/*
 * Entrypoint for LLVM libfuzzer, it requires libprotobuf-mutator:
 *
 * https://github.com/google/libprotobuf-mutator
 */

#include "fuzzing_syscalls.h"

#include <src/libfuzzer/libfuzzer_macro.h>

DEFINE_PROTO_FUZZER(const generated::traces::Syscalls& syscalls) {
  ckb_fuzzing_start_syscall_flavor(&syscalls);
}
