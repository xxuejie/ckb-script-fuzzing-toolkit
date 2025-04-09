/*
 * Entrypoint for AFLplusplus fuzzer
 */

#include "fuzzing_syscalls_internal.h"

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
      if (syscalls.ParseFromArray(buf, len)) {
        ckb_fuzzing_start_syscall_flavor(&syscalls);
      }
    }
  }

  return 0;
}
#define main CKB_FUZZING_ENTRYPOINT
