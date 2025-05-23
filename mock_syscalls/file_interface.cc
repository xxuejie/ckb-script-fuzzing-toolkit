/*
 * A standard entrypoint interface that builds the code into a binary,
 * which then reads from a file for fuzzing input data.
 *
 * This interface should fit honggfuzz, and possibly other fuzzers that
 * only require external tweaking.
 */

#include "fuzzing_syscalls_internal.h"

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
