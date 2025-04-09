/*
 * A utility converting protobuf's binary format to text format.
 * Since prost does not support text format, we provide the utility
 * as a component of the toolkit.
 */
#include "fuzzing_syscalls_internal.h"

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
