/*
 * A standard entrypoint interface that builds the code into a binary,
 * which then reads from a file for fuzzing input data.
 *
 * This interface should fit honggfuzz, and possibly other fuzzers that
 * only require external tweaking.
 */

#include "fuzzing_syscalls.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#undef main
int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <INPUT FILE>\n", argv[0]);
    return 1;
  }

  FILE *fp = fopen(argv[1], "rb");
  if (fp == NULL) {
    return 1;
  }
  fseek(fp, 0, SEEK_END);
  size_t length = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  uint8_t *buffer = (uint8_t *)malloc(length);
  assert(buffer != NULL);

  fread(buffer, 1, length, fp);
  fclose(fp);

  int ret = ckb_fuzzing_start(buffer, length);
  free(buffer);

  return ret;
}
#define main CKB_FUZZING_ENTRYPOINT
