/*
 * Mock syscall implementations in fuzzing
 */

#include "fuzzing_syscalls.h"

#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ckb_consts.h"
#include "ckb_syscall_apis.h"

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

      const generated::traces::Syscalls* syscalls =
          (const generated::traces::Syscalls*)_CKB_FUZZING_GCONTEXT->traces;
      delete syscalls;
      _CKB_FUZZING_GCONTEXT->traces = NULL;
    }
    free(_CKB_FUZZING_GCONTEXT);
    _CKB_FUZZING_GCONTEXT = NULL;
  }
}

int _ckb_fuzzing_start(const generated::traces::Syscalls* syscalls) {
  _ckb_fuzzing_cleanup();

  // Flatten args in protobuf to plain array
  // At the start, each argv item requires a pointer, plus a NULL pointer
  size_t offset = syscalls->args_size() * sizeof(size_t) + 1;
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
  memcpy(addr, io_data.available_data().data(), read);
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
    *spawn_args->process_id = syscall.success_output_data();
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_wait(uint64_t pid, int8_t* exit_code) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
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
    out_fds[0] = fds.fds(0);
    out_fds[1] = fds.fds(1);
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_read(uint64_t fd, void* buffer, size_t* length) {
  (void)fd;

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(buffer, length, syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int ckb_write(uint64_t fd, const void* buffer, size_t* length) {
  (void)fd;
  (void)buffer;

  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
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
