/*
 * Mock syscall implementations in fuzzing
 */

#include "syscalls/protobuf.h"
#include "syscalls/utils.h"

#include <assert.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <google/protobuf/text_format.h>

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

int ckb_fuzzing_start_with_protobuf(
    const generated::traces::Syscalls* syscalls) {
  _ckb_fuzzing_context_t context = {
      .flavor = _CKB_FUZZING_SYSCALL_FLAVOR,
      .traces = syscalls,
      .counter = 0,
  };
  _CKB_FUZZING_GCONTEXT = &context;

  // Flatten args in protobuf to plain array
  ArgvBuilder argv_builder;
  for (int i = 0; i < syscalls->args_size(); i++) {
    argv_builder.push(syscalls->args(i).c_str());
  }
  int argc = argv_builder.argc();
  char** argv = argv_builder.argv();

  if (!setjmp(_CKB_FUZZING_GCONTEXT->buf)) {
    _CKB_FUZZING_GCONTEXT->exit_code = CKB_FUZZING_ENTRYPOINT(argc, argv);
  } else {
    // No action is needed in this branch.
  }
  free(argv);
  _CKB_FUZZING_GCONTEXT = NULL;
  return context.exit_code;
}

int ckb_fuzzing_start(const uint8_t* data, size_t length) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  generated::traces::Syscalls syscalls;
  google::protobuf::io::ArrayInputStream zinput(data, length);
  bool parsed = false;
#ifdef CKB_FUZZING_USE_TEXT_PROTO
  parsed = google::protobuf::TextFormat::Parse(&zinput, &syscalls);
#else
  parsed = syscalls.ParseFromZeroCopyStream(&zinput);
#endif
  if (parsed) {
    return ckb_fuzzing_start_with_protobuf(&syscalls);
  } else {
    return CKB_FUZZING_UNEXPECTED;
  }
}

#define FETCH_SYSCALL(syscalls, counter)          \
  if ((counter) >= (syscalls)->syscalls_size()) { \
    return CKB_FUZZING_UNEXPECTED;                \
  }                                               \
  const generated::traces::Syscall& syscall = (syscalls)->syscalls((counter))

int _ckb_fuzzing_io_data(void* addr, uint64_t* len,
                         const generated::traces::Syscalls* syscalls,
                         int* counter, size_t offset, size_t expected_length) {
  FETCH_SYSCALL(syscalls, *counter);
  if (syscall.has_return_with_code()) {
    *counter += 1;
    return (int)syscall.return_with_code();
  }

  if (!syscall.has_io_data()) {
    return CKB_FUZZING_UNEXPECTED;
  }
  const generated::traces::IoData io_data = syscall.io_data();
  if (expected_length > 0) {
    if (offset > expected_length) {
      return CKB_FUZZING_UNEXPECTED;
    }
    if (io_data.available_data().length() != expected_length - offset) {
      return CKB_FUZZING_UNEXPECTED;
    }
  }

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

int _CKB_FUZZING_SYSCALL_FUNC_NAME(exit)(int8_t code) {
  _CKB_FUZZING_GCONTEXT->exit_code = (int)code;
  longjmp(_CKB_FUZZING_GCONTEXT->buf, 1);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_tx_hash)(void* addr, uint64_t* len,
                                                 size_t offset) {
  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 32));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script_hash)(void* addr, uint64_t* len,
                                                     size_t offset) {
  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 32));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell)(void* addr, uint64_t* len,
                                              size_t offset, size_t index,
                                              size_t source) {
  (void)index;
  (void)source;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input)(void* addr, uint64_t* len,
                                               size_t offset, size_t index,
                                               size_t source) {
  (void)index;
  (void)source;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header)(void* addr, uint64_t* len,
                                                size_t offset, size_t index,
                                                size_t source) {
  (void)index;
  (void)source;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_witness)(void* addr, uint64_t* len,
                                                 size_t offset, size_t index,
                                                 size_t source) {
  (void)index;
  (void)source;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script)(void* addr, uint64_t* len,
                                                size_t offset) {
  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_transaction)(void* addr, uint64_t* len,
                                                     size_t offset) {
  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field) {
  (void)index;
  (void)source;

  size_t expected_length = 0;
  switch (field) {
    case CKB_CELL_FIELD_CAPACITY: {
      expected_length = 8;
    } break;
    case CKB_CELL_FIELD_DATA_HASH: {
      expected_length = 32;
    } break;
    case CKB_CELL_FIELD_LOCK_HASH: {
      expected_length = 32;
    } break;
    case CKB_CELL_FIELD_TYPE_HASH: {
      expected_length = 32;
    } break;
    case CKB_CELL_FIELD_OCCUPIED_CAPACITY: {
      expected_length = 8;
    } break;
  }

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter, offset,
                                           expected_length));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field) {
  (void)index;
  (void)source;
  (void)field;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 8));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field) {
  (void)index;
  (void)source;

  size_t expected_length = 0;
  switch (field) {
    case CKB_INPUT_FIELD_SINCE: {
      expected_length = 8;
    } break;
  }

  WHEN_SYSCALL_FLAVOR(_ckb_fuzzing_io_data(addr, len, syscalls, counter, offset,
                                           expected_length));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data)(void* addr, uint64_t* len,
                                                   size_t offset, size_t index,
                                                   size_t source) {
  (void)index;
  (void)source;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data_as_code)(
    void* addr, size_t memory_size, size_t content_offset, size_t content_size,
    size_t index, size_t source) {
  fprintf(stderr, "Load cell data as code is not supported!\n");
  abort();
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(debug)(const char* s) {
  (void)s;
#ifdef CKB_FUZZING_PRINT_DEBUG_MESSAGE
  fprintf(stderr, "Script debug message: %s\n", s);
#endif
  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(vm_version)() {
  WHEN_SYSCALL_FLAVOR((int)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

uint64_t _CKB_FUZZING_SYSCALL_FUNC_NAME(current_cycles)() {
  WHEN_SYSCALL_FLAVOR((uint64_t)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(exec)(size_t index, size_t source,
                                         size_t place, size_t bounds, int argc,
                                         const char* argv[]) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_terminated()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    return ckb_exit(0);
  }

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(spawn)(size_t index, size_t source,
                                          size_t place, size_t bounds,
                                          spawn_args_t* spawn_args) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    *spawn_args->process_id = syscall.success_output_data();
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(wait)(uint64_t pid, int8_t* exit_code) {
  ASSERT_SYSCALL_FLAVOR;

  if (syscall.has_success_output_data()) {
    _CKB_FUZZING_GCONTEXT->counter += 1;
    *exit_code = (int8_t)syscall.success_output_data();
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

uint64_t _CKB_FUZZING_SYSCALL_FUNC_NAME(process_id)() {
  WHEN_SYSCALL_FLAVOR((uint64_t)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(pipe)(uint64_t out_fds[2]) {
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

int _CKB_FUZZING_SYSCALL_FUNC_NAME(read)(uint64_t fd, void* buffer,
                                         size_t* length) {
  (void)fd;

  ASSERT_SYSCALL_FLAVOR;
  if (!syscall.has_io_data()) {
    return CKB_FUZZING_UNEXPECTED;
  }

  const generated::traces::IoData io_data = syscall.io_data();
  size_t read = *length;
  if (read > io_data.available_data().length()) {
    read = io_data.available_data().length();
  }
  if (read > 0) {
    memcpy(buffer, io_data.available_data().data(), read);
  }
  *length = read;
  _CKB_FUZZING_GCONTEXT->counter += 1;
  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(write)(uint64_t fd, const void* buffer,
                                          size_t* length) {
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

int _CKB_FUZZING_SYSCALL_FUNC_NAME(inherited_fds)(uint64_t* out_fds,
                                                  size_t* length) {
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
    *length = fds.fds_size();
    _CKB_FUZZING_GCONTEXT->counter += 1;
    return CKB_SUCCESS;
  }

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(close)(uint64_t fd) {
  (void)fd;

  WHEN_SYSCALL_FLAVOR((int)_ckb_fuzzing_return_code(syscalls, counter));

  return CKB_FUZZING_UNEXPECTED;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_block_extension)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  (void)index;
  (void)source;

  WHEN_SYSCALL_FLAVOR(
      _ckb_fuzzing_io_data(addr, len, syscalls, counter, offset, 0));

  return CKB_FUZZING_UNEXPECTED;
}

#undef WHEN_SYSCALL_FLAVOR
#undef ASSERT_SYSCALL_FLAVOR
#undef FETCH_SYSCALL
