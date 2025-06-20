/*
 * Mock syscall implementations using FuzzedDataProvider.h from LLVM
 */

#include "fuzzing_syscalls.h"
#include "syscalls/FuzzedDataProvider.h"
#include "syscalls/utils.h"

#include <setjmp.h>

typedef struct {
  FuzzedDataProvider* provider;
  int argc;
  char** argv;
} _ckb_fuzzing_fdp_data_t;

typedef struct {
  _ckb_fuzzing_fdp_data_t d;

  jmp_buf buf;
  int exit_code;
} _ckb_fuzzing_context_t;

_ckb_fuzzing_context_t _CKB_FUZZING_GCONTEXT;

extern "C" const _ckb_fuzzing_fdp_data_t* ckb_fuzzing_fdp_init(
    const uint8_t* data, size_t length) {
  FuzzedDataProvider* provider = new FuzzedDataProvider(data, length);

  ArgvBuilder argv_builder;
  int argc = provider->ConsumeIntegralInRange(0, 20);
  for (int i = 0; i < argc; i++) {
    std::string arg = provider->ConsumeRandomLengthString(50);
    argv_builder.push(arg.c_str());
  }
  char** argv = argv_builder.argv();

  _CKB_FUZZING_GCONTEXT.d.provider = provider;
  _CKB_FUZZING_GCONTEXT.d.argc = argc;
  _CKB_FUZZING_GCONTEXT.d.argv = argv;

  return &(_CKB_FUZZING_GCONTEXT.d);
}

extern "C" void ckb_fuzzing_fdp_cleanup() {
  if (_CKB_FUZZING_GCONTEXT.d.provider != NULL) {
    delete _CKB_FUZZING_GCONTEXT.d.provider;
    _CKB_FUZZING_GCONTEXT.d.provider = NULL;
  }
  _CKB_FUZZING_GCONTEXT.d.argc = 0;
  if (_CKB_FUZZING_GCONTEXT.d.argv != NULL) {
    free(_CKB_FUZZING_GCONTEXT.d.argv);
    _CKB_FUZZING_GCONTEXT.d.argv = NULL;
  }
}

int ckb_fuzzing_start(const uint8_t* data, size_t length) {
  ckb_fuzzing_fdp_init(data, length);

  if (!setjmp(_CKB_FUZZING_GCONTEXT.buf)) {
    _CKB_FUZZING_GCONTEXT.exit_code = CKB_FUZZING_ENTRYPOINT(
        _CKB_FUZZING_GCONTEXT.d.argc, _CKB_FUZZING_GCONTEXT.d.argv);
  } else {
    // No action is needed in this branch.
  }
  ckb_fuzzing_fdp_cleanup();
  return _CKB_FUZZING_GCONTEXT.exit_code;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(exit)(int8_t code) {
  _CKB_FUZZING_GCONTEXT.exit_code = (int)code;
  longjmp(_CKB_FUZZING_GCONTEXT.buf, 1);
}

int _ckb_fuzzing_io_data(void* addr, uint64_t* len,
                         FuzzedDataProvider* provider, size_t offset,
                         size_t expected_length) {
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  uint64_t available_length = provider->ConsumeIntegral<uint64_t>();
  if (expected_length > 0) {
    if (offset > expected_length) {
      return CKB_FUZZING_UNEXPECTED;
    }
    if (available_length != expected_length - offset) {
      return CKB_FUZZING_UNEXPECTED;
    }
  }

  std::vector<uint8_t> available_data =
      provider->ConsumeBytes<uint8_t>(available_length);
  uint64_t remaining_length = provider->ConsumeIntegral<uint64_t>();

  uint64_t read = *len;
  if (read > available_length) {
    if (remaining_length > 0) {
      return CKB_FUZZING_UNEXPECTED;
    }
    read = available_length;
  }
  if (read > 0) {
    memcpy(addr, available_data.data(), read);
  }
  *len = read + remaining_length;
  if (*len < read) {
    // Overflow checking
    return CKB_FUZZING_UNEXPECTED;
  }

  return CKB_SUCCESS;
}

int64_t _ckb_fuzzing_return_code(FuzzedDataProvider* provider) {
  return provider->ConsumeIntegral<int64_t>();
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_tx_hash)(void* addr, uint64_t* len,
                                                 size_t offset) {
  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 32);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script_hash)(void* addr, uint64_t* len,
                                                     size_t offset) {
  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 32);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell)(void* addr, uint64_t* len,
                                              size_t offset, size_t index,
                                              size_t source) {
  (void)index;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input)(void* addr, uint64_t* len,
                                               size_t offset, size_t index,
                                               size_t source) {
  (void)index;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header)(void* addr, uint64_t* len,
                                                size_t offset, size_t index,
                                                size_t source) {
  (void)index;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_witness)(void* addr, uint64_t* len,
                                                 size_t offset, size_t index,
                                                 size_t source) {
  (void)index;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script)(void* addr, uint64_t* len,
                                                size_t offset) {
  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_transaction)(void* addr, uint64_t* len,
                                                     size_t offset) {
  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
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

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, expected_length);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field) {
  (void)index;
  (void)source;
  (void)field;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 8);
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

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, expected_length);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data)(void* addr, uint64_t* len,
                                                   size_t offset, size_t index,
                                                   size_t source) {
  (void)index;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data_as_code)(
    void* addr, size_t memory_size, size_t content_offset, size_t content_size,
    size_t index, size_t source) {
  (void)addr;
  (void)memory_size;
  (void)content_offset;
  (void)content_size;
  (void)index;
  (void)source;

  fprintf(stderr, "Load cell data as code is not supported!\n");
  abort();
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(debug)(const char* s) {
  (void) s;
#ifdef CKB_FUZZING_PRINT_DEBUG_MESSAGE
  fprintf(stderr, "Script debug message: %s\n", s);
#endif
  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(vm_version)() {
  return (int)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT.d.provider);
}

uint64_t _CKB_FUZZING_SYSCALL_FUNC_NAME(current_cycles)() {
  return (uint64_t)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT.d.provider);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(exec)(size_t index, size_t source,
                                         size_t place, size_t bounds, int argc,
                                         const char* argv[]) {
  (void)index;
  (void)source;
  (void)place;
  (void)bounds;
  (void)argc;
  (void)argv;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  return ckb_exit(0);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(spawn)(size_t index, size_t source,
                                          size_t place, size_t bounds,
                                          spawn_args_t* spawn_args) {
  (void)index;
  (void)source;
  (void)place;
  (void)bounds;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  *spawn_args->process_id = provider->ConsumeIntegral<uint64_t>();
  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(wait)(uint64_t pid, int8_t* exit_code) {
  (void)pid;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  *exit_code = provider->ConsumeIntegral<int8_t>();
  return CKB_SUCCESS;
}

uint64_t _CKB_FUZZING_SYSCALL_FUNC_NAME(process_id)() {
  return (uint64_t)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT.d.provider);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(pipe)(uint64_t out_fds[2]) {
  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  out_fds[0] = provider->ConsumeIntegral<uint64_t>();
  out_fds[1] = provider->ConsumeIntegral<uint64_t>();
  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(read)(uint64_t fd, void* buffer,
                                         size_t* length) {
  (void)fd;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }
  uint64_t read = provider->ConsumeIntegralInRange<uint64_t>(0, *length);
  std::vector<uint8_t> data = provider->ConsumeBytes<uint8_t>(read);

  memcpy(buffer, data.data(), read);
  *length = read;

  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(write)(uint64_t fd, const void* buffer,
                                          size_t* length) {
  (void)fd;
  (void)buffer;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  *length = provider->ConsumeIntegral<uint64_t>();
  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(inherited_fds)(uint64_t* out_fds,
                                                  size_t* length) {
  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT.d.provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  size_t available = provider->ConsumeIntegral<size_t>();
  if (available < *length) {
    return CKB_FUZZING_UNEXPECTED;
  }
  size_t count = available;
  if (count > *length) {
    count = *length;
  }
  for (size_t i = 0; i < count; i++) {
    out_fds[i] = provider->ConsumeIntegral<uint64_t>();
  }
  *length = available;

  return CKB_SUCCESS;
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(close)(uint64_t fd) {
  (void)fd;

  return (int)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT.d.provider);
}

int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_block_extension)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  (void)index;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT.d.provider,
                              offset, 0);
}
