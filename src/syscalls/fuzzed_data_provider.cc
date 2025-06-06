/*
 * Mock syscall implementations using FuzzedDataProvider.h from LLVM
 */

#include "fuzzing_syscalls.h"
#include "syscalls/FuzzedDataProvider.h"
#include "syscalls/argv_builder.h"

#include <setjmp.h>

typedef struct {
  FuzzedDataProvider* provider;

  jmp_buf buf;
  int exit_code;
} _ckb_fuzzing_context_t;

_ckb_fuzzing_context_t* _CKB_FUZZING_GCONTEXT = NULL;

int ckb_fuzzing_start(const uint8_t* data, size_t length) {
  FuzzedDataProvider provider(data, length);
  _ckb_fuzzing_context_t context;
  context.provider = &provider;
  _CKB_FUZZING_GCONTEXT = &context;

  ArgvBuilder argv_builder;
  int argc = provider.ConsumeIntegralInRange(0, 20);
  for (int i = 0; i < argc; i++) {
    std::string arg = provider.ConsumeRandomLengthString(50);
    argv_builder.push(arg.c_str());
  }
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

int ckb_exit(int8_t code) {
  _CKB_FUZZING_GCONTEXT->exit_code = (int)code;
  longjmp(_CKB_FUZZING_GCONTEXT->buf, 1);
}

int _ckb_fuzzing_io_data(void* addr, uint64_t* len,
                         FuzzedDataProvider* provider) {
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  uint64_t available_length = provider->ConsumeIntegral<uint64_t>();
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

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source) {
  (void)offset;
  (void)index;
  (void)source;
  (void)offset;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_transaction(void* addr, uint64_t* len, size_t offset) {
  (void)offset;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;
  (void)field;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;
  (void)field;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;
  (void)field;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_cell_data_as_code(void* addr, size_t memory_size,
                               size_t content_offset, size_t content_size,
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

int ckb_debug(const char* s) {
  fprintf(stderr, "Script debug message: %s\n", s);
  return CKB_SUCCESS;
}

int ckb_vm_version() {
  return (int)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT->provider);
}

uint64_t ckb_current_cycles() {
  return (uint64_t)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT->provider);
}

int ckb_exec(size_t index, size_t source, size_t place, size_t bounds, int argc,
             const char* argv[]) {
  (void)index;
  (void)source;
  (void)place;
  (void)bounds;
  (void)argc;
  (void)argv;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT->provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  return ckb_exit(0);
}

int ckb_spawn(size_t index, size_t source, size_t place, size_t bounds,
              spawn_args_t* spawn_args) {
  (void)index;
  (void)source;
  (void)place;
  (void)bounds;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT->provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  *spawn_args->process_id = provider->ConsumeIntegral<uint64_t>();
  return CKB_SUCCESS;
}

int ckb_wait(uint64_t pid, int8_t* exit_code) {
  (void)pid;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT->provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  *exit_code = provider->ConsumeIntegral<int8_t>();
  return CKB_SUCCESS;
}

uint64_t ckb_process_id() {
  return (uint64_t)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT->provider);
}

int ckb_pipe(uint64_t out_fds[2]) {
  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT->provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  out_fds[0] = provider->ConsumeIntegral<uint64_t>();
  out_fds[1] = provider->ConsumeIntegral<uint64_t>();
  return CKB_SUCCESS;
}

int ckb_read(uint64_t fd, void* buffer, size_t* length) {
  (void)fd;

  return _ckb_fuzzing_io_data(buffer, length, _CKB_FUZZING_GCONTEXT->provider);
}

int ckb_write(uint64_t fd, const void* buffer, size_t* length) {
  (void)fd;
  (void)buffer;

  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT->provider;
  if (provider->ConsumeIntegral<uint8_t>() > 127) {
    // Return with a non zero error code
    return (int)provider->ConsumeIntegralInRange<uint8_t>(1, 255);
  }

  *length = provider->ConsumeIntegral<uint64_t>();
  return CKB_SUCCESS;
}

int ckb_inherited_fds(uint64_t* out_fds, size_t* length) {
  FuzzedDataProvider* provider = _CKB_FUZZING_GCONTEXT->provider;
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

int ckb_close(uint64_t fd) {
  (void)fd;

  return (int)_ckb_fuzzing_return_code(_CKB_FUZZING_GCONTEXT->provider);
}

int ckb_load_block_extension(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  (void)offset;
  (void)index;
  (void)offset;
  (void)source;

  return _ckb_fuzzing_io_data(addr, len, _CKB_FUZZING_GCONTEXT->provider);
}
