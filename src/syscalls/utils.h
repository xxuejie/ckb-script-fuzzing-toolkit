#ifndef CKB_FUZZING_SYSCALLS_UTILS_H_
#define CKB_FUZZING_SYSCALLS_UTILS_H_

#include "fuzzing_syscalls.h"

#include <vector>

#include <stdlib.h>
#include <string.h>

class ArgvBuilder {
  char* buffer_;
  size_t length_;
  std::vector<size_t> offsets_;

 public:
  ArgvBuilder() : buffer_(NULL), length_(0) {}

  ~ArgvBuilder() {
    if (buffer_ != NULL) {
      free(buffer_);
    }
  }

  void push(const char* arg) {
    // Each argv is aligned by 8 bytes.
    size_t current_len = strlen(arg) + 1;
    size_t rounded_len = ((current_len + 7) / 8) * 8;

    buffer_ = (char*)realloc(buffer_, length_ + rounded_len);
    memcpy(&buffer_[length_], arg, current_len);
    if (rounded_len > current_len) {
      memset(&buffer_[length_ + current_len], 0, rounded_len - current_len);
    }

    offsets_.push_back(length_);
    length_ += rounded_len;
  }

  int argc() const { return offsets_.size(); }

  char** argv() const {
    // At the start, each argv item requires a pointer, plus a NULL pointer
    size_t pointers_size = (offsets_.size() + 1) * sizeof(size_t);
    char* flattened_argv = (char*)malloc(pointers_size + length_);
    if (length_ > 0) {
      memcpy(&flattened_argv[pointers_size], buffer_, length_);
    }
    for (size_t i = 0; i < offsets_.size(); i++) {
      ((size_t*)flattened_argv)[i] =
          (size_t)(&flattened_argv[pointers_size + offsets_[i]]);
    }
    ((size_t*)flattened_argv)[offsets_.size()] = 0;
    return (char**)flattened_argv;
  }
};

#if CKB_FUZZING_OVERRIDE_INTERNAL_SYSCALL == 1

#ifndef _CKB_FUZZING_SYSCALL_FUNC_NAME
#define _CKB_FUZZING_SYSCALL_FUNC_NAME(func) (_ckb_fuzzing_##func)
#endif
#define _CKB_FUZZING_INTERNAL_SYSCALL_OVERRIDE

#else

#ifndef _CKB_FUZZING_SYSCALL_FUNC_NAME
#define _CKB_FUZZING_SYSCALL_FUNC_NAME(func) (ckb_##func)
#endif
#undef _CKB_FUZZING_INTERNAL_SYSCALL_OVERRIDE

#endif

extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(exit)(int8_t code);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_tx_hash)(void* addr,
                                                        uint64_t* len,
                                                        size_t offset);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_transaction)(void* addr,
                                                            uint64_t* len,
                                                            size_t offset);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script_hash)(void* addr,
                                                            uint64_t* len,
                                                            size_t offset);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script)(void* addr,
                                                       uint64_t* len,
                                                       size_t offset);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(debug)(const char* s);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell)(void* addr, uint64_t* len,
                                                     size_t offset,
                                                     size_t index,
                                                     size_t source);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input)(void* addr, uint64_t* len,
                                                      size_t offset,
                                                      size_t index,
                                                      size_t source);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_witness)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input_by_field)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source,
    size_t field);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data_as_code)(
    void* addr, size_t memory_size, size_t content_offset, size_t content_size,
    size_t index, size_t source);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(vm_version)();
extern uint64_t _CKB_FUZZING_SYSCALL_FUNC_NAME(current_cycles)();
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(exec)(size_t index, size_t source,
                                                size_t place, size_t bounds,
                                                int argc, const char* argv[]);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(spawn)(size_t index, size_t source,
                                                 size_t place, size_t bounds,
                                                 spawn_args_t* spawn_args);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(wait)(uint64_t pid,
                                                int8_t* exit_code);
extern uint64_t _CKB_FUZZING_SYSCALL_FUNC_NAME(process_id)();
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(pipe)(uint64_t fds[2]);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(read)(uint64_t fd, void* buffer,
                                                size_t* length);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(write)(uint64_t fd,
                                                 const void* buffer,
                                                 size_t* length);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(inherited_fds)(uint64_t* fds,
                                                         size_t* length);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(close)(uint64_t fd);
extern int _CKB_FUZZING_SYSCALL_FUNC_NAME(load_block_extension)(
    void* addr, uint64_t* len, size_t offset, size_t index, size_t source);

#ifdef _CKB_FUZZING_INTERNAL_SYSCALL_OVERRIDE

long __internal_syscall(long n, long a0, long a1, long a2, long a3, long a4,
                        long a5) {
  switch (n) {
    case SYS_exit: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(exit)(a0);
    } break;
    case SYS_ckb_vm_version: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(vm_version)();
    } break;
    case SYS_ckb_current_cycles: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(current_cycles)();
    } break;
    case SYS_ckb_exec: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(exec)(a0, a1, a2, a3, (int)a4,
                                                  (const char**)a5);
    } break;
    case SYS_ckb_load_transaction: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_transaction)(
          (void*)a0, (uint64_t*)a1, a2);
    } break;
    case SYS_ckb_load_script: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script)((void*)a0,
                                                         (uint64_t*)a1, a2);
    } break;
    case SYS_ckb_load_tx_hash: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_tx_hash)((void*)a0,
                                                          (uint64_t*)a1, a2);
    } break;
    case SYS_ckb_load_script_hash: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_script_hash)(
          (void*)a0, (uint64_t*)a1, a2);
    } break;
    case SYS_ckb_load_cell: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell)((void*)a0, (uint64_t*)a1,
                                                       a2, a3, a4);
    } break;
    case SYS_ckb_load_header: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4);
    } break;
    case SYS_ckb_load_input: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4);
    } break;
    case SYS_ckb_load_witness: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_witness)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4);
    } break;
    case SYS_ckb_load_cell_by_field: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_by_field)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4, a5);
    } break;
    case SYS_ckb_load_header_by_field: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_header_by_field)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4, a5);
    } break;
    case SYS_ckb_load_input_by_field: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_input_by_field)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4, a5);
    } break;
    case SYS_ckb_load_cell_data_as_code: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data_as_code)(
          (void*)a0, a1, a2, a3, a4, a5);
    } break;
    case SYS_ckb_load_cell_data: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_cell_data)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4);
    } break;
    case SYS_ckb_debug: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(debug)((const char*)a0);
    } break;
    case SYS_ckb_load_block_extension: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(load_block_extension)(
          (void*)a0, (uint64_t*)a1, a2, a3, a4);
    } break;
    case SYS_ckb_spawn: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(spawn)(a0, a1, a2, a3,
                                                   (spawn_args_t*)a4);
    } break;
    case SYS_ckb_wait: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(wait)(a0, (int8_t*)a1);
    } break;
    case SYS_ckb_process_id: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(process_id)();
    } break;
    case SYS_ckb_pipe: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(pipe)((uint64_t*)a0);
    } break;
    case SYS_ckb_write: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(write)(a0, (const void*)a1,
                                                   (size_t*)a2);
    } break;
    case SYS_ckb_read: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(read)(a0, (void*)a1, (size_t*)a2);
    } break;
    case SYS_ckb_inherited_fds: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(inherited_fds)((uint64_t*)a0,
                                                           (size_t*)a1);
    } break;
    case SYS_ckb_close: {
      return _CKB_FUZZING_SYSCALL_FUNC_NAME(close)(a0);
    } break;
  }
  return _CKB_FUZZING_SYSCALL_FUNC_NAME(exit)(CKB_FUZZING_UNEXPECTED);
}
#endif

#endif  // CKB_FUZZING_SYSCALLS_UTILS_H_
