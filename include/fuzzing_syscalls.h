#ifndef CKB_FUZZING_SYSCALLS_H_
#define CKB_FUZZING_SYSCALLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CKB_C_STDLIB_CKB_SYSCALLS_H_) || \
    defined(CKB_C_STDLIB_CKB_RAW_SYSCALLS_H_)
#error \
    "fuzzing_syscalls.h cannot be used with ckb_syscalls.h, please use ckb_syscall_apis.h instead."
#endif

/* main function in actual CKB script will be rewritten to this name. */
#ifndef CKB_FUZZING_ENTRYPOINT
#define CKB_FUZZING_ENTRYPOINT _ckb_fuzzing_entrypoint
#endif

/* A special error code used by fuzzing engine. */
#ifndef CKB_FUZZING_UNEXPECTED
#define CKB_FUZZING_UNEXPECTED 19
#endif

#define CKB_FUZZING_OVERRIDE_MODE_INTERNAL_SYSCALL 1
#define CKB_FUZZING_OVERRIDE_MODE_LOADER_FUNCS 2
#ifndef CKB_FUZZING_OVERRIDE_INTERNAL_SYSCALL
#define CKB_FUZZING_OVERRIDE_INTERNAL_SYSCALL \
  CKB_FUZZING_OVERRIDE_MODE_INTERNAL_SYSCALL
#endif

#include "ckb_consts.h"
#include "ckb_syscall_apis.h"

extern int CKB_FUZZING_ENTRYPOINT(int argc, char* argv[]);
extern int ckb_fuzzing_start(const uint8_t* data, size_t length);

/*
 * !!!!!!!!!!!!!!!!!!!!!!!IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !Any reference to main will be rewritten in the actual code!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define main CKB_FUZZING_ENTRYPOINT

#ifdef __cplusplus
}
#endif

#endif /* CKB_FUZZING_SYSCALLS_H_ */
