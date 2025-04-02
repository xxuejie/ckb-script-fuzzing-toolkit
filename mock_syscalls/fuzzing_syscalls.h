#ifndef CKB_FUZZING_MOCK_SYSCALLS_H_
#define CKB_FUZZING_MOCK_SYSCALLS_H_

#ifdef CKB_C_STDLIB_CKB_SYSCALLS_H_
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

/* Forward declarations required by C / C++ */

#include "traces.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int CKB_FUZZING_ENTRYPOINT(int argc, char* argv[]);

int ckb_fuzzing_start_syscall_flavor(
    const generated::traces::Syscalls* syscalls);

#ifdef __cplusplus
}
#endif

/*
 * !!!!!!!!!!!!!!!!!!!!!!!IMPORTANT!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !Any reference to main will be rewritten in the actual code!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define main CKB_FUZZING_ENTRYPOINT

#endif /* CKB_FUZZING_MOCK_SYSCALLS_H_ */
