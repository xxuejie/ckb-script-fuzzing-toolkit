#ifndef CKB_FUZZING_SYSCALLS_INTERNAL_H_
#define CKB_FUZZING_SYSCALLS_INTERNAL_H_

#include "fuzzing_syscalls.h"
#include "traces.pb.h"

int ckb_fuzzing_start_syscall_flavor(
    const generated::traces::Syscalls* syscalls);

#endif /* CKB_FUZZING_SYSCALLS_INTERNAL_H_ */
