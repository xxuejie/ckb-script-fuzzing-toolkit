#ifndef CKB_FUZZING_SYSCALLS_PROTOBUF_H_
#define CKB_FUZZING_SYSCALLS_PROTOBUF_H_

#include "fuzzing_syscalls.h"
#include "traces.pb.h"

int ckb_fuzzing_start_with_protobuf(
    const generated::traces::Syscalls* syscalls);

#endif /* CKB_FUZZING_SYSCALLS_PROTOBUF_H_ */
