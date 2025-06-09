#![no_std]

extern crate alloc;

// TODO: test if setjmp / longjmp is good enough here, or use panics
// instead.
pub use ckb_c_to_std_syscalls as syscalls;
use ckb_syscall_defs::syscall_impls_from_ckb_std_style_module;

pub struct FdpSyscallWrapper {}
syscall_impls_from_ckb_std_style_module!(syscalls, FdpSyscallWrapper);
