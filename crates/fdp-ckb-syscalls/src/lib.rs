#![cfg_attr(not(feature = "std"), no_std)]

use ckb_std::syscalls::traits::SyscallImpls;
use ckb_vm_fuzzing_utils::exit_with_panic;
use core::ffi::{c_int, c_long, c_void};

#[repr(C)]
pub struct FdpCData {
    provider: *mut c_void,
    argc: c_int,
    argv: *const *const i8,
}

unsafe extern "C" {
    fn __internal_syscall(
        n: c_long,
        a0: c_long,
        a1: c_long,
        a2: c_long,
        a3: c_long,
        a4: c_long,
        a5: c_long,
    ) -> c_long;

    fn ckb_fuzzing_fdp_init(data: *const u8, length: u64) -> *const FdpCData;
    fn ckb_fuzzing_fdp_cleanup();
}

#[unsafe(no_mangle)]
pub extern "C" fn _ckb_fuzzing_entrypoint(_argc: c_int, _argv: *const *const i8) -> c_int {
    panic!("Please use Rust's own entrypoint");
}

#[cfg(feature = "std")]
pub fn entry<F>(data: &[u8], f: F) -> i8
where
    F: Fn() -> i8 + std::panic::UnwindSafe,
{
    let p = unsafe { ckb_fuzzing_fdp_init(data.as_ptr(), data.len() as u64) };
    let s = unsafe { &*p };
    let argv = unsafe { core::slice::from_raw_parts(s.argv as *const _, s.argc as usize) };
    let impls = FdpSyscallImpls {};
    let result = ckb_vm_fuzzing_utils::entry(impls, f, argv);
    unsafe { ckb_fuzzing_fdp_cleanup() };
    result
}

pub struct FdpSyscallImpls {}

impl Drop for FdpSyscallImpls {
    fn drop(&mut self) {
        unsafe { ckb_fuzzing_fdp_cleanup() }
    }
}

impl SyscallImpls for FdpSyscallImpls {
    fn syscall(&self, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, n: u64) -> u64 {
        (unsafe {
            __internal_syscall(
                n as c_long,
                a0 as c_long,
                a1 as c_long,
                a2 as c_long,
                a3 as c_long,
                a4 as c_long,
                a5 as c_long,
            )
        }) as u64
    }

    fn exit(&self, code: i8) -> ! {
        exit_with_panic(code);
    }
}
