//! This module maps C APIs defined in ckb-c-stdlib:
//! https://github.com/nervosnetwork/ckb-c-stdlib/blob/7245b6268ef623f204501dc2beb6b3ae7d7b3cf4/ckb_syscall_apis.h#L14-L76
//! to Rust APIs defined in ckb-std:
//! https://docs.rs/ckb-std/latest/ckb_std/syscalls/index.html
//! It is originally designed for FDP based fuzzer, but the code should
//! be flexible enough to reuse elsewhere.
#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use ckb_std::{
    ckb_constants::{CellField, HeaderField, InputField, Source},
    error::SysError,
};
use core::ffi::{CStr, c_char, c_int, c_void};

pub use ckb_std::syscalls::SpawnArgs;
pub type SizeT = u64;

unsafe extern "C" {
    fn ckb_exit(code: i8) -> c_int;
    fn ckb_load_tx_hash(addr: *mut c_void, len: *mut u64, offset: SizeT) -> c_int;
    fn ckb_load_transaction(addr: *mut c_void, len: *mut u64, offset: SizeT) -> c_int;
    fn ckb_load_script_hash(addr: *mut c_void, len: *mut u64, offset: SizeT) -> c_int;
    fn ckb_load_script(addr: *mut c_void, len: *mut u64, offset: SizeT) -> c_int;
    fn ckb_debug(s: *const c_char);

    fn ckb_load_cell(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;
    fn ckb_load_input(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;
    fn ckb_load_header(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;
    fn ckb_load_witness(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;
    fn ckb_load_cell_by_field(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
        field: SizeT,
    ) -> c_int;
    fn ckb_load_header_by_field(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
        field: SizeT,
    ) -> c_int;
    fn ckb_load_input_by_field(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
        field: SizeT,
    ) -> c_int;
    fn ckb_load_cell_data(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;
    fn ckb_load_cell_data_as_code(
        addr: *mut c_void,
        memory_size: SizeT,
        content_offset: SizeT,
        content_size: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;

    fn ckb_vm_version() -> c_int;
    fn ckb_current_cycles() -> u64;
    fn ckb_exec(
        index: SizeT,
        source: SizeT,
        place: SizeT,
        bounds: SizeT,
        argc: c_int,
        argv: *const *const c_char,
    ) -> c_int;

    fn ckb_spawn(
        index: SizeT,
        source: SizeT,
        place: SizeT,
        bounds: SizeT,
        spawn_args: *mut SpawnArgs,
    ) -> c_int;
    fn ckb_wait(pid: u64, exit_code: *mut i8) -> c_int;
    fn ckb_process_id() -> u64;
    fn ckb_pipe(fds: *mut u64) -> c_int;
    fn ckb_read(fd: u64, buffer: *mut c_void, length: *mut SizeT) -> c_int;
    fn ckb_write(fd: u64, buffer: *const c_void, length: *mut SizeT) -> c_int;
    fn ckb_inherited_fds(fds: *mut u64, length: *mut SizeT) -> c_int;
    fn ckb_close(fd: u64) -> c_int;
    fn ckb_load_block_extension(
        addr: *mut c_void,
        len: *mut u64,
        offset: SizeT,
        index: SizeT,
        source: SizeT,
    ) -> c_int;
}

pub fn close(fd: u64) -> Result<(), SysError> {
    let ret = unsafe { ckb_close(fd) } as u64;
    match ret {
        0 => Ok(()),
        6 => Err(SysError::InvalidFd),
        x => Err(SysError::Unknown(x)),
    }
}

pub fn current_cycles() -> u64 {
    unsafe { ckb_current_cycles() }
}

pub fn debug(mut s: String) {
    s.push('\0');
    let b = s.into_bytes();

    unsafe { ckb_debug(b.as_ptr() as *const _) }
}

pub fn exec(index: usize, source: Source, place: usize, bounds: usize, argv: &[&CStr]) -> u64 {
    let argv_ptr: Vec<_> = argv.iter().map(|e| e.as_ptr() as *const i8).collect();
    unsafe {
        ckb_exec(
            index as SizeT,
            source as SizeT,
            place as SizeT,
            bounds as SizeT,
            argv.len() as c_int,
            argv_ptr.as_ptr(),
        ) as u64
    }
}

pub fn exit(code: i8) -> ! {
    unsafe {
        ckb_exit(code);
    }
    unreachable!()
}

pub fn inherited_fds(fds: &mut [u64]) -> u64 {
    let mut l = fds.len() as u64;
    unsafe { ckb_inherited_fds(fds.as_mut_ptr(), &mut l as *mut u64) };
    l
}

pub fn load_block_extension(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_block_extension(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_cell(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_cell(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_cell_by_field(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
    field: CellField,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_cell_by_field(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
            field as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_cell_code(
    buf_ptr: *mut u8,
    len: usize,
    content_offset: usize,
    content_size: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let errno = unsafe {
        ckb_load_cell_data_as_code(
            buf_ptr as *mut _,
            len as SizeT,
            content_offset as SizeT,
            content_size as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, len, len)
}

pub fn load_cell_data(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    load_cell_data_raw(buf.as_mut_ptr(), buf.len(), offset, index, source)
}

pub fn load_cell_data_raw(
    buf_ptr: *mut u8,
    len: usize,
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let mut actual_len = len as u64;
    let errno = unsafe {
        ckb_load_cell_data(
            buf_ptr as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, len, actual_len as usize)
}

pub fn load_header(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_header(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_header_by_field(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
    field: HeaderField,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_header_by_field(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
            field as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_input(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_input(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_input_by_field(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
    field: InputField,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_input_by_field(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
            field as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_script(buf: &mut [u8], offset: usize) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_script(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_script_hash(buf: &mut [u8], offset: usize) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_script_hash(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_transaction(buf: &mut [u8], offset: usize) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_transaction(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_tx_hash(buf: &mut [u8], offset: usize) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_tx_hash(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn load_witness(
    buf: &mut [u8],
    offset: usize,
    index: usize,
    source: Source,
) -> Result<usize, SysError> {
    let mut actual_len = buf.len() as u64;
    let errno = unsafe {
        ckb_load_witness(
            buf.as_mut_ptr() as *mut _,
            &mut actual_len as *mut u64,
            offset as SizeT,
            index as SizeT,
            source as SizeT,
        )
    };
    build_result(errno, buf.len(), actual_len as usize)
}

pub fn pipe() -> Result<(u64, u64), SysError> {
    let mut fds: [u64; 2] = [0, 0];
    let ret = unsafe { ckb_pipe(fds.as_mut_ptr()) };
    match ret {
        0 => Ok((fds[0], fds[1])),
        9 => Err(SysError::MaxFdsCreated),
        x => Err(SysError::Unknown(x as u64)),
    }
}

pub fn process_id() -> u64 {
    unsafe { ckb_process_id() }
}

pub fn read(fd: u64, buffer: &mut [u8]) -> Result<usize, SysError> {
    let mut l: u64 = buffer.len() as u64;
    let ret = unsafe { ckb_read(fd, buffer.as_mut_ptr() as *mut _, &mut l as *mut u64) };
    match ret {
        0 => Ok(l as usize),
        1 => Err(SysError::IndexOutOfBound),
        6 => Err(SysError::InvalidFd),
        7 => Err(SysError::OtherEndClosed),
        x => Err(SysError::Unknown(x as u64)),
    }
}

pub fn spawn(
    index: usize,
    source: Source,
    place: usize,
    bounds: usize,
    spgs: &mut SpawnArgs,
) -> Result<u64, SysError> {
    let ret = unsafe {
        ckb_spawn(
            index as SizeT,
            source as SizeT,
            place as SizeT,
            bounds as SizeT,
            spgs as *mut _,
        )
    };
    match ret {
        0 => Ok(unsafe { *spgs.process_id }),
        1 => Err(SysError::IndexOutOfBound),
        2 => Err(SysError::ItemMissing),
        3 => Err(SysError::Encoding),
        6 => Err(SysError::InvalidFd),
        8 => Err(SysError::MaxVmsSpawned),
        x => Err(SysError::Unknown(x as u64)),
    }
}

pub fn vm_version() -> Result<u64, SysError> {
    let ret = unsafe { ckb_vm_version() } as u64;
    match ret {
        1 | 2 => Ok(ret),
        _ => Err(SysError::Unknown(ret)),
    }
}

pub fn wait(pid: u64) -> Result<i8, SysError> {
    let mut code: i8 = 0;
    let ret = unsafe { ckb_wait(pid, &mut code as *mut i8) };
    match ret {
        0 => Ok(code),
        5 => Err(SysError::WaitFailure),
        x => Err(SysError::Unknown(x as u64)),
    }
}

pub fn write(fd: u64, buffer: &[u8]) -> Result<usize, SysError> {
    let mut l: u64 = buffer.len() as u64;
    let ret = unsafe { ckb_write(fd, buffer.as_ptr() as *const _, &mut l as *mut u64) };
    match ret {
        0 => Ok(l as usize),
        1 => Err(SysError::IndexOutOfBound),
        6 => Err(SysError::InvalidFd),
        7 => Err(SysError::OtherEndClosed),
        x => Err(SysError::Unknown(x as u64)),
    }
}

fn build_result(errno: c_int, load_len: usize, actual_data_len: usize) -> Result<usize, SysError> {
    use SysError::*;

    match errno {
        0 => {
            if actual_data_len > load_len {
                return Err(LengthNotEnough(actual_data_len));
            }
            Ok(actual_data_len)
        }
        1 => Err(IndexOutOfBound),
        2 => Err(ItemMissing),
        _ => Err(Unknown(errno as u64)),
    }
}
