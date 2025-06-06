//! This module is the opposite directory of stub:
//! Syscalls defined in https://docs.rs/ckb-std/latest/ckb_std/syscalls/index.html
//! were written at different times, with different mindsets, and accumulated
//! throughout the years. They are not following a unified set of conventions.
//! In addition, certain functions handle syscalls in a weird way. This module
//! aims to solve the problem: it defines a dummy struct implementing SyscallImpls
//! trait, which is designed in a way that all syscalls share the same convention,
//! handle error codes in the same fashion. By relying on this module, one can
//! avoid confusions in ckb-std, and have this module does the dirty conversion
//! undearneath.

#[macro_export]
macro_rules! syscall_impls_from_ckb_std_style_module {
    ($module:ident, $structure:ident) => {
        impl $crate::SyscallImpls for $structure {
            fn debug(&self, s: &str) {
                use alloc::string::ToString;
                $module::debug(s.to_string())
            }

            fn exit(&self, code: i8) -> ! {
                $module::exit(code)
            }

            fn load_cell(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_cell(buf, offset, index, source.into()),
                    buf.len(),
                )
            }

            fn load_cell_by_field(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
                field: $crate::types::CellField,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_cell_by_field(buf, offset, index, source.into(), field.into()),
                    buf.len(),
                )
            }

            fn load_cell_code(
                &self,
                buf_ptr: *mut u8,
                len: usize,
                content_offset: usize,
                content_size: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> Result<(), $crate::types::Error> {
                $crate::ckb_std::trait_wrapper::ce($module::load_cell_code(
                    buf_ptr,
                    len,
                    content_offset,
                    content_size,
                    index,
                    source.into(),
                ))
                .map(|_| ())
            }

            fn load_cell_data_raw(
                &self,
                buf_ptr: *mut u8,
                len: usize,
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_cell_data_raw(buf_ptr, len, offset, index, source.into()),
                    len,
                )
            }

            fn load_cell_data(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_cell_data(buf, offset, index, source.into()),
                    buf.len(),
                )
            }

            fn load_header(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_header(buf, offset, index, source.into()),
                    buf.len(),
                )
            }

            fn load_header_by_field(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
                field: $crate::types::HeaderField,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_header_by_field(buf, offset, index, source.into(), field.into()),
                    buf.len(),
                )
            }

            fn load_input(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_input(buf, offset, index, source.into()),
                    buf.len(),
                )
            }

            fn load_input_by_field(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
                field: $crate::types::InputField,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_input_by_field(buf, offset, index, source.into(), field.into()),
                    buf.len(),
                )
            }

            fn load_script(&self, buf: &mut [u8], offset: usize) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_script(buf, offset),
                    buf.len(),
                )
            }

            fn load_script_hash(&self, buf: &mut [u8], offset: usize) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_script_hash(buf, offset),
                    buf.len(),
                )
            }

            fn load_transaction(&self, buf: &mut [u8], offset: usize) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_transaction(buf, offset),
                    buf.len(),
                )
            }

            fn load_tx_hash(&self, buf: &mut [u8], offset: usize) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_tx_hash(buf, offset),
                    buf.len(),
                )
            }

            fn load_witness(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_witness(buf, offset, index, source.into()),
                    buf.len(),
                )
            }

            fn vm_version(&self) -> u64 {
                match $module::vm_version() {
                    Ok(version) => version,
                    Err(ckb_std::error::SysError::Unknown(future_version)) => future_version,
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            }

            fn current_cycles(&self) -> u64 {
                $module::current_cycles()
            }

            fn exec(
                &self,
                index: usize,
                source: $crate::types::Source,
                place: usize,
                bounds: usize,
                argv: &[&core::ffi::CStr],
            ) -> Result<(), $crate::types::Error> {
                let code = $module::exec(index, source.into(), place, bounds, argv);
                if code == 0 {
                    Ok(())
                } else {
                    Err(code.try_into().unwrap())
                }
            }

            fn spawn(
                &self,
                index: usize,
                source: $crate::types::Source,
                place: usize,
                bounds: usize,
                argv: &[&core::ffi::CStr],
                inherited_fds: &[u64],
            ) -> Result<u64, $crate::types::Error> {
                let mut fds_with_terminator = alloc::vec![0; inherited_fds.len() + 1];
                fds_with_terminator[0..inherited_fds.len()].copy_from_slice(inherited_fds);

                let mut argv_ptrs = alloc::vec::Vec::with_capacity(argv.len());
                for arg in argv {
                    argv_ptrs.push(arg.as_ptr());
                }

                let mut process_id = 0;
                let mut spgs = $module::SpawnArgs {
                    argc: argv.len() as u64,
                    argv: argv_ptrs.as_ptr(),
                    process_id: &mut process_id,
                    inherited_fds: fds_with_terminator.as_ptr(),
                };

                $crate::ckb_std::trait_wrapper::ce($module::spawn(
                    index,
                    source.into(),
                    place,
                    bounds,
                    &mut spgs,
                ))
            }

            fn pipe(&self) -> Result<(u64, u64), $crate::types::Error> {
                $crate::ckb_std::trait_wrapper::ce($module::pipe())
            }

            fn inherited_fds(&self, fds: &mut [u64]) -> Result<usize, $crate::types::Error> {
                // For now, ckb-std's inherited_fds function assumes that this
                // syscall always succeeds. There is no way we can know what
                // possible error the syscall returns.
                Ok($module::inherited_fds(fds) as usize)
            }

            fn read(&self, fd: u64, buffer: &mut [u8]) -> Result<usize, $crate::types::Error> {
                $crate::ckb_std::trait_wrapper::ce($module::read(fd, buffer))
            }

            fn write(&self, fd: u64, buffer: &[u8]) -> Result<usize, $crate::types::Error> {
                $crate::ckb_std::trait_wrapper::ce($module::write(fd, buffer))
            }

            fn close(&self, fd: u64) -> Result<(), $crate::types::Error> {
                $crate::ckb_std::trait_wrapper::ce($module::close(fd))
            }

            fn wait(&self, pid: u64) -> Result<i8, $crate::types::Error> {
                $crate::ckb_std::trait_wrapper::ce($module::wait(pid))
            }

            fn process_id(&self) -> u64 {
                $module::process_id()
            }

            fn load_block_extension(
                &self,
                buf: &mut [u8],
                offset: usize,
                index: usize,
                source: $crate::types::Source,
            ) -> $crate::types::IoResult {
                $crate::ckb_std::trait_wrapper::build_io_result(
                    $module::load_block_extension(buf, offset, index, source.into()),
                    buf.len(),
                )
            }
        }
    };
}

pub struct StdSyscallWrapper {}
syscall_impls_from_ckb_std_style_module!(std_syscalls, StdSyscallWrapper);

use crate::types::{Error, IoResult};
use ckb_std::{error::SysError, syscalls as std_syscalls};

pub fn build_io_result(result: Result<usize, SysError>, original_length: usize) -> IoResult {
    match result {
        Ok(l) => {
            assert!(l <= original_length);
            IoResult::FullyLoaded(l)
        }
        Err(SysError::LengthNotEnough(available)) => IoResult::PartialLoaded {
            loaded: original_length,
            available,
        },
        Err(e) => IoResult::Error(e.try_into().unwrap()),
    }
}

pub fn ce<V>(result: Result<V, SysError>) -> Result<V, Error> {
    result.map_err(|e| e.try_into().unwrap())
}
