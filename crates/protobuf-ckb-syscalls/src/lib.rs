#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod generated {
    pub mod traces {
        include!(concat!(env!("OUT_DIR"), "/generated.traces.rs"));
    }
}

use crate::generated::traces;
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use ckb_std::{
    ckb_constants::{CellField, HeaderField, InputField, Source},
    syscalls::traits::{Error, IoResult, SyscallImpls},
};
use ckb_vm_fuzzing_utils::{exit_with_panic, flatten_args};
use core::ffi::CStr;
use prost::Message;
use spin::Mutex;

pub const UNEXPECTED: u64 = 19;
pub const UNEXPECTED_ERROR: Error = Error::Other(UNEXPECTED);
pub const UNEXPECTED_RESULT: IoResult = IoResult::Error(UNEXPECTED_ERROR);

#[cfg(feature = "std")]
pub fn entry<F>(data: &[u8], f: F) -> i8
where
    F: Fn() -> i8 + std::panic::UnwindSafe,
{
    let Some(impls) = ProtobufBasedSyscallImpls::new_with_bytes(data) else {
        return UNEXPECTED as i8;
    };
    let (argc, argv) = flatten_args(impls.args());
    let argv = unsafe { core::slice::from_raw_parts(argv.as_ptr() as *const _, argc) };
    ckb_vm_fuzzing_utils::entry(impls, f, argv)
}

pub struct ProtobufBasedSyscallImpls {
    syscalls: Mutex<VecDeque<traces::Syscall>>,
    args: Vec<Vec<u8>>,
    debug_printer: Box<dyn Fn(&str) + Send + Sync>,
}

impl ProtobufBasedSyscallImpls {
    fn new(syscalls: traces::Syscalls) -> Option<Self> {
        Some(Self {
            syscalls: Mutex::new(syscalls.syscalls.into()),
            args: syscalls.args,
            #[allow(unused_variables)]
            debug_printer: Box::new(|message| {
                #[cfg(feature = "std")]
                eprintln!("Script message: {}", message);
            }),
        })
    }

    pub fn new_with_bytes<B: AsRef<[u8]>>(bytes: B) -> Option<Self> {
        traces::Syscalls::decode(bytes.as_ref())
            .ok()
            .and_then(|data| Self::new(data))
    }

    #[cfg(feature = "std")]
    pub fn new_with_file<P: AsRef<std::path::Path>>(path: P) -> Option<Self> {
        Self::new_with_bytes(std::fs::read(path).expect("read trace file"))
    }

    pub fn args(&self) -> &[Vec<u8>] {
        &self.args
    }

    fn syscall(&self) -> Option<traces::syscall::Value> {
        let mut syscalls = self.syscalls.lock();
        syscalls.pop_front().and_then(|s| s.value)
    }

    fn io_syscall(&self, buf: &mut [u8]) -> IoResult {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                let Ok(e): Result<Error, _> = (code as u64).try_into() else {
                    return UNEXPECTED_RESULT;
                };
                e.into()
            }
            Some(traces::syscall::Value::IoData(io_data)) => {
                let result = if buf.len() > io_data.available_data.len() {
                    if io_data.additional_length > 0 {
                        return UNEXPECTED_RESULT;
                    }
                    IoResult::FullyLoaded(io_data.available_data.len())
                } else if (buf.len() < io_data.available_data.len())
                    || (io_data.additional_length > 0)
                {
                    IoResult::PartialLoaded {
                        loaded: buf.len(),
                        available: io_data.available_data.len()
                            + io_data.additional_length as usize,
                    }
                } else {
                    // buf.len() == io_data.available_data.len() &&
                    // io_data.additional_length == 0
                    IoResult::FullyLoaded(buf.len())
                };
                if let Some(read) = result.loaded() {
                    if read > 0 {
                        buf[0..read].copy_from_slice(&io_data.available_data[0..read]);
                    }
                }
                result
            }
            _ => UNEXPECTED_RESULT,
        }
    }
}

impl SyscallImpls for ProtobufBasedSyscallImpls {
    fn debug(&self, s: &CStr) {
        (self.debug_printer)(s.to_str().unwrap_or("utf8 error"));
    }

    fn exit(&self, code: i8) -> ! {
        exit_with_panic(code);
    }

    fn load_cell(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_cell_by_field(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
        _field: CellField,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_cell_code(
        &self,
        _buf_ptr: *mut u8,
        _len: usize,
        _content_offset: usize,
        _content_size: usize,
        _index: usize,
        _source: Source,
    ) -> Result<(), Error> {
        panic!("Load cell data as code is not suported!");
    }

    fn load_cell_data(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_header(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_header_by_field(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
        _field: HeaderField,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_input(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_input_by_field(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
        _field: InputField,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_script(&self, buf: &mut [u8], _offset: usize) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_script_hash(&self, buf: &mut [u8], _offset: usize) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_transaction(&self, buf: &mut [u8], _offset: usize) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_tx_hash(&self, buf: &mut [u8], _offset: usize) -> IoResult {
        self.io_syscall(buf)
    }

    fn load_witness(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        self.io_syscall(buf)
    }

    fn vm_version(&self) -> u64 {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => code as u64,
            _ => UNEXPECTED,
        }
    }

    fn current_cycles(&self) -> u64 {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => code as u64,
            _ => UNEXPECTED,
        }
    }

    fn exec(
        &self,
        _index: usize,
        _source: Source,
        _place: usize,
        _bounds: usize,
        _argv: &[&CStr],
    ) -> Result<(), Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::Terminated(_)) => {
                self.exit(0);
            }
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn spawn(
        &self,
        _index: usize,
        _source: Source,
        _place: usize,
        _bounds: usize,
        _argv: &[&CStr],
        _inherited_fds: &[u64],
    ) -> Result<u64, Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::SuccessOutputData(output)) => Ok(output),
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn pipe(&self) -> Result<(u64, u64), Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::Fds(fds)) => {
                if fds.fds.len() != 2 {
                    return Err(UNEXPECTED_ERROR);
                }
                Ok((fds.fds[0], fds.fds[1]))
            }
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn inherited_fds(&self, out_fds: &mut [u64]) -> Result<usize, Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::Fds(fds)) => {
                let count = core::cmp::min(out_fds.len(), fds.fds.len());
                out_fds[..count].copy_from_slice(&fds.fds[..count]);
                Ok(fds.fds.len())
            }
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn read(&self, _fd: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::IoData(io_data)) => {
                let read = core::cmp::min(io_data.available_data.len(), buffer.len());
                buffer[0..read].copy_from_slice(&io_data.available_data[0..read]);
                Ok(read)
            }
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn write(&self, _fd: u64, _buffer: &[u8]) -> Result<usize, Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::SuccessOutputData(output)) => Ok(output as usize),
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn close(&self, _fd: u64) -> Result<(), Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                if code == 0 {
                    Ok(())
                } else {
                    Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
                }
            }
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn wait(&self, _pid: u64) -> Result<i8, Error> {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => {
                Err((code as u64).try_into().unwrap_or(UNEXPECTED_ERROR))
            }
            Some(traces::syscall::Value::SuccessOutputData(output)) => Ok(output as i8),
            _ => Err(UNEXPECTED_ERROR),
        }
    }

    fn process_id(&self) -> u64 {
        match self.syscall() {
            Some(traces::syscall::Value::ReturnWithCode(code)) => code as u64,
            _ => UNEXPECTED,
        }
    }

    fn load_block_extension(
        &self,
        buf: &mut [u8],
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        self.io_syscall(buf)
    }
}
