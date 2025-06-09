#![no_std]

extern crate alloc;

pub mod generated {
    pub mod traces {
        include!(concat!(env!("OUT_DIR"), "/generated.traces.rs"));
    }
}

use crate::generated::traces;
use alloc::{boxed::Box, collections::VecDeque};
use ckb_syscall_defs::{
    SyscallImpls,
    types::{CellField, Error, HeaderField, InputField, IoResult, Source},
};
use core::ffi::CStr;
use spin::Mutex;

pub const UNEXPECTED: u64 = 19;
pub const UNEXPECTED_ERROR: Error = Error::Other(UNEXPECTED);
pub const UNEXPECTED_RESULT: IoResult = IoResult::Error(UNEXPECTED_ERROR);

pub struct ProtobufBasedSyscallImpls {
    syscalls: Mutex<VecDeque<traces::Syscall>>,
    debug_printer: Box<dyn Fn(&str) + Send + Sync>,
}

impl ProtobufBasedSyscallImpls {
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
    fn debug(&self, s: &str) {
        (self.debug_printer)(s);
    }

    fn exit(&self, code: i8) -> ! {
        panic!("@@@@CKB@@@@FUZING@@@@EXIT@@@@{}@@@@", code);
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

    fn load_cell_data_raw(
        &self,
        buf_ptr: *mut u8,
        len: usize,
        _offset: usize,
        _index: usize,
        _source: Source,
    ) -> IoResult {
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr, len) };
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
                for i in 0..count {
                    out_fds[i] = fds.fds[i];
                }
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
