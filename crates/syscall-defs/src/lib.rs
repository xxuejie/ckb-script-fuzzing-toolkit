#![no_std]
#[macro_use]
extern crate alloc;

#[cfg(feature = "ckb-std")]
pub mod ckb_std;
pub mod types;

use crate::types::{CellField, Error, HeaderField, InputField, IoResult, Source, SyscallCode};
use alloc::{ffi::CString, string::String, vec::Vec};
use ckb_vm::{
    Error as VMError, Memory, Register, SupportMachine, Syscalls,
    memory::load_c_string_byte_by_byte,
    registers::{A0, A1, A2, A3, A4, A5, A7},
};
use core::ffi::CStr;
use core::marker::PhantomData;

pub trait SyscallImpls {
    fn debug(&self, s: &str);
    fn exit(&self, code: i8) -> !;
    fn load_cell(&self, buf: &mut [u8], offset: usize, index: usize, source: Source) -> IoResult;
    fn load_cell_by_field(
        &self,
        buf: &mut [u8],
        offset: usize,
        index: usize,
        source: Source,
        field: CellField,
    ) -> IoResult;
    fn load_cell_code(
        &self,
        buf_ptr: *mut u8,
        len: usize,
        content_offset: usize,
        content_size: usize,
        index: usize,
        source: Source,
    ) -> Result<(), Error>;
    fn load_cell_data_raw(
        &self,
        buf_ptr: *mut u8,
        len: usize,
        offset: usize,
        index: usize,
        source: Source,
    ) -> IoResult;
    fn load_header(&self, buf: &mut [u8], offset: usize, index: usize, source: Source) -> IoResult;
    fn load_header_by_field(
        &self,
        buf: &mut [u8],
        offset: usize,
        index: usize,
        source: Source,
        field: HeaderField,
    ) -> IoResult;
    fn load_input(&self, buf: &mut [u8], offset: usize, index: usize, source: Source) -> IoResult;
    fn load_input_by_field(
        &self,
        buf: &mut [u8],
        offset: usize,
        index: usize,
        source: Source,
        field: InputField,
    ) -> IoResult;
    fn load_script(&self, buf: &mut [u8], offset: usize) -> IoResult;
    fn load_script_hash(&self, buf: &mut [u8], offset: usize) -> IoResult;
    fn load_transaction(&self, buf: &mut [u8], offset: usize) -> IoResult;
    fn load_tx_hash(&self, buf: &mut [u8], offset: usize) -> IoResult;
    fn load_witness(&self, buf: &mut [u8], offset: usize, index: usize, source: Source)
    -> IoResult;

    fn vm_version(&self) -> u64;
    fn current_cycles(&self) -> u64;
    fn exec(
        &self,
        index: usize,
        source: Source,
        place: usize,
        bounds: usize,
        argv: &[&CStr],
    ) -> Result<(), Error>;

    fn spawn(
        &self,
        index: usize,
        source: Source,
        place: usize,
        bounds: usize,
        argv: &[&CStr],
        inherited_fds: &[u64],
    ) -> Result<u64, Error>;
    fn pipe(&self) -> Result<(u64, u64), Error>;
    fn inherited_fds(&self, fds: &mut [u64]) -> Result<usize, Error>;
    fn read(&self, fd: u64, buffer: &mut [u8]) -> Result<usize, Error>;
    fn write(&self, fd: u64, buffer: &[u8]) -> Result<usize, Error>;
    fn close(&self, fd: u64) -> Result<(), Error>;
    fn wait(&self, pid: u64) -> Result<i8, Error>;
    fn process_id(&self) -> u64;
    fn load_block_extension(
        &self,
        buf: &mut [u8],
        offset: usize,
        index: usize,
        source: Source,
    ) -> IoResult;

    fn load_cell_data(
        &self,
        buf: &mut [u8],
        offset: usize,
        index: usize,
        source: Source,
    ) -> IoResult {
        self.load_cell_data_raw(buf.as_mut_ptr(), buf.len(), offset, index, source)
    }
}

pub struct SyscallImplsSynchronousWrapper<S, M> {
    pub impls: S,
    _marker: PhantomData<M>,
}

impl<S, M> SyscallImplsSynchronousWrapper<S, M> {
    pub fn new(impls: S) -> Self {
        Self {
            impls,
            _marker: PhantomData,
        }
    }
}

impl<S, M> SyscallImplsSynchronousWrapper<S, M>
where
    S: SyscallImpls + Send,
    M: SupportMachine + Send,
{
    fn set_return<V>(&self, result: Result<V, Error>, machine: &mut M) {
        let code = match result {
            Ok(_) => 0,
            Err(e) => e.into(),
        };
        machine.set_register(A0, M::REG::from_u64(code));
    }

    fn load_data<F>(&self, machine: &mut M, f: F) -> Result<(), VMError>
    where
        F: Fn(&mut [u8], &S, &mut M) -> IoResult,
    {
        let size_addr = machine.registers()[A1].clone();
        let size = machine.memory_mut().load64(&size_addr)?.to_u64();
        let mut buf = vec![0u8; size as usize];

        let result = f(&mut buf, &self.impls, machine);
        if let Some(loaded) = result.loaded() {
            let addr = machine.registers()[A0].to_u64();
            machine.memory_mut().store_bytes(addr, &buf[0..loaded])?;
        }
        if let Some(available) = result.available() {
            machine
                .memory_mut()
                .store64(&size_addr, &M::REG::from_u64(available as u64))?;
        }
        self.set_return(result.to_result(), machine);
        Ok(())
    }

    fn load_o<F>(&self, machine: &mut M, f: F) -> Result<(), VMError>
    where
        F: Fn(&mut [u8], &S, usize) -> IoResult,
    {
        self.load_data(machine, |buf, impls, machine| {
            let offset = machine.registers()[A2].to_u64() as usize;
            f(buf, impls, offset)
        })
    }

    fn load_ois<F>(&self, machine: &mut M, f: F) -> Result<(), VMError>
    where
        F: Fn(&mut [u8], &S, usize, usize, Source) -> IoResult,
    {
        self.load_data(machine, |buf, impls, machine| {
            let offset = machine.registers()[A2].to_u64() as usize;
            let index = machine.registers()[A3].to_u64() as usize;
            let source = machine.registers()[A4]
                .to_u64()
                .try_into()
                .expect("parse source");
            f(buf, impls, offset, index, source)
        })
    }

    fn load_oisf<F, V>(&self, machine: &mut M, f: F) -> Result<(), VMError>
    where
        F: Fn(&mut [u8], &S, usize, usize, Source, V) -> IoResult,
        V: TryFrom<u64>,
        <V as TryFrom<u64>>::Error: core::fmt::Debug,
    {
        self.load_data(machine, |buf, impls, machine| {
            let offset = machine.registers()[A2].to_u64() as usize;
            let index = machine.registers()[A3].to_u64() as usize;
            let source = machine.registers()[A4]
                .to_u64()
                .try_into()
                .expect("parse source");
            let field = machine.registers()[A5]
                .to_u64()
                .try_into()
                .expect("parse field");
            f(buf, impls, offset, index, source, field)
        })
    }
}

/// Note that SyscallImplsSynchronousWrapper assumes synchronous operations for now,
/// this means all syscalls, including spawn / exec / read / write are expected
/// to terminate in a single method call, there is no scheduler-like message box
/// used.
impl<S, M> Syscalls<M> for SyscallImplsSynchronousWrapper<S, M>
where
    S: SyscallImpls + Send,
    M: SupportMachine + Send,
{
    fn initialize(&mut self, _machine: &mut M) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut M) -> Result<bool, VMError> {
        let Ok(code): Result<SyscallCode, _> = machine.registers()[A7].to_u64().try_into() else {
            return Ok(false);
        };
        match code {
            SyscallCode::LoadTransaction => self.load_o(machine, |buf, impls, offset| {
                impls.load_transaction(buf, offset)
            })?,
            SyscallCode::LoadTxHash => self.load_o(machine, |buf, impls, offset| {
                impls.load_tx_hash(buf, offset)
            })?,
            SyscallCode::LoadScript => {
                self.load_o(machine, |buf, impls, offset| impls.load_script(buf, offset))?
            }
            SyscallCode::LoadScriptHash => self.load_o(machine, |buf, impls, offset| {
                impls.load_script_hash(buf, offset)
            })?,
            SyscallCode::LoadCell => self
                .load_ois(machine, |buf, impls, offset, index, source| {
                    impls.load_cell(buf, offset, index, source)
                })?,
            SyscallCode::LoadHeader => self
                .load_ois(machine, |buf, impls, offset, index, source| {
                    impls.load_header(buf, offset, index, source)
                })?,
            SyscallCode::LoadInput => self
                .load_ois(machine, |buf, impls, offset, index, source| {
                    impls.load_input(buf, offset, index, source)
                })?,
            SyscallCode::LoadWitness => self
                .load_ois(machine, |buf, impls, offset, index, source| {
                    impls.load_witness(buf, offset, index, source)
                })?,
            SyscallCode::LoadCellByField => {
                self.load_oisf(machine, |buf, impls, offset, index, source, field| {
                    impls.load_cell_by_field(buf, offset, index, source, field)
                })?
            }
            SyscallCode::LoadHeaderByField => {
                self.load_oisf(machine, |buf, impls, offset, index, source, field| {
                    impls.load_header_by_field(buf, offset, index, source, field)
                })?
            }
            SyscallCode::LoadInputByField => {
                self.load_oisf(machine, |buf, impls, offset, index, source, field| {
                    impls.load_input_by_field(buf, offset, index, source, field)
                })?
            }
            SyscallCode::LoadCellDataAsCode => {
                let addr = machine.registers()[A0].to_u64() as *mut u8;
                let memory_size = machine.registers()[A1].to_u64() as usize;
                let content_offset = machine.registers()[A2].to_u64() as usize;
                let content_size = machine.registers()[A3].to_u64() as usize;
                let index = machine.registers()[A4].to_u64() as usize;
                let source = machine.registers()[A5]
                    .to_u64()
                    .try_into()
                    .expect("parse source");
                let result = self.impls.load_cell_code(
                    addr,
                    memory_size,
                    content_offset,
                    content_size,
                    index,
                    source,
                );
                self.set_return(result, machine);
            }
            SyscallCode::LoadCellData => {
                self.load_ois(machine, |buf, impls, offset, index, source| {
                    impls.load_cell_data_raw(buf.as_mut_ptr(), buf.len(), offset, index, source)
                })?
            }
            SyscallCode::LoadBlockExtension => {
                self.load_ois(machine, |buf, impls, offset, index, source| {
                    impls.load_block_extension(buf, offset, index, source)
                })?
            }
            SyscallCode::VmVersion => {
                let version = self.impls.vm_version();
                machine.set_register(A0, M::REG::from_u64(version));
            }
            SyscallCode::CurrentCycles => {
                let cycles = self.impls.current_cycles();
                machine.set_register(A0, M::REG::from_u64(cycles));
            }
            SyscallCode::Exec => {
                let index = machine.registers()[A0].to_u64() as usize;
                let source = machine.registers()[A1]
                    .to_u64()
                    .try_into()
                    .expect("parse source");
                let place = machine.registers()[A2].to_u64() as usize;
                let bounds = machine.registers()[A3].to_u64() as usize;
                let argc = machine.registers()[A4].to_u64();
                let argv_ptr = machine.registers()[A5].to_u64();

                let mut argv = vec![];
                for i in 0..argc {
                    let addr = machine
                        .memory_mut()
                        .load64(&M::REG::from_u64(argv_ptr + i * 8))?;
                    argv.push(
                        CString::new(load_c_string_byte_by_byte(machine.memory_mut(), &addr)?)
                            .expect("create cstring"),
                    );
                }
                let argv_refs: Vec<_> = argv.iter().map(|arg| arg.as_c_str()).collect();

                let result = self.impls.exec(index, source, place, bounds, &argv_refs);
                // In case of success, a new binary will be loaded
                if result.is_err() {
                    self.set_return(result, machine);
                }
            }
            SyscallCode::Spawn => {
                let index = machine.registers()[A0].to_u64() as usize;
                let source = machine.registers()[A1]
                    .to_u64()
                    .try_into()
                    .expect("parse source");
                let place = machine.registers()[A2].to_u64() as usize;
                let bounds = machine.registers()[A3].to_u64() as usize;
                let spgs_addr = machine.registers()[A4].to_u64();
                let argc_addr = spgs_addr;
                let argc = machine
                    .memory_mut()
                    .load64(&M::REG::from_u64(argc_addr))?
                    .to_u64();
                let argv_addr = spgs_addr.wrapping_add(8);
                let argv_ptr = machine
                    .memory_mut()
                    .load64(&M::REG::from_u64(argv_addr))?
                    .to_u64();

                let mut argv = vec![];
                for i in 0..argc {
                    let addr = machine
                        .memory_mut()
                        .load64(&M::REG::from_u64(argv_ptr + i * 8))?;
                    argv.push(
                        CString::new(load_c_string_byte_by_byte(machine.memory_mut(), &addr)?)
                            .expect("create cstring"),
                    );
                }
                let argv_refs: Vec<_> = argv.iter().map(|arg| arg.as_c_str()).collect();

                let process_id_addr_addr = spgs_addr.wrapping_add(16);
                let process_id_addr = machine
                    .memory_mut()
                    .load64(&M::REG::from_u64(process_id_addr_addr))?;
                let fds_addr_addr = spgs_addr.wrapping_add(24);
                let mut fds_addr = machine
                    .memory_mut()
                    .load64(&M::REG::from_u64(fds_addr_addr))?
                    .to_u64();
                let mut fds = vec![];
                if fds_addr != 0 {
                    loop {
                        let fd = machine
                            .memory_mut()
                            .load64(&M::REG::from_u64(fds_addr))?
                            .to_u64();
                        if fd == 0 {
                            break;
                        }
                        fds.push(fd);
                        fds_addr += 8;
                    }
                }

                // For now we assume synchronous operation
                let result = self
                    .impls
                    .spawn(index, source, place, bounds, &argv_refs, &fds);
                if let Ok(process_id) = result {
                    machine
                        .memory_mut()
                        .store64(&process_id_addr, &M::REG::from_u64(process_id))?;
                }
                self.set_return(result, machine);
            }
            SyscallCode::Wait => {
                let target_id = machine.registers()[A0].to_u64();

                let result = self.impls.wait(target_id);
                if let Ok(exit_code) = result {
                    let exit_code_addr = machine.registers()[A1].clone();
                    machine
                        .memory_mut()
                        .store64(&exit_code_addr, &M::REG::from_i8(exit_code))?;
                }
                self.set_return(result, machine);
            }
            SyscallCode::ProcessId => {
                let id = self.impls.process_id();
                machine.set_register(A0, M::REG::from_u64(id));
            }
            SyscallCode::Pipe => {
                let result = self.impls.pipe();
                if let Ok((a, b)) = result {
                    let fd1_addr = machine.registers()[A0].clone();
                    let fd2_addr = fd1_addr.overflowing_add(&M::REG::from_u64(8));
                    machine
                        .memory_mut()
                        .store64(&fd1_addr, &M::REG::from_u64(a))?;
                    machine
                        .memory_mut()
                        .store64(&fd2_addr, &M::REG::from_u64(b))?;
                }
                self.set_return(result, machine);
            }
            SyscallCode::Write => {
                let fd = machine.registers()[A0].to_u64();
                let buffer_addr = machine.registers()[A1].to_u64();
                let length_addr = machine.registers()[A2].clone();
                let length = machine.memory_mut().load64(&length_addr)?.to_u64();

                let buffer = machine.memory_mut().load_bytes(buffer_addr, length)?;
                let result = self.impls.write(fd, &buffer);

                if let Ok(wrote) = result {
                    machine
                        .memory_mut()
                        .store64(&length_addr, &M::REG::from_u64(wrote as u64))?;
                }
                self.set_return(result, machine);
            }
            SyscallCode::Read => {
                let fd = machine.registers()[A0].to_u64();
                let buffer_addr = machine.registers()[A1].to_u64();
                let length_addr = machine.registers()[A2].clone();
                let length = machine.memory_mut().load64(&length_addr)?.to_u64() as usize;

                let mut buffer = vec![0u8; length];
                let result = self.impls.read(fd, &mut buffer);

                if let Ok(read) = result {
                    machine
                        .memory_mut()
                        .store64(&length_addr, &M::REG::from_u64(read as u64))?;
                    machine
                        .memory_mut()
                        .store_bytes(buffer_addr, &buffer[0..read])?;
                }
                self.set_return(result, machine);
            }
            SyscallCode::InheritedFd => {
                let buffer_addr = machine.registers()[A0].clone();
                let length_addr = machine.registers()[A1].clone();
                let length = machine.memory_mut().load64(&length_addr)?.to_u64() as usize;

                let mut fds = vec![0; length];
                let result = self.impls.inherited_fds(&mut fds);
                if let Ok(wrote_length) = result {
                    for i in 0..wrote_length {
                        machine.memory_mut().store64(
                            &buffer_addr.overflowing_add(&M::REG::from_u64(i as u64 * 8)),
                            &M::REG::from_u64(fds[i]),
                        )?;
                    }
                }
                self.set_return(result, machine);
            }
            SyscallCode::Close => {
                let fd = machine.registers()[A0].to_u64();

                let result = self.impls.close(fd);
                self.set_return(result, machine);
            }
            SyscallCode::Debug => {
                let addr = machine.registers()[A0].clone();
                let b = load_c_string_byte_by_byte(machine.memory_mut(), &addr)?;
                let s = String::from_utf8(b.to_vec())
                    .map_err(|e| VMError::External(format!("String from buffer {e:?}")))?;
                self.impls.debug(&s);
            }
        }
        Ok(true)
    }
}
