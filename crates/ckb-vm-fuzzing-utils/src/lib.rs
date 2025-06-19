#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

use alloc::{ffi::CString, vec::Vec};
use ckb_std::{
    ckb_constants::Source,
    syscalls::traits::{Error, IoResult, SyscallImpls},
};
use ckb_vm::{
    Error as VMError, Memory, Register, SupportMachine, Syscalls,
    memory::load_c_string_byte_by_byte,
    registers::{A0, A1, A2, A3, A4, A5, A7},
};
use core::ffi::CStr;
use core::marker::PhantomData;
use core::pin::Pin;
use int_enum::IntEnum;

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
pub enum SyscallCode {
    LoadTransaction = 2051,
    LoadScript = 2052,
    LoadTxHash = 2061,
    LoadScriptHash = 2062,
    LoadCell = 2071,
    LoadHeader = 2072,
    LoadInput = 2073,
    LoadWitness = 2074,
    LoadCellByField = 2081,
    LoadHeaderByField = 2082,
    LoadInputByField = 2083,
    LoadCellDataAsCode = 2091,
    LoadCellData = 2092,
    LoadBlockExtension = 2104,
    VmVersion = 2041,
    CurrentCycles = 2042,
    Exec = 2043,
    Spawn = 2601,
    Wait = 2602,
    ProcessId = 2603,
    Pipe = 2604,
    Write = 2605,
    Read = 2606,
    InheritedFd = 2607,
    Close = 2608,
    Debug = 2177,
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
                    impls.load_cell_data(buf, offset, index, source)
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
                    for (i, fd) in fds.iter().enumerate().take(wrote_length) {
                        machine.memory_mut().store64(
                            &buffer_addr.overflowing_add(&M::REG::from_u64(i as u64 * 8)),
                            &M::REG::from_u64(*fd),
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
                let s = unsafe { CStr::from_ptr(b.as_ptr() as *const _) };
                self.impls.debug(s);
            }
        }
        Ok(true)
    }
}

#[cfg(feature = "std")]
pub fn entry<S, F>(impls: S, f: F, argv: &'static [ckb_std::env::Arg]) -> i8
where
    S: SyscallImpls + 'static,
    F: Fn() -> i8 + std::panic::UnwindSafe,
{
    let impls = Box::new(impls);
    unsafe { ckb_std::env::set_argv(argv) };
    ckb_std::syscalls::init(impls);

    match std::panic::catch_unwind(f) {
        Ok(code) => code,
        Err(e) => {
            let mut code = None;
            if let Some(s) = e.downcast_ref::<&str>() {
                code = parse_panic_for_exit_code(s);
            } else if let Some(s) = e.downcast_ref::<String>() {
                code = parse_panic_for_exit_code(s);
            }

            if let Some(exit_code) = code {
                exit_code
            } else {
                std::panic::resume_unwind(e)
            }
        }
    }
}

pub fn exit_with_panic(code: i8) -> ! {
    panic!("@@@@CKB@@@@FUZING@@@@EXIT@@@@{}@@@@", code);
}

pub fn parse_panic_for_exit_code(s: &str) -> Option<i8> {
    let re = regex::Regex::new(r"@@@@CKB@@@@FUZING@@@@EXIT@@@@([0-9]+)@@@@").unwrap();
    if let Some(caps) = re.captures(s) {
        if let Some(m) = caps.get(1) {
            return m.as_str().parse::<i8>().ok();
        }
    }
    None
}

pub fn flatten_args(args: &[Vec<u8>]) -> (usize, Pin<Box<[u8]>>) {
    let mut total_length = (args.len() + 1) * 8;
    for arg in args {
        let current_len = if arg.last().map(|b| *b == 0).unwrap_or(false) {
            arg.len()
        } else {
            arg.len() + 1
        };
        let rounded_len = current_len.div_ceil(8) * 8;

        total_length += rounded_len;
    }

    let mut buf = vec![0u8; total_length];
    let mut offsets = (args.len() + 1) * 8;
    for (i, arg) in args.iter().enumerate() {
        let ptr = buf[offsets..offsets + arg.len()].as_ptr() as u64;
        unsafe { (buf[i * 8..i * 8 + 8].as_mut_ptr() as *mut u64).write(ptr) };
        buf[offsets..offsets + arg.len()].copy_from_slice(arg);

        let current_len = if arg.last().map(|b| *b == 0).unwrap_or(false) {
            arg.len()
        } else {
            arg.len() + 1
        };
        let rounded_len = current_len.div_ceil(8) * 8;
        offsets += rounded_len;
    }

    (args.len(), Pin::new(buf.into()))
}
