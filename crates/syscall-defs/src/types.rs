//! This is an experiment to see if we can make current crate free from
//! depending on ckb-std.

use int_enum::IntEnum;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum IoResult {
    FullyLoaded(usize),
    PartialLoaded { loaded: usize, available: usize },
    Error(Error),
}

impl IoResult {
    pub fn to_result(&self) -> Result<(), Error> {
        match self {
            IoResult::FullyLoaded(_) => Ok(()),
            IoResult::PartialLoaded { .. } => Ok(()),
            IoResult::Error(e) => Err(*e),
        }
    }

    pub fn loaded(&self) -> Option<usize> {
        match self {
            IoResult::FullyLoaded(l) => Some(*l),
            IoResult::PartialLoaded { loaded, .. } => Some(*loaded),
            IoResult::Error(_) => None,
        }
    }

    pub fn available(&self) -> Option<usize> {
        match self {
            IoResult::FullyLoaded(l) => Some(*l),
            IoResult::PartialLoaded { available, .. } => Some(*available),
            IoResult::Error(_) => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    IndexOutOfBound,
    ItemMissing,
    SliceOutOfBound,
    WrongFormat,
    WaitFailure,
    InvalidFd,
    OtherEndClosed,
    MaxVmsSpawned,
    MaxFdsCreated,
    Other(u64),
}

impl From<Error> for u64 {
    fn from(e: Error) -> u64 {
        match e {
            Error::IndexOutOfBound => 1,
            Error::ItemMissing => 2,
            Error::SliceOutOfBound => 3,
            Error::WrongFormat => 4,
            Error::WaitFailure => 5,
            Error::InvalidFd => 6,
            Error::OtherEndClosed => 7,
            Error::MaxVmsSpawned => 8,
            Error::MaxFdsCreated => 9,
            Error::Other(e) => e,
        }
    }
}

impl TryFrom<u64> for Error {
    type Error = &'static str;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            0 => Err("Error cannot be zero!"),
            1 => Ok(Error::IndexOutOfBound),
            2 => Ok(Error::ItemMissing),
            3 => Ok(Error::SliceOutOfBound),
            4 => Ok(Error::WrongFormat),
            5 => Ok(Error::WaitFailure),
            6 => Ok(Error::InvalidFd),
            7 => Ok(Error::OtherEndClosed),
            8 => Ok(Error::MaxVmsSpawned),
            9 => Ok(Error::MaxFdsCreated),
            _ => Ok(Error::Other(v)),
        }
    }
}

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

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
pub enum Source {
    Input = 1,
    Output = 2,
    CellDep = 3,
    HeaderDep = 4,
    GroupInput = 0x0100000000000001,
    GroupOutput = 0x0100000000000002,
}

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
pub enum CellField {
    Capacity = 0,
    DataHash = 1,
    Lock = 2,
    LockHash = 3,
    Type = 4,
    TypeHash = 5,
    OccupiedCapacity = 6,
}

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
pub enum HeaderField {
    EpochNumber = 0,
    EpochStartBlockNumber = 1,
    EpochLength = 2,
}

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
pub enum InputField {
    OutPoint = 0,
    Since = 1,
}
