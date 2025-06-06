pub mod stub;
pub mod trait_wrapper;

use crate::types::{CellField, Error, HeaderField, InputField, IoResult, Source};
use ckb_std::{ckb_constants as sc, error::SysError};

impl From<IoResult> for Result<usize, SysError> {
    fn from(result: IoResult) -> Result<usize, SysError> {
        match result {
            IoResult::FullyLoaded(l) => Ok(l),
            IoResult::PartialLoaded { available, .. } => Err(SysError::LengthNotEnough(available)),
            IoResult::Error(e) => Err(e.into()),
        }
    }
}

impl From<Error> for SysError {
    fn from(e: Error) -> SysError {
        match e {
            Error::IndexOutOfBound => SysError::IndexOutOfBound,
            Error::ItemMissing => SysError::ItemMissing,
            Error::SliceOutOfBound => SysError::Encoding,
            Error::WrongFormat => SysError::Unknown(4),
            Error::WaitFailure => SysError::WaitFailure,
            Error::InvalidFd => SysError::InvalidFd,
            Error::OtherEndClosed => SysError::OtherEndClosed,
            Error::MaxVmsSpawned => SysError::MaxVmsSpawned,
            Error::MaxFdsCreated => SysError::MaxFdsCreated,
            Error::Other(e) => SysError::Unknown(e),
        }
    }
}

impl TryFrom<SysError> for Error {
    type Error = &'static str;

    fn try_from(e: SysError) -> Result<Self, Self::Error> {
        match e {
            SysError::IndexOutOfBound => Ok(Error::IndexOutOfBound),
            SysError::ItemMissing => Ok(Error::ItemMissing),
            SysError::LengthNotEnough(_) => Err("no matching error!"),
            SysError::Encoding => Ok(Error::SliceOutOfBound),
            SysError::Unknown(4) => Ok(Error::WrongFormat),
            SysError::WaitFailure => Ok(Error::WaitFailure),
            SysError::InvalidFd => Ok(Error::InvalidFd),
            SysError::OtherEndClosed => Ok(Error::OtherEndClosed),
            SysError::MaxVmsSpawned => Ok(Error::MaxVmsSpawned),
            SysError::MaxFdsCreated => Ok(Error::MaxFdsCreated),
            SysError::Unknown(e) => Ok(Error::Other(e)),
        }
    }
}

impl From<Source> for sc::Source {
    fn from(s: Source) -> sc::Source {
        match s {
            Source::Input => sc::Source::Input,
            Source::Output => sc::Source::Output,
            Source::CellDep => sc::Source::CellDep,
            Source::HeaderDep => sc::Source::HeaderDep,
            Source::GroupInput => sc::Source::GroupInput,
            Source::GroupOutput => sc::Source::GroupOutput,
        }
    }
}

impl From<sc::Source> for Source {
    fn from(s: sc::Source) -> Source {
        match s {
            sc::Source::Input => Source::Input,
            sc::Source::Output => Source::Output,
            sc::Source::CellDep => Source::CellDep,
            sc::Source::HeaderDep => Source::HeaderDep,
            sc::Source::GroupInput => Source::GroupInput,
            sc::Source::GroupOutput => Source::GroupOutput,
        }
    }
}

impl From<CellField> for sc::CellField {
    fn from(f: CellField) -> sc::CellField {
        match f {
            CellField::Capacity => sc::CellField::Capacity,
            CellField::DataHash => sc::CellField::DataHash,
            CellField::Lock => sc::CellField::Lock,
            CellField::LockHash => sc::CellField::LockHash,
            CellField::Type => sc::CellField::Type,
            CellField::TypeHash => sc::CellField::TypeHash,
            CellField::OccupiedCapacity => sc::CellField::OccupiedCapacity,
        }
    }
}

impl From<sc::CellField> for CellField {
    fn from(f: sc::CellField) -> CellField {
        match f {
            sc::CellField::Capacity => CellField::Capacity,
            sc::CellField::DataHash => CellField::DataHash,
            sc::CellField::Lock => CellField::Lock,
            sc::CellField::LockHash => CellField::LockHash,
            sc::CellField::Type => CellField::Type,
            sc::CellField::TypeHash => CellField::TypeHash,
            sc::CellField::OccupiedCapacity => CellField::OccupiedCapacity,
        }
    }
}

impl From<HeaderField> for sc::HeaderField {
    fn from(f: HeaderField) -> sc::HeaderField {
        match f {
            HeaderField::EpochNumber => sc::HeaderField::EpochNumber,
            HeaderField::EpochStartBlockNumber => sc::HeaderField::EpochStartBlockNumber,
            HeaderField::EpochLength => sc::HeaderField::EpochLength,
        }
    }
}

impl From<sc::HeaderField> for HeaderField {
    fn from(f: sc::HeaderField) -> HeaderField {
        match f {
            sc::HeaderField::EpochNumber => HeaderField::EpochNumber,
            sc::HeaderField::EpochStartBlockNumber => HeaderField::EpochStartBlockNumber,
            sc::HeaderField::EpochLength => HeaderField::EpochLength,
        }
    }
}

impl From<InputField> for sc::InputField {
    fn from(f: InputField) -> sc::InputField {
        match f {
            InputField::OutPoint => sc::InputField::OutPoint,
            InputField::Since => sc::InputField::Since,
        }
    }
}

impl From<sc::InputField> for InputField {
    fn from(f: sc::InputField) -> InputField {
        match f {
            sc::InputField::OutPoint => InputField::OutPoint,
            sc::InputField::Since => InputField::Since,
        }
    }
}
