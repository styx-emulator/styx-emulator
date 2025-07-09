// SPDX-License-Identifier: BSD-2-Clause
use crate::styx_cpu::StyxCpuBackendError;
use crate::StyxMemoryError;
use crate::UnknownError;
use goblin::error::Error as GoblinError;
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum StyxLoaderError {
    #[error("CpuEngine error: `{0}`")]
    CpuEngineError(StyxCpuBackendError),
    #[error("Error with firmware file `{0}`")]
    FileError(io::Error),
    #[error("Firmware file too big `{0}` > `{1}`")]
    FirmwareTooBig(u64, u64),
    #[error("Bad hint type for var: `{0}`, should be: `{1}`")]
    HintType(&'static str, &'static str),
    #[error("LoadFirmwareError: `{0}`")]
    LoadFirmwareError(String),
    #[error("Loader backend issues: `{0}`")]
    LoaderBackend(Box<dyn std::error::Error + Send + Sync>),
    #[error("Malformed input file: `{0}`")]
    MalformedInput(String),
    #[error("Error constructing MemoryRegion: `{0}`")]
    MemoryRegion(StyxMemoryError),
    #[error("Hint missing required information: `{0}`")]
    MissingHintInfo(String),
    #[error(transparent)]
    Unknown(#[from] UnknownError),
}

impl From<std::io::Error> for StyxLoaderError {
    fn from(value: std::io::Error) -> Self {
        StyxLoaderError::FileError(value)
    }
}

impl From<StyxCpuBackendError> for StyxLoaderError {
    fn from(value: StyxCpuBackendError) -> Self {
        StyxLoaderError::CpuEngineError(value)
    }
}

impl From<StyxMemoryError> for StyxLoaderError {
    fn from(value: StyxMemoryError) -> Self {
        StyxLoaderError::MemoryRegion(value)
    }
}

impl From<GoblinError> for StyxLoaderError {
    fn from(value: GoblinError) -> Self {
        match value {
            GoblinError::Malformed(error_text) => Self::MalformedInput(error_text),
            GoblinError::BadMagic(magic_value) => {
                Self::MalformedInput(format!("Bad file magic: {:X}", magic_value))
            }
            scroll_error @ GoblinError::Scroll(_) => Self::LoaderBackend(Box::new(scroll_error)),
            GoblinError::IO(io_error) => io_error.into(),
            GoblinError::BufferTooShort(n, msg) => {
                Self::MalformedInput(format!("Buffer too short for `{:X}`: `{}`", n, msg))
            }
            _ => unreachable!("Goblin added a new error"),
        }
    }
}
