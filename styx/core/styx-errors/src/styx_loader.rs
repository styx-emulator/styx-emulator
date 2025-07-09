// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
