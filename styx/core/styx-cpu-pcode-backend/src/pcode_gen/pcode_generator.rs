// SPDX-License-Identifier: BSD-2-Clause
use styx_pcode_translator::SleighTranslateError;
use thiserror::Error;

/// The Ghidra translator does not expose these errors but they are left for a future translator
/// that will (or if ghidra translator is modified to report these statuses).
#[allow(dead_code)]
#[derive(Error, Debug, Clone)]
pub enum GeneratePcodeError {
    #[error("address is not valid")]
    InvalidAddress,
    #[error("invalid instruction found")]
    InvalidInstruction,
    #[error("not enough bytes left in data generator")]
    NotEnoughBytes,
}

impl From<SleighTranslateError> for GeneratePcodeError {
    fn from(value: SleighTranslateError) -> Self {
        match value {
            SleighTranslateError::BadDataError => GeneratePcodeError::InvalidInstruction,
        }
    }
}
