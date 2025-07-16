// SPDX-License-Identifier: BSD-2-Clause
use crate::styx_hooks::StyxHookError;
use crate::styx_memory::StyxMemoryError;
use styx_cpu_type::arch::{backends::ArchRegister, Arch, RegisterValue};
use styx_cpu_type::TargetExitReason;
use thiserror::Error;
use unicorn_engine::uc_error;

#[derive(Error, Debug)]
pub enum StyxCpuSnapshotError {
    #[error("Saved context is empty.")]
    EmptyContext,
    #[error("CPU is not stopped.")]
    NotStopped,
}

#[derive(Error, Debug)]
pub enum StyxCpuBuilderError {
    #[error("Invalid architecture `{0}` for selected backend")]
    BadArchitecture(String),
    #[error("Missing an `Arch`")]
    MissingArch,
    #[error("Missing an `ArchitectureVariant`")]
    MissingArchVariant,
    #[error("Missing a `Backend`")]
    MissingBackend,
    #[error("Unable to instantiate backend: `{0}`")]
    UnableInstantiate(String),
}

#[derive(Error, Debug)]
pub enum StyxCpuBackendError {
    #[error("Error while building backend: `{0}`")]
    BackendBuilder(StyxCpuBuilderError),
    #[error("Return from C-FFI with an error::OK status")]
    ErrorOkay(String),
    #[error("FFI call failed: `{0}`")]
    FFIFailure(String),
    #[error("Error: {0}")]
    GenericError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Hook error")]
    HookError(StyxHookError),
    #[error("Action is invalid for architecture: {0}")]
    InvalidForArchitecture(Arch),
    #[error("Register `{0}` is not available on this target")]
    InvalidPlatformRegister(ArchRegister),
    #[error("Register `{0}` does not fit in size `{1}`")]
    RegisterDoesNotFit(ArchRegister, String),
    #[error("RegisterValue `{0}` is not type `{1}`")]
    RegisterValueTypeCast(RegisterValue, &'static str),
    #[error("Snapshot failed.")]
    SnapshotError(StyxCpuSnapshotError),
    #[error("Memory error")]
    StyxMemoryError(StyxMemoryError),
    #[error("Target exited due to: `{0}`")]
    TargetExitReason(TargetExitReason),
    #[error("Target is not running")]
    TargetNotRunning,
}

impl From<StyxCpuSnapshotError> for StyxCpuBackendError {
    fn from(value: StyxCpuSnapshotError) -> Self {
        StyxCpuBackendError::SnapshotError(value)
    }
}

impl From<StyxMemoryError> for StyxCpuBackendError {
    fn from(value: StyxMemoryError) -> Self {
        match value {
            StyxMemoryError::HookError(err) => StyxCpuBackendError::HookError(err),
            _ => StyxCpuBackendError::StyxMemoryError(value),
        }
    }
}

impl From<StyxCpuBuilderError> for StyxCpuBackendError {
    fn from(value: StyxCpuBuilderError) -> Self {
        Self::BackendBuilder(value)
    }
}

impl From<RegisterValue> for StyxCpuBackendError {
    fn from(value: RegisterValue) -> Self {
        Self::RegisterValueTypeCast(value, "")
    }
}

impl From<StyxHookError> for StyxCpuBackendError {
    fn from(value: StyxHookError) -> Self {
        StyxCpuBackendError::HookError(value)
    }
}

//
// unicorn compat
//

impl From<uc_error> for StyxCpuBackendError {
    fn from(value: uc_error) -> Self {
        // make an into all the fun things
        // need to go back through the api and add other checks as well
        match value {
            uc_error::EXCEPTION => StyxCpuBackendError::FFIFailure("Generic Exception".into()),
            uc_error::ARG => StyxCpuBackendError::FFIFailure("Bad Arguments".into()),
            uc_error::OK => {
                StyxCpuBackendError::ErrorOkay("Error state from unicorn passed OK".into())
            }
            _ => StyxCpuBackendError::FFIFailure(format!("Unicorn Error: {value:?}")),
        }
    }
}
