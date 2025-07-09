// SPDX-License-Identifier: BSD-2-Clause
//! Collection of Styx error types and unknown error guidance.
//!
//! Styx errors are designed to be ergonomic for developers to create while
//! maintaining information critical to users that allows them to handle
//! expected failure states. First and foremost, Styx library code should not
//! panic and all errors should be propagated up. "Expected" errors that users
//! may need to handle are implemented in custom Error structs while "unknown"
//! errors indicating a bug or unrecoverable state in Styx code are handled
//! using an [anyhow::Error] aliased to the name [UnknownError].
//!
//! Custom error enums should be used sparingly. The reason being that error
//! enums represent a public api that must be upheld and creates friction for
//! Styx developers trying to maintain that api. If users of a public
//! system/function are likely to use an error state then by all means add it,
//! but err of less custom error enums to maintain and instead use
//! [UnknownError] to propagate errors.
//!
//! ## [thiserror]
//!
//! [thiserror] allows for easy creation of [std::error::Error] types. Check out
//! its documentation or the example below to get familiar.
//!
//! ## [UnknownError]
//!
//! Check out [anyhow]'s documentation for more info.
//!
//! ## Example
//!
//! ```
//! use std::str::FromStr;
//! // included in core prelude:
//! use styx_errors::*;
//! use anyhow::Context;
//!
//! #[derive(thiserror::Error, Debug)]
//! enum ConvertFrobError {
//!     #[error("invalid frob")]
//!     InvalidFrob,
//!     #[error(transparent)]
//!     Unknown(#[from] UnknownError)
//! }
//!
//! fn check_frob() -> Result<(), ConvertFrobError> {
//!     return Ok(());
//! }
//!
//! fn convert_frob() -> Result<(), ConvertFrobError> {
//!     // use ? to early return of the same error type
//!     check_frob()?;
//!
//!     let bar = "10";
//!     // with_context converts to an UnknownError that we can into() (and thus use ?) to ConvertFrobError.
//!     // this also adds a backtrace entry to the error
//!     u8::from_str(bar).with_context(|| "failed to parse bar")?;
//!
//!     let foo = "foo";
//!     // this will error
//!     u8::from_str(foo).with_context(|| "failed to parse foo")?;
//!
//!     Ok(())
//! }
//!
//! let result = convert_frob().with_context(|| "failed to convert frob").err().expect("expected convert_frob to error");
//! let result_text = format!("{:?}", result);
//! let expected_text =
//! r#"failed to convert frob
//!
//! Caused by:
//!     0: failed to parse foo
//!     1: invalid digit found in string"#;
//! assert_eq!(result_text, expected_text);
//! ```

use styx_grpc::ApplicationError;
use styx_processor_type::ProcessorStateError;
use thiserror::Error;
// use thiserror::Error;
extern crate thiserror;

mod error_buffer;
pub mod styx_cpu;
pub mod styx_grpc;
pub mod styx_hooks;
pub mod styx_loader;
pub mod styx_memory;
pub mod styx_processor;

use styx_cpu::{StyxCpuBackendError, StyxCpuBuilderError};
use styx_cpu_type::arch::backends::ArchVariant;
use styx_loader::StyxLoaderError;
use styx_memory::StyxMemoryError;
use styx_processor::ProcessorBuilderError;

pub use anyhow;
pub type UnknownError = anyhow::Error;

pub use error_buffer::ErrorBuffer;

#[derive(Debug, Error)]
pub enum StyxMachineError {
    /// The targeted cpu family does not include the given variant
    #[error("Family Conversion Incompatibility: From: `{0:?}`")]
    FamilyIncompatibility(ArchVariant),
    #[error("Error while loading")]
    LoaderError(#[source] StyxLoaderError),
    #[error("MemoryError: `{0}`")]
    MemoryError(StyxMemoryError),
    /// All machines **must** have an executor plugin
    #[error("No executor plugin")]
    MissingExecutor,
    /// Non fatal plugin runtime error
    #[error("Plugin error: `{0}`")]
    PluginError(String),
    /// Fatal plugin runtime error
    #[error("Plugin fatal error: `{0}`")]
    PluginFatalError(String),
    #[error("Plugin `{0}` failed to initialize")]
    PluginInitFail(String),
    #[error("Processor builder error: `{0}`")]
    ProcessorBuilder(ProcessorBuilderError),
    #[error("Processor is already initialized")]
    ProcessorInitialized,
    #[error("Processor failed to start: `{0}")]
    ProcessorStart(String),
    #[error("ProcessorStateError: `{0}`")]
    ProcessorState(ProcessorStateError),
    #[error("Processor failed to stop: `{0}`")]
    ProcessorStop(String),
    #[error("Cpu backend error: `{0}`")]
    StyxCpuBackendError(StyxCpuBackendError),
    /// All target specific errors get propagated through this variant
    #[error("Target specific error: `{0}`")]
    TargetSpecific(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Unknown(#[from] UnknownError),
}

impl From<StyxCpuBackendError> for StyxMachineError {
    fn from(value: StyxCpuBackendError) -> Self {
        Self::StyxCpuBackendError(value)
    }
}

impl From<StyxCpuBuilderError> for StyxMachineError {
    fn from(value: StyxCpuBuilderError) -> Self {
        Self::StyxCpuBackendError(value.into())
    }
}

impl From<StyxLoaderError> for StyxMachineError {
    fn from(value: StyxLoaderError) -> Self {
        Self::LoaderError(value)
    }
}

impl From<StyxMemoryError> for StyxMachineError {
    fn from(value: StyxMemoryError) -> Self {
        Self::MemoryError(value)
    }
}

impl From<StyxMachineError> for ApplicationError {
    fn from(value: StyxMachineError) -> Self {
        ApplicationError::InitializeEmulationServiceFailed(value.to_string())
    }
}

impl From<ProcessorStateError> for StyxMachineError {
    fn from(value: ProcessorStateError) -> Self {
        Self::ProcessorState(value)
    }
}
