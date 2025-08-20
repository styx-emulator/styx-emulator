// SPDX-License-Identifier: BSD-2-Clause
use derive_more::Display;

pub mod arch;
mod backend_compat;
pub mod macros;

pub use arch::{Arch, ArchEndian};
use thiserror::Error;

/// This Enum is used to select which backend to run emulation on
/// top of.
#[repr(u8)]
#[derive(
    Debug, Display, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default, serde::Deserialize,
)]
#[non_exhaustive]
pub enum Backend {
    #[cfg(feature = "unicorn-backend")]
    Unicorn,
    /// A Pcode Interpreter
    #[default]
    Pcode,
}

#[derive(Error, Debug)]
#[error("backend {0} not supported by this processor")]
pub struct BackendNotSupported(pub Backend);

/// A generalized exit reason for all target code.
#[derive(Debug, Display, Clone, PartialEq, Eq, Hash)]
pub enum TargetExitReason {
    /// Generic bus error for the target system, most likely
    /// going to occur if hardware is attempted to be put into
    /// an invalid state
    BusError,
    /// Generic double fault, the interrupt / exception hander
    /// faulted, on the target platform a double fault is fatal.
    /// The string should detail the 2-level faults that occured
    DoubleFault(String),
    /// The initial provided execution timout window was reached
    ExecutionTimeoutComplete,
    /// Generic fault, the populated string should detail more
    GeneralFault(String),
    /// Target hardware requested poweroff
    HardwarePowerOff,
    /// Target hardware requested restart
    HardwareReset,
    /// Host has issued a `.cpu_stop()` request
    HostStopRequest,
    /// Target attempted to execute an illegal instruction,
    /// this is generally going to occur when non privileged code
    /// attempts to execute a privileged instruction as opposed
    /// to [`TargetExitReason::InstructionDecodeError`] which occurs
    /// when the bytes at `pc` cannot be decoded into a valid
    /// instruction for the target processor
    IllegalInstruction,
    /// The initial provided instruction count was completed
    InstructionCountComplete,
    /// Target is unable to decode the bytes at `pc`
    InstructionDecodeError,
    /// Target encountered an invalid memory mapping
    InvalidMemoryMapping,
    /// The host has attempted to set an invalid state in the target
    /// platform. The string should detail what action caused this
    /// to occur
    InvalidStateFromHost(String),
    /// The target has attempted to set an invalid state in the
    /// target platform. The string should detail what action caused
    /// this to occur
    InvalidStateFromTarget(String),
    /// Target attempted to fetch memory that does not have any permissions
    ProtectedMemoryFetch,
    /// Target attempted to read memory that does not have read permissions
    ProtectedMemoryRead,
    /// Target attempted to write memory that does not have write permissions
    ProtectedMemoryWrite,
    /// Target software requested shutdown
    SoftwarePowerOff,
    /// Target software requested restart
    SoftwareReset,
    /// Generic triple fault, the interrupt / exception handler
    /// faulted 3 deep, on the target platform a triple fault is
    /// fatal. The string should detail the 3-level faults that
    /// occured
    TripleFault(String),
    /// Target performed an unaligned memory fetch
    UnalignedMemoryFetch,
    /// Target performed an unaligned memory read
    UnalignedMemoryRead,
    /// Target performed an unaligned memory read
    UnalignedMemoryWrite,
    /// Target performed an unmapped memory fetch
    UnmappedMemoryFetch,
    /// Target performed an unmapped memory read
    UnmappedMemoryRead,
    /// Target performed an unmapped memory read
    UnmappedMemoryWrite,
}

impl TargetExitReason {
    /// Checks if the exit state is `fatal` or not. If fatal is false
    /// then the target emulation stopped for an external reason, not an
    /// internal exception or interrupt request.
    pub fn fatal(&self) -> bool {
        !matches!(
            self,
            TargetExitReason::InstructionCountComplete
                | TargetExitReason::ExecutionTimeoutComplete
                | TargetExitReason::HostStopRequest
        )
    }

    #[inline]
    pub fn is_stop_request(&self) -> bool {
        matches!(self, TargetExitReason::HostStopRequest)
    }
}

impl From<TargetExitReason> for gdbstub::common::Signal {
    fn from(value: TargetExitReason) -> Self {
        use gdbstub::common::Signal;
        use TargetExitReason as Tgt;

        match value {
            Tgt::BusError => Signal::SIGBUS,
            Tgt::ExecutionTimeoutComplete
            | Tgt::InstructionCountComplete
            | Tgt::HostStopRequest => unreachable!(),
            Tgt::IllegalInstruction | Tgt::InstructionDecodeError => Signal::SIGILL,
            Tgt::UnmappedMemoryFetch
            | Tgt::UnmappedMemoryRead
            | Tgt::UnmappedMemoryWrite
            | Tgt::UnalignedMemoryFetch
            | Tgt::UnalignedMemoryRead
            | Tgt::UnalignedMemoryWrite
            | Tgt::ProtectedMemoryFetch
            | Tgt::ProtectedMemoryRead
            | Tgt::ProtectedMemoryWrite
            | Tgt::InvalidMemoryMapping => Signal::SIGSEGV,
            Tgt::HardwareReset | Tgt::HardwarePowerOff => Signal::SIGKILL,
            Tgt::SoftwarePowerOff | Tgt::SoftwareReset => Signal::SIGSTOP,
            Tgt::GeneralFault(_) => Signal::SIGSTOP,
            Tgt::DoubleFault(_) | Tgt::TripleFault(_) => Signal::SIGKILL,
            Tgt::InvalidStateFromTarget(msg) | Tgt::InvalidStateFromHost(msg) => {
                panic!("Something is very wrong: `{msg}` attempted to be serialized to gdb")
            }
        }
    }
}
