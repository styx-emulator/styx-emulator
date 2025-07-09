// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::prelude as styx;

#[repr(C)]
pub enum TargetExitReason {
    /// Generic bus error for the target system, most likely
    /// going to occur if hardware is attempted to be put into
    /// an invalid state
    BusError,
    /// Generic double fault, the interrupt / exception handed
    /// faulted, on the target platform a double fault is fatal.
    /// The string should detail the 2-level faults that occurred
    DoubleFault,
    /// The initial provided execution timeout window was reached
    ExecutionTimeoutComplete,
    /// Generic fault, the populated string should detail more
    GeneralFault,
    /// Target hardware requested power off.
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
    InvalidStateFromHost,
    /// The target has attempted to set an invalid state in the
    /// target platform. The string should detail what action caused
    /// this to occur
    InvalidStateFromTarget,
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
    /// occurred
    TripleFault,
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

impl From<styx::TargetExitReason> for TargetExitReason {
    fn from(value: styx::TargetExitReason) -> Self {
        match value {
            styx::TargetExitReason::BusError => TargetExitReason::BusError,
            styx::TargetExitReason::DoubleFault(_) => TargetExitReason::DoubleFault,
            styx::TargetExitReason::ExecutionTimeoutComplete => {
                TargetExitReason::ExecutionTimeoutComplete
            }
            styx::TargetExitReason::GeneralFault(_) => TargetExitReason::GeneralFault,
            styx::TargetExitReason::HardwarePowerOff => TargetExitReason::HardwarePowerOff,
            styx::TargetExitReason::HardwareReset => TargetExitReason::HardwareReset,
            styx::TargetExitReason::HostStopRequest => TargetExitReason::HostStopRequest,
            styx::TargetExitReason::IllegalInstruction => TargetExitReason::IllegalInstruction,
            styx::TargetExitReason::InstructionCountComplete => {
                TargetExitReason::InstructionCountComplete
            }
            styx::TargetExitReason::InstructionDecodeError => {
                TargetExitReason::InstructionDecodeError
            }
            styx::TargetExitReason::InvalidMemoryMapping => TargetExitReason::InvalidMemoryMapping,
            styx::TargetExitReason::InvalidStateFromHost(_) => {
                TargetExitReason::InvalidStateFromHost
            }
            styx::TargetExitReason::InvalidStateFromTarget(_) => {
                TargetExitReason::InvalidStateFromTarget
            }
            styx::TargetExitReason::ProtectedMemoryFetch => TargetExitReason::ProtectedMemoryFetch,
            styx::TargetExitReason::ProtectedMemoryRead => TargetExitReason::ProtectedMemoryRead,
            styx::TargetExitReason::ProtectedMemoryWrite => TargetExitReason::ProtectedMemoryWrite,
            styx::TargetExitReason::SoftwarePowerOff => TargetExitReason::SoftwarePowerOff,
            styx::TargetExitReason::SoftwareReset => TargetExitReason::SoftwareReset,
            styx::TargetExitReason::TripleFault(_) => TargetExitReason::TripleFault,
            styx::TargetExitReason::UnalignedMemoryFetch => TargetExitReason::UnalignedMemoryFetch,
            styx::TargetExitReason::UnalignedMemoryRead => TargetExitReason::UnalignedMemoryRead,
            styx::TargetExitReason::UnalignedMemoryWrite => TargetExitReason::UnalignedMemoryWrite,
            styx::TargetExitReason::UnmappedMemoryFetch => TargetExitReason::UnmappedMemoryFetch,
            styx::TargetExitReason::UnmappedMemoryRead => TargetExitReason::UnmappedMemoryRead,
            styx::TargetExitReason::UnmappedMemoryWrite => TargetExitReason::UnmappedMemoryWrite,
        }
    }
}
