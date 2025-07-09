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
use log::info;
use nix::sys::signal::{raise, Signal};
use styx_cpu_type::TargetExitReason;
use tap::Conv;

/// Allows users to determine the behavior of exception handling.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Default)]
pub enum ExceptionBehavior {
    /// Immediately abort the host process
    Panic,
    /// Pause the target, the [crate::executor::Executor] will receive
    /// the exit reason. Useful when you want the [`crate::executor::Executor`]
    /// to be able to keep track of whats going on (eg. gdb)
    Pause,
    /// Have the host process raise a UNIX signal
    /// equivalent to the exception the target encountered
    /// (useful for dumb fuzzers)
    Raise,
    /// Have the target handle the exception via its
    /// own exception handlers, only logging a message
    /// if enabled. After a triple fault execution will halt.
    #[default]
    TargetHandle,
}

/// Subset of [`Exception`].
#[derive(Clone, Copy, Debug)]
pub enum FetchException {
    ProtectedMemoryFetch,
    InvalidInstruction,
    UnmappedMemoryFetch,
}

impl FetchException {
    pub fn exit_reason(self) -> TargetExitReason {
        self.conv::<Exception>().into()
    }
}

impl From<FetchException> for Exception {
    fn from(value: FetchException) -> Self {
        match value {
            FetchException::ProtectedMemoryFetch => Exception::ProtectedMemoryFetch,
            FetchException::InvalidInstruction => Exception::InvalidInstruction,
            FetchException::UnmappedMemoryFetch => Exception::UnmappedMemoryFetch,
        }
    }
}

/// Represents a target agnostic cpu exception.
///
/// Cpu backends can construct this and use [`ExceptionBehavior::handle_exception()`] to determine
/// how to handle an occurred exception.
#[derive(Clone, Copy, Debug)]
pub enum Exception {
    // Read from memory without correct permissions.
    ProtectedMemoryRead,
    // Write to memory without correct permissions.
    ProtectedMemoryWrite,
    // Fetch from memory without correct permissions.
    ProtectedMemoryFetch,
    // Read from unmapped memory.
    UnmappedMemoryRead,
    // Write to unmapped memory.
    UnmappedMemoryWrite,
    // Fetch from unmapped memory.
    UnmappedMemoryFetch,
    /// Target is unable to decode the bytes at `pc`
    IllegalInstruction,
    /// Target attempted to execute an illegal instruction,
    /// this is generally going to occur when non privileged code
    /// attempts to execute a privileged instruction as opposed
    /// to [`Exception::IllegalInstruction`] which occurs
    /// when the bytes at `pc` cannot be decoded into a valid
    /// instruction for the target processor
    InvalidInstruction,
}

impl Exception {
    /// Get the [`TargetExitReason`] if an exception of this type is handled and pauses emulation.
    pub fn exit_reason(self) -> TargetExitReason {
        self.into()
    }
}

impl From<Exception> for TargetExitReason {
    fn from(value: Exception) -> Self {
        match value {
            Exception::ProtectedMemoryRead => TargetExitReason::ProtectedMemoryRead,
            Exception::ProtectedMemoryWrite => TargetExitReason::ProtectedMemoryWrite,
            Exception::ProtectedMemoryFetch => TargetExitReason::ProtectedMemoryFetch,
            Exception::UnmappedMemoryRead => TargetExitReason::UnmappedMemoryRead,
            Exception::UnmappedMemoryWrite => TargetExitReason::UnmappedMemoryWrite,
            Exception::UnmappedMemoryFetch => TargetExitReason::UnmappedMemoryFetch,
            Exception::IllegalInstruction => TargetExitReason::IllegalInstruction,
            Exception::InvalidInstruction => TargetExitReason::InstructionDecodeError,
        }
    }
}

#[derive(Debug, Clone)]
pub enum HandleExceptionAction {
    /// Exception behavior indicates to pause emulation immediately with the given exit reason.
    Pause(TargetExitReason),
    /// Exception behavior indicates to attempt to grpause emulation immediately with the given exit reason.
    TargetHandle(TargetExitReason),
}

impl ExceptionBehavior {
    /// Given the `exception` has occurred, perform the configured exception handling or return an
    /// `action` for the backend to perform.
    ///
    /// This function will panic or raise a signal if the exception handler is configured to do so.
    ///
    /// Otherwise, the backend should deconstruct the [`HandleExceptionAction`] to determine the
    /// exception behavior.
    pub fn handle_exception(self, exception: Exception) -> HandleExceptionAction {
        let exit = exception.into();

        match self {
            ExceptionBehavior::Panic => {
                panic!("exception encountered and exception behavior set to panic. Exception: {exception:?}");
            }
            ExceptionBehavior::Pause => HandleExceptionAction::Pause(exit),
            ExceptionBehavior::Raise => match exception {
                Exception::ProtectedMemoryRead
                | Exception::ProtectedMemoryWrite
                | Exception::ProtectedMemoryFetch => {
                    raise_signal(Signal::SIGSEGV, "protected memory")
                }
                Exception::UnmappedMemoryRead
                | Exception::UnmappedMemoryWrite
                | Exception::UnmappedMemoryFetch => raise_signal(Signal::SIGBUS, "unmapped memory"),
                Exception::InvalidInstruction | Exception::IllegalInstruction => {
                    raise_signal(Signal::SIGILL, "invalid instruction")
                }
            },
            ExceptionBehavior::TargetHandle => HandleExceptionAction::TargetHandle(exit),
        }
    }
}

fn raise_signal(signal: Signal, name: &'static str) -> ! {
    info!("exception occurred and ExceptionBehavior set to raise: raising {name} signal");
    raise(signal).expect("failed to raise signal");
    panic!("signal was caught by exception handler, this should not happen.")
}
