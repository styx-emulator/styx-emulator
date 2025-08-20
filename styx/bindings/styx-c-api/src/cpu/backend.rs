// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::prelude::Backend as StyxRustBackend;

/// All of the supported emulator backends
#[repr(C)]
pub enum StyxBackend {
    #[cfg(feature = "unicorn-backend")]
    /// A backend that uses Unicorn to emulate the system
    Unicorn,
    /// A backend which uses PCode to emulate the system
    Pcode,
}

impl From<StyxBackend> for StyxRustBackend {
    fn from(value: StyxBackend) -> Self {
        match value {
            StyxBackend::Pcode => StyxRustBackend::Pcode,
            #[cfg(feature = "unicorn-backend")]
            StyxBackend::Unicorn => StyxRustBackend::Unicorn,
        }
    }
}
