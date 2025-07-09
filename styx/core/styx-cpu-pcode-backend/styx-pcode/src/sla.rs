// SPDX-License-Identifier: BSD-2-Clause
use std::fmt::Debug;

/// Provides raw bytes for a sla architecture definition.
pub trait SlaSpec {
    /// Raw form of the sla specification file..
    fn spec() -> &'static [u8];

    /// File name of the sla
    fn name() -> &'static str;
}

/// Implemented on a sla spec to provide a type to define the user ops for a spec.
pub trait SlaUserOps {
    type UserOps: UserOps;
}

/// User op type, usually an enum with hardcoded indexes.
pub trait UserOps: Debug + Clone + Copy {
    /// Given index of user op as defined in sla.
    fn index(self) -> u64;
}
