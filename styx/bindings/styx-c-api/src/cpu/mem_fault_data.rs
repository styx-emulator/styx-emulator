// SPDX-License-Identifier: BSD-2-Clause
use std::marker::PhantomData;

use crate::data::ArrayPtr;

/// memory fault information
///
/// NULL if the fault is a read fault
/// Non-Null uint8_t* if the fault is a write fault
#[repr(transparent)]
pub struct MemFaultData<'a>(ArrayPtr<u8>, PhantomData<fn(&'a ())>);

impl<'a> From<styx_emulator::hooks::MemFaultData<'a>> for MemFaultData<'a> {
    #[inline]
    fn from(value: styx_emulator::hooks::MemFaultData<'a>) -> Self {
        Self(
            match value {
                styx_emulator::hooks::MemFaultData::Read => ArrayPtr::null(),
                styx_emulator::hooks::MemFaultData::Write { data } => ArrayPtr::new(data.as_ptr()),
            },
            PhantomData,
        )
    }
}
