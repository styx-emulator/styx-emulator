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
