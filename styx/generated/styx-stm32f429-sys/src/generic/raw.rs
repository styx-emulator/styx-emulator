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
use super::{marker, BitM, FieldSpec, RegisterSpec, Unsafe};
pub struct R<REG: RegisterSpec> {
    pub(crate) bits: REG::Ux,
    pub(super) _reg: marker::PhantomData<REG>,
}
pub struct W<REG: RegisterSpec> {
    #[doc = "Writable bits"]
    pub(crate) bits: REG::Ux,
    pub(super) _reg: marker::PhantomData<REG>,
}
pub struct FieldReader<FI = u8>
where
    FI: FieldSpec,
{
    pub(crate) bits: FI::Ux,
    _reg: marker::PhantomData<FI>,
}
impl<FI: FieldSpec> FieldReader<FI> {
    #[doc = " Creates a new instance of the reader."]
    #[inline(always)]
    pub(crate) const fn new(bits: FI::Ux) -> Self {
        Self {
            bits,
            _reg: marker::PhantomData,
        }
    }
}
pub struct BitReader<FI = bool> {
    pub(crate) bits: bool,
    _reg: marker::PhantomData<FI>,
}
impl<FI> BitReader<FI> {
    #[doc = " Creates a new instance of the reader."]
    #[inline(always)]
    pub(crate) const fn new(bits: bool) -> Self {
        Self {
            bits,
            _reg: marker::PhantomData,
        }
    }
}
pub struct FieldWriter<'a, REG, const WI: u8, FI = u8, Safety = Unsafe>
where
    REG: RegisterSpec,
    FI: FieldSpec,
{
    pub(crate) w: &'a mut W<REG>,
    pub(crate) o: u8,
    _field: marker::PhantomData<(FI, Safety)>,
}
impl<'a, REG, const WI: u8, FI, Safety> FieldWriter<'a, REG, WI, FI, Safety>
where
    REG: RegisterSpec,
    FI: FieldSpec,
{
    #[doc = " Creates a new instance of the writer"]
    #[inline(always)]
    pub(crate) fn new(w: &'a mut W<REG>, o: u8) -> Self {
        Self {
            w,
            o,
            _field: marker::PhantomData,
        }
    }
}
pub struct BitWriter<'a, REG, FI = bool, M = BitM>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    pub(crate) w: &'a mut W<REG>,
    pub(crate) o: u8,
    _field: marker::PhantomData<(FI, M)>,
}
impl<'a, REG, FI, M> BitWriter<'a, REG, FI, M>
where
    REG: RegisterSpec,
    bool: From<FI>,
{
    #[doc = " Creates a new instance of the writer"]
    #[inline(always)]
    pub(crate) fn new(w: &'a mut W<REG>, o: u8) -> Self {
        Self {
            w,
            o,
            _field: marker::PhantomData,
        }
    }
}
