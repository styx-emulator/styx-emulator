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
#[doc = "Register `globgrp_ghwcfg1` reader"]
pub type R = crate::R<GlobgrpGhwcfg1Spec>;
#[doc = "Register `globgrp_ghwcfg1` writer"]
pub type W = crate::W<GlobgrpGhwcfg1Spec>;
#[doc = "This 32-bit field uses two bits per endpoint to determine the endpoint direction. Endpoint -Bits \\[31:30\\]: Endpoint 15 direction -Bits \\[29:28\\]: Endpoint 14 direction ... -Bits \\[3:2\\]: Endpoint 1 direction -Bits\\[1:0\\]: Endpoint 0 direction (always BIDIR)\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Ghwcfg1 {
    #[doc = "0: `0`"]
    Bdir = 0,
    #[doc = "1: `1`"]
    Inendpt = 1,
    #[doc = "2: `10`"]
    Outendpt = 2,
}
impl From<Ghwcfg1> for u32 {
    #[inline(always)]
    fn from(variant: Ghwcfg1) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Ghwcfg1 {
    type Ux = u32;
}
#[doc = "Field `ghwcfg1` reader - This 32-bit field uses two bits per endpoint to determine the endpoint direction. Endpoint -Bits \\[31:30\\]: Endpoint 15 direction -Bits \\[29:28\\]: Endpoint 14 direction ... -Bits \\[3:2\\]: Endpoint 1 direction -Bits\\[1:0\\]: Endpoint 0 direction (always BIDIR)"]
pub type Ghwcfg1R = crate::FieldReader<Ghwcfg1>;
impl Ghwcfg1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Option<Ghwcfg1> {
        match self.bits {
            0 => Some(Ghwcfg1::Bdir),
            1 => Some(Ghwcfg1::Inendpt),
            2 => Some(Ghwcfg1::Outendpt),
            _ => None,
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_bdir(&self) -> bool {
        *self == Ghwcfg1::Bdir
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_inendpt(&self) -> bool {
        *self == Ghwcfg1::Inendpt
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_outendpt(&self) -> bool {
        *self == Ghwcfg1::Outendpt
    }
}
#[doc = "Field `ghwcfg1` writer - This 32-bit field uses two bits per endpoint to determine the endpoint direction. Endpoint -Bits \\[31:30\\]: Endpoint 15 direction -Bits \\[29:28\\]: Endpoint 14 direction ... -Bits \\[3:2\\]: Endpoint 1 direction -Bits\\[1:0\\]: Endpoint 0 direction (always BIDIR)"]
pub type Ghwcfg1W<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This 32-bit field uses two bits per endpoint to determine the endpoint direction. Endpoint -Bits \\[31:30\\]: Endpoint 15 direction -Bits \\[29:28\\]: Endpoint 14 direction ... -Bits \\[3:2\\]: Endpoint 1 direction -Bits\\[1:0\\]: Endpoint 0 direction (always BIDIR)"]
    #[inline(always)]
    pub fn ghwcfg1(&self) -> Ghwcfg1R {
        Ghwcfg1R::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This 32-bit field uses two bits per endpoint to determine the endpoint direction. Endpoint -Bits \\[31:30\\]: Endpoint 15 direction -Bits \\[29:28\\]: Endpoint 14 direction ... -Bits \\[3:2\\]: Endpoint 1 direction -Bits\\[1:0\\]: Endpoint 0 direction (always BIDIR)"]
    #[inline(always)]
    #[must_use]
    pub fn ghwcfg1(&mut self) -> Ghwcfg1W<GlobgrpGhwcfg1Spec> {
        Ghwcfg1W::new(self, 0)
    }
}
#[doc = "This register contains the logical endpoint direction(s).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg1::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct GlobgrpGhwcfg1Spec;
impl crate::RegisterSpec for GlobgrpGhwcfg1Spec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`globgrp_ghwcfg1::R`](R) reader structure"]
impl crate::Readable for GlobgrpGhwcfg1Spec {}
#[doc = "`reset()` method sets globgrp_ghwcfg1 to value 0"]
impl crate::Resettable for GlobgrpGhwcfg1Spec {
    const RESET_VALUE: u32 = 0;
}
