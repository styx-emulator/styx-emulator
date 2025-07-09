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
#[doc = "Register `FS_DSTS` reader"]
pub type R = crate::R<FsDstsSpec>;
#[doc = "Register `FS_DSTS` writer"]
pub type W = crate::W<FsDstsSpec>;
#[doc = "Field `SUSPSTS` reader - Suspend status"]
pub type SuspstsR = crate::BitReader;
#[doc = "Field `SUSPSTS` writer - Suspend status"]
pub type SuspstsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ENUMSPD` reader - Enumerated speed"]
pub type EnumspdR = crate::FieldReader;
#[doc = "Field `ENUMSPD` writer - Enumerated speed"]
pub type EnumspdW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `EERR` reader - Erratic error"]
pub type EerrR = crate::BitReader;
#[doc = "Field `EERR` writer - Erratic error"]
pub type EerrW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FNSOF` reader - Frame number of the received SOF"]
pub type FnsofR = crate::FieldReader<u16>;
#[doc = "Field `FNSOF` writer - Frame number of the received SOF"]
pub type FnsofW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bit 0 - Suspend status"]
    #[inline(always)]
    pub fn suspsts(&self) -> SuspstsR {
        SuspstsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 1:2 - Enumerated speed"]
    #[inline(always)]
    pub fn enumspd(&self) -> EnumspdR {
        EnumspdR::new(((self.bits >> 1) & 3) as u8)
    }
    #[doc = "Bit 3 - Erratic error"]
    #[inline(always)]
    pub fn eerr(&self) -> EerrR {
        EerrR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bits 8:21 - Frame number of the received SOF"]
    #[inline(always)]
    pub fn fnsof(&self) -> FnsofR {
        FnsofR::new(((self.bits >> 8) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bit 0 - Suspend status"]
    #[inline(always)]
    #[must_use]
    pub fn suspsts(&mut self) -> SuspstsW<FsDstsSpec> {
        SuspstsW::new(self, 0)
    }
    #[doc = "Bits 1:2 - Enumerated speed"]
    #[inline(always)]
    #[must_use]
    pub fn enumspd(&mut self) -> EnumspdW<FsDstsSpec> {
        EnumspdW::new(self, 1)
    }
    #[doc = "Bit 3 - Erratic error"]
    #[inline(always)]
    #[must_use]
    pub fn eerr(&mut self) -> EerrW<FsDstsSpec> {
        EerrW::new(self, 3)
    }
    #[doc = "Bits 8:21 - Frame number of the received SOF"]
    #[inline(always)]
    #[must_use]
    pub fn fnsof(&mut self) -> FnsofW<FsDstsSpec> {
        FnsofW::new(self, 8)
    }
}
#[doc = "OTG_FS device status register (OTG_FS_DSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fs_dsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FsDstsSpec;
impl crate::RegisterSpec for FsDstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`fs_dsts::R`](R) reader structure"]
impl crate::Readable for FsDstsSpec {}
#[doc = "`reset()` method sets FS_DSTS to value 0x10"]
impl crate::Resettable for FsDstsSpec {
    const RESET_VALUE: u32 = 0x10;
}
