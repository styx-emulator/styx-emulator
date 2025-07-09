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
#[doc = "Register `OTG_FS_HNPTXSTS` reader"]
pub type R = crate::R<OtgFsHnptxstsSpec>;
#[doc = "Register `OTG_FS_HNPTXSTS` writer"]
pub type W = crate::W<OtgFsHnptxstsSpec>;
#[doc = "Field `NPTXFSAV` reader - Non-periodic TxFIFO space available"]
pub type NptxfsavR = crate::FieldReader<u16>;
#[doc = "Field `NPTXFSAV` writer - Non-periodic TxFIFO space available"]
pub type NptxfsavW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `NPTQXSAV` reader - Non-periodic transmit request queue space available"]
pub type NptqxsavR = crate::FieldReader;
#[doc = "Field `NPTQXSAV` writer - Non-periodic transmit request queue space available"]
pub type NptqxsavW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
#[doc = "Field `NPTXQTOP` reader - Top of the non-periodic transmit request queue"]
pub type NptxqtopR = crate::FieldReader;
#[doc = "Field `NPTXQTOP` writer - Top of the non-periodic transmit request queue"]
pub type NptxqtopW<'a, REG> = crate::FieldWriter<'a, REG, 7>;
impl R {
    #[doc = "Bits 0:15 - Non-periodic TxFIFO space available"]
    #[inline(always)]
    pub fn nptxfsav(&self) -> NptxfsavR {
        NptxfsavR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:23 - Non-periodic transmit request queue space available"]
    #[inline(always)]
    pub fn nptqxsav(&self) -> NptqxsavR {
        NptqxsavR::new(((self.bits >> 16) & 0xff) as u8)
    }
    #[doc = "Bits 24:30 - Top of the non-periodic transmit request queue"]
    #[inline(always)]
    pub fn nptxqtop(&self) -> NptxqtopR {
        NptxqtopR::new(((self.bits >> 24) & 0x7f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:15 - Non-periodic TxFIFO space available"]
    #[inline(always)]
    #[must_use]
    pub fn nptxfsav(&mut self) -> NptxfsavW<OtgFsHnptxstsSpec> {
        NptxfsavW::new(self, 0)
    }
    #[doc = "Bits 16:23 - Non-periodic transmit request queue space available"]
    #[inline(always)]
    #[must_use]
    pub fn nptqxsav(&mut self) -> NptqxsavW<OtgFsHnptxstsSpec> {
        NptqxsavW::new(self, 16)
    }
    #[doc = "Bits 24:30 - Top of the non-periodic transmit request queue"]
    #[inline(always)]
    #[must_use]
    pub fn nptxqtop(&mut self) -> NptxqtopW<OtgFsHnptxstsSpec> {
        NptxqtopW::new(self, 24)
    }
}
#[doc = "OTG_FS non-periodic transmit FIFO/queue status register (OTG_FS_GNPTXSTS)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hnptxsts::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsHnptxstsSpec;
impl crate::RegisterSpec for OtgFsHnptxstsSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`otg_fs_hnptxsts::R`](R) reader structure"]
impl crate::Readable for OtgFsHnptxstsSpec {}
#[doc = "`reset()` method sets OTG_FS_HNPTXSTS to value 0x0008_0200"]
impl crate::Resettable for OtgFsHnptxstsSpec {
    const RESET_VALUE: u32 = 0x0008_0200;
}
