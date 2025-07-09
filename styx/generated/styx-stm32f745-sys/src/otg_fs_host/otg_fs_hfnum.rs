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
#[doc = "Register `OTG_FS_HFNUM` reader"]
pub type R = crate::R<OtgFsHfnumSpec>;
#[doc = "Register `OTG_FS_HFNUM` writer"]
pub type W = crate::W<OtgFsHfnumSpec>;
#[doc = "Field `FRNUM` reader - Frame number"]
pub type FrnumR = crate::FieldReader<u16>;
#[doc = "Field `FRNUM` writer - Frame number"]
pub type FrnumW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `FTREM` reader - Frame time remaining"]
pub type FtremR = crate::FieldReader<u16>;
#[doc = "Field `FTREM` writer - Frame time remaining"]
pub type FtremW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Frame number"]
    #[inline(always)]
    pub fn frnum(&self) -> FrnumR {
        FrnumR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - Frame time remaining"]
    #[inline(always)]
    pub fn ftrem(&self) -> FtremR {
        FtremR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Frame number"]
    #[inline(always)]
    #[must_use]
    pub fn frnum(&mut self) -> FrnumW<OtgFsHfnumSpec> {
        FrnumW::new(self, 0)
    }
    #[doc = "Bits 16:31 - Frame time remaining"]
    #[inline(always)]
    #[must_use]
    pub fn ftrem(&mut self) -> FtremW<OtgFsHfnumSpec> {
        FtremW::new(self, 16)
    }
}
#[doc = "OTG_FS host frame number/frame time remaining register (OTG_FS_HFNUM)\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_fs_hfnum::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgFsHfnumSpec;
impl crate::RegisterSpec for OtgFsHfnumSpec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`otg_fs_hfnum::R`](R) reader structure"]
impl crate::Readable for OtgFsHfnumSpec {}
#[doc = "`reset()` method sets OTG_FS_HFNUM to value 0x3fff"]
impl crate::Resettable for OtgFsHfnumSpec {
    const RESET_VALUE: u32 = 0x3fff;
}
