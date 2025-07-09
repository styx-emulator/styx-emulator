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
#[doc = "Register `MMCTIMR` reader"]
pub type R = crate::R<MmctimrSpec>;
#[doc = "Register `MMCTIMR` writer"]
pub type W = crate::W<MmctimrSpec>;
#[doc = "Field `TGFSCM` reader - TGFSCM"]
pub type TgfscmR = crate::BitReader;
#[doc = "Field `TGFSCM` writer - TGFSCM"]
pub type TgfscmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TGFMSCM` reader - TGFMSCM"]
pub type TgfmscmR = crate::BitReader;
#[doc = "Field `TGFMSCM` writer - TGFMSCM"]
pub type TgfmscmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TGFM` reader - TGFM"]
pub type TgfmR = crate::BitReader;
#[doc = "Field `TGFM` writer - TGFM"]
pub type TgfmW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 14 - TGFSCM"]
    #[inline(always)]
    pub fn tgfscm(&self) -> TgfscmR {
        TgfscmR::new(((self.bits >> 14) & 1) != 0)
    }
    #[doc = "Bit 15 - TGFMSCM"]
    #[inline(always)]
    pub fn tgfmscm(&self) -> TgfmscmR {
        TgfmscmR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - TGFM"]
    #[inline(always)]
    pub fn tgfm(&self) -> TgfmR {
        TgfmR::new(((self.bits >> 16) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 14 - TGFSCM"]
    #[inline(always)]
    #[must_use]
    pub fn tgfscm(&mut self) -> TgfscmW<MmctimrSpec> {
        TgfscmW::new(self, 14)
    }
    #[doc = "Bit 15 - TGFMSCM"]
    #[inline(always)]
    #[must_use]
    pub fn tgfmscm(&mut self) -> TgfmscmW<MmctimrSpec> {
        TgfmscmW::new(self, 15)
    }
    #[doc = "Bit 16 - TGFM"]
    #[inline(always)]
    #[must_use]
    pub fn tgfm(&mut self) -> TgfmW<MmctimrSpec> {
        TgfmW::new(self, 16)
    }
}
#[doc = "Ethernet MMC transmit interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`mmctimr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`mmctimr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MmctimrSpec;
impl crate::RegisterSpec for MmctimrSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`mmctimr::R`](R) reader structure"]
impl crate::Readable for MmctimrSpec {}
#[doc = "`write(|w| ..)` method takes [`mmctimr::W`](W) writer structure"]
impl crate::Writable for MmctimrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MMCTIMR to value 0"]
impl crate::Resettable for MmctimrSpec {
    const RESET_VALUE: u32 = 0;
}
