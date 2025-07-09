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
#[doc = "Register `SDCMR` reader"]
pub type R = crate::R<SdcmrSpec>;
#[doc = "Register `SDCMR` writer"]
pub type W = crate::W<SdcmrSpec>;
#[doc = "Field `MODE` reader - Command mode"]
pub type ModeR = crate::FieldReader;
#[doc = "Field `MODE` writer - Command mode"]
pub type ModeW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `CTB2` reader - Command target bank 2"]
pub type Ctb2R = crate::BitReader;
#[doc = "Field `CTB2` writer - Command target bank 2"]
pub type Ctb2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CTB1` reader - Command target bank 1"]
pub type Ctb1R = crate::BitReader;
#[doc = "Field `CTB1` writer - Command target bank 1"]
pub type Ctb1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `NRFS` reader - Number of Auto-refresh"]
pub type NrfsR = crate::FieldReader;
#[doc = "Field `NRFS` writer - Number of Auto-refresh"]
pub type NrfsW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
#[doc = "Field `MRD` reader - Mode Register definition"]
pub type MrdR = crate::FieldReader<u16>;
#[doc = "Field `MRD` writer - Mode Register definition"]
pub type MrdW<'a, REG> = crate::FieldWriter<'a, REG, 13, u16>;
impl R {
    #[doc = "Bits 0:2 - Command mode"]
    #[inline(always)]
    pub fn mode(&self) -> ModeR {
        ModeR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 3 - Command target bank 2"]
    #[inline(always)]
    pub fn ctb2(&self) -> Ctb2R {
        Ctb2R::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Command target bank 1"]
    #[inline(always)]
    pub fn ctb1(&self) -> Ctb1R {
        Ctb1R::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:8 - Number of Auto-refresh"]
    #[inline(always)]
    pub fn nrfs(&self) -> NrfsR {
        NrfsR::new(((self.bits >> 5) & 0x0f) as u8)
    }
    #[doc = "Bits 9:21 - Mode Register definition"]
    #[inline(always)]
    pub fn mrd(&self) -> MrdR {
        MrdR::new(((self.bits >> 9) & 0x1fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:2 - Command mode"]
    #[inline(always)]
    #[must_use]
    pub fn mode(&mut self) -> ModeW<SdcmrSpec> {
        ModeW::new(self, 0)
    }
    #[doc = "Bit 3 - Command target bank 2"]
    #[inline(always)]
    #[must_use]
    pub fn ctb2(&mut self) -> Ctb2W<SdcmrSpec> {
        Ctb2W::new(self, 3)
    }
    #[doc = "Bit 4 - Command target bank 1"]
    #[inline(always)]
    #[must_use]
    pub fn ctb1(&mut self) -> Ctb1W<SdcmrSpec> {
        Ctb1W::new(self, 4)
    }
    #[doc = "Bits 5:8 - Number of Auto-refresh"]
    #[inline(always)]
    #[must_use]
    pub fn nrfs(&mut self) -> NrfsW<SdcmrSpec> {
        NrfsW::new(self, 5)
    }
    #[doc = "Bits 9:21 - Mode Register definition"]
    #[inline(always)]
    #[must_use]
    pub fn mrd(&mut self) -> MrdW<SdcmrSpec> {
        MrdW::new(self, 9)
    }
}
#[doc = "SDRAM Command Mode register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sdcmr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sdcmr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SdcmrSpec;
impl crate::RegisterSpec for SdcmrSpec {
    type Ux = u32;
    const OFFSET: u64 = 336u64;
}
#[doc = "`read()` method returns [`sdcmr::R`](R) reader structure"]
impl crate::Readable for SdcmrSpec {}
#[doc = "`write(|w| ..)` method takes [`sdcmr::W`](W) writer structure"]
impl crate::Writable for SdcmrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SDCMR to value 0"]
impl crate::Resettable for SdcmrSpec {
    const RESET_VALUE: u32 = 0;
}
