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
#[doc = "Register `SAI_ACR2` reader"]
pub type R = crate::R<SaiAcr2Spec>;
#[doc = "Register `SAI_ACR2` writer"]
pub type W = crate::W<SaiAcr2Spec>;
#[doc = "Field `FTH` reader - FIFO threshold"]
pub type FthR = crate::FieldReader;
#[doc = "Field `FTH` writer - FIFO threshold"]
pub type FthW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `FFLUSH` reader - FIFO flush"]
pub type FflushR = crate::BitReader;
#[doc = "Field `FFLUSH` writer - FIFO flush"]
pub type FflushW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TRIS` reader - Tristate management on data line"]
pub type TrisR = crate::BitReader;
#[doc = "Field `TRIS` writer - Tristate management on data line"]
pub type TrisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTE` reader - Mute"]
pub type MuteR = crate::BitReader;
#[doc = "Field `MUTE` writer - Mute"]
pub type MuteW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTEVAL` reader - Mute value"]
pub type MutevalR = crate::BitReader;
#[doc = "Field `MUTEVAL` writer - Mute value"]
pub type MutevalW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MUTECNT` reader - Mute counter"]
pub type MutecntR = crate::FieldReader;
#[doc = "Field `MUTECNT` writer - Mute counter"]
pub type MutecntW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
#[doc = "Field `CPL` reader - Complement bit"]
pub type CplR = crate::BitReader;
#[doc = "Field `CPL` writer - Complement bit"]
pub type CplW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `COMP` reader - Companding mode"]
pub type CompR = crate::FieldReader;
#[doc = "Field `COMP` writer - Companding mode"]
pub type CompW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:2 - FIFO threshold"]
    #[inline(always)]
    pub fn fth(&self) -> FthR {
        FthR::new((self.bits & 7) as u8)
    }
    #[doc = "Bit 3 - FIFO flush"]
    #[inline(always)]
    pub fn fflush(&self) -> FflushR {
        FflushR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Tristate management on data line"]
    #[inline(always)]
    pub fn tris(&self) -> TrisR {
        TrisR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Mute"]
    #[inline(always)]
    pub fn mute(&self) -> MuteR {
        MuteR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Mute value"]
    #[inline(always)]
    pub fn muteval(&self) -> MutevalR {
        MutevalR::new(((self.bits >> 6) & 1) != 0)
    }
    #[doc = "Bits 7:12 - Mute counter"]
    #[inline(always)]
    pub fn mutecnt(&self) -> MutecntR {
        MutecntR::new(((self.bits >> 7) & 0x3f) as u8)
    }
    #[doc = "Bit 13 - Complement bit"]
    #[inline(always)]
    pub fn cpl(&self) -> CplR {
        CplR::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 14:15 - Companding mode"]
    #[inline(always)]
    pub fn comp(&self) -> CompR {
        CompR::new(((self.bits >> 14) & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - FIFO threshold"]
    #[inline(always)]
    #[must_use]
    pub fn fth(&mut self) -> FthW<SaiAcr2Spec> {
        FthW::new(self, 0)
    }
    #[doc = "Bit 3 - FIFO flush"]
    #[inline(always)]
    #[must_use]
    pub fn fflush(&mut self) -> FflushW<SaiAcr2Spec> {
        FflushW::new(self, 3)
    }
    #[doc = "Bit 4 - Tristate management on data line"]
    #[inline(always)]
    #[must_use]
    pub fn tris(&mut self) -> TrisW<SaiAcr2Spec> {
        TrisW::new(self, 4)
    }
    #[doc = "Bit 5 - Mute"]
    #[inline(always)]
    #[must_use]
    pub fn mute(&mut self) -> MuteW<SaiAcr2Spec> {
        MuteW::new(self, 5)
    }
    #[doc = "Bit 6 - Mute value"]
    #[inline(always)]
    #[must_use]
    pub fn muteval(&mut self) -> MutevalW<SaiAcr2Spec> {
        MutevalW::new(self, 6)
    }
    #[doc = "Bits 7:12 - Mute counter"]
    #[inline(always)]
    #[must_use]
    pub fn mutecnt(&mut self) -> MutecntW<SaiAcr2Spec> {
        MutecntW::new(self, 7)
    }
    #[doc = "Bit 13 - Complement bit"]
    #[inline(always)]
    #[must_use]
    pub fn cpl(&mut self) -> CplW<SaiAcr2Spec> {
        CplW::new(self, 13)
    }
    #[doc = "Bits 14:15 - Companding mode"]
    #[inline(always)]
    #[must_use]
    pub fn comp(&mut self) -> CompW<SaiAcr2Spec> {
        CompW::new(self, 14)
    }
}
#[doc = "SAI AConfiguration register 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sai_acr2::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`sai_acr2::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SaiAcr2Spec;
impl crate::RegisterSpec for SaiAcr2Spec {
    type Ux = u32;
    const OFFSET: u64 = 8u64;
}
#[doc = "`read()` method returns [`sai_acr2::R`](R) reader structure"]
impl crate::Readable for SaiAcr2Spec {}
#[doc = "`write(|w| ..)` method takes [`sai_acr2::W`](W) writer structure"]
impl crate::Writable for SaiAcr2Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets SAI_ACR2 to value 0x40"]
impl crate::Resettable for SaiAcr2Spec {
    const RESET_VALUE: u32 = 0x40;
}
