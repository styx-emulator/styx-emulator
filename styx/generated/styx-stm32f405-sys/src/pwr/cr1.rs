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
#[doc = "Register `CR1` reader"]
pub type R = crate::R<Cr1Spec>;
#[doc = "Register `CR1` writer"]
pub type W = crate::W<Cr1Spec>;
#[doc = "Field `LPDS` reader - Low-power deep sleep"]
pub type LpdsR = crate::BitReader;
#[doc = "Field `LPDS` writer - Low-power deep sleep"]
pub type LpdsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PDDS` reader - Power down deepsleep"]
pub type PddsR = crate::BitReader;
#[doc = "Field `PDDS` writer - Power down deepsleep"]
pub type PddsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CSBF` reader - Clear standby flag"]
pub type CsbfR = crate::BitReader;
#[doc = "Field `CSBF` writer - Clear standby flag"]
pub type CsbfW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PVDE` reader - Power voltage detector enable"]
pub type PvdeR = crate::BitReader;
#[doc = "Field `PVDE` writer - Power voltage detector enable"]
pub type PvdeW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `PLS` reader - PVD level selection"]
pub type PlsR = crate::FieldReader;
#[doc = "Field `PLS` writer - PVD level selection"]
pub type PlsW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `DBP` reader - Disable backup domain write protection"]
pub type DbpR = crate::BitReader;
#[doc = "Field `DBP` writer - Disable backup domain write protection"]
pub type DbpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FPDS` reader - Flash power down in Stop mode"]
pub type FpdsR = crate::BitReader;
#[doc = "Field `FPDS` writer - Flash power down in Stop mode"]
pub type FpdsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `LPUDS` reader - Low-power regulator in deepsleep under-drive mode"]
pub type LpudsR = crate::BitReader;
#[doc = "Field `LPUDS` writer - Low-power regulator in deepsleep under-drive mode"]
pub type LpudsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `MRUDS` reader - Main regulator in deepsleep under-drive mode"]
pub type MrudsR = crate::BitReader;
#[doc = "Field `MRUDS` writer - Main regulator in deepsleep under-drive mode"]
pub type MrudsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ADCDC1` reader - ADCDC1"]
pub type Adcdc1R = crate::BitReader;
#[doc = "Field `ADCDC1` writer - ADCDC1"]
pub type Adcdc1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `VOS` reader - Regulator voltage scaling output selection"]
pub type VosR = crate::FieldReader;
#[doc = "Field `VOS` writer - Regulator voltage scaling output selection"]
pub type VosW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `ODEN` reader - Over-drive enable"]
pub type OdenR = crate::BitReader;
#[doc = "Field `ODEN` writer - Over-drive enable"]
pub type OdenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ODSWEN` reader - Over-drive switching enabled"]
pub type OdswenR = crate::BitReader;
#[doc = "Field `ODSWEN` writer - Over-drive switching enabled"]
pub type OdswenW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UDEN` reader - Under-drive enable in stop mode"]
pub type UdenR = crate::FieldReader;
#[doc = "Field `UDEN` writer - Under-drive enable in stop mode"]
pub type UdenW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bit 0 - Low-power deep sleep"]
    #[inline(always)]
    pub fn lpds(&self) -> LpdsR {
        LpdsR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Power down deepsleep"]
    #[inline(always)]
    pub fn pdds(&self) -> PddsR {
        PddsR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 3 - Clear standby flag"]
    #[inline(always)]
    pub fn csbf(&self) -> CsbfR {
        CsbfR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Power voltage detector enable"]
    #[inline(always)]
    pub fn pvde(&self) -> PvdeR {
        PvdeR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bits 5:7 - PVD level selection"]
    #[inline(always)]
    pub fn pls(&self) -> PlsR {
        PlsR::new(((self.bits >> 5) & 7) as u8)
    }
    #[doc = "Bit 8 - Disable backup domain write protection"]
    #[inline(always)]
    pub fn dbp(&self) -> DbpR {
        DbpR::new(((self.bits >> 8) & 1) != 0)
    }
    #[doc = "Bit 9 - Flash power down in Stop mode"]
    #[inline(always)]
    pub fn fpds(&self) -> FpdsR {
        FpdsR::new(((self.bits >> 9) & 1) != 0)
    }
    #[doc = "Bit 10 - Low-power regulator in deepsleep under-drive mode"]
    #[inline(always)]
    pub fn lpuds(&self) -> LpudsR {
        LpudsR::new(((self.bits >> 10) & 1) != 0)
    }
    #[doc = "Bit 11 - Main regulator in deepsleep under-drive mode"]
    #[inline(always)]
    pub fn mruds(&self) -> MrudsR {
        MrudsR::new(((self.bits >> 11) & 1) != 0)
    }
    #[doc = "Bit 13 - ADCDC1"]
    #[inline(always)]
    pub fn adcdc1(&self) -> Adcdc1R {
        Adcdc1R::new(((self.bits >> 13) & 1) != 0)
    }
    #[doc = "Bits 14:15 - Regulator voltage scaling output selection"]
    #[inline(always)]
    pub fn vos(&self) -> VosR {
        VosR::new(((self.bits >> 14) & 3) as u8)
    }
    #[doc = "Bit 16 - Over-drive enable"]
    #[inline(always)]
    pub fn oden(&self) -> OdenR {
        OdenR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - Over-drive switching enabled"]
    #[inline(always)]
    pub fn odswen(&self) -> OdswenR {
        OdswenR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bits 18:19 - Under-drive enable in stop mode"]
    #[inline(always)]
    pub fn uden(&self) -> UdenR {
        UdenR::new(((self.bits >> 18) & 3) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - Low-power deep sleep"]
    #[inline(always)]
    #[must_use]
    pub fn lpds(&mut self) -> LpdsW<Cr1Spec> {
        LpdsW::new(self, 0)
    }
    #[doc = "Bit 1 - Power down deepsleep"]
    #[inline(always)]
    #[must_use]
    pub fn pdds(&mut self) -> PddsW<Cr1Spec> {
        PddsW::new(self, 1)
    }
    #[doc = "Bit 3 - Clear standby flag"]
    #[inline(always)]
    #[must_use]
    pub fn csbf(&mut self) -> CsbfW<Cr1Spec> {
        CsbfW::new(self, 3)
    }
    #[doc = "Bit 4 - Power voltage detector enable"]
    #[inline(always)]
    #[must_use]
    pub fn pvde(&mut self) -> PvdeW<Cr1Spec> {
        PvdeW::new(self, 4)
    }
    #[doc = "Bits 5:7 - PVD level selection"]
    #[inline(always)]
    #[must_use]
    pub fn pls(&mut self) -> PlsW<Cr1Spec> {
        PlsW::new(self, 5)
    }
    #[doc = "Bit 8 - Disable backup domain write protection"]
    #[inline(always)]
    #[must_use]
    pub fn dbp(&mut self) -> DbpW<Cr1Spec> {
        DbpW::new(self, 8)
    }
    #[doc = "Bit 9 - Flash power down in Stop mode"]
    #[inline(always)]
    #[must_use]
    pub fn fpds(&mut self) -> FpdsW<Cr1Spec> {
        FpdsW::new(self, 9)
    }
    #[doc = "Bit 10 - Low-power regulator in deepsleep under-drive mode"]
    #[inline(always)]
    #[must_use]
    pub fn lpuds(&mut self) -> LpudsW<Cr1Spec> {
        LpudsW::new(self, 10)
    }
    #[doc = "Bit 11 - Main regulator in deepsleep under-drive mode"]
    #[inline(always)]
    #[must_use]
    pub fn mruds(&mut self) -> MrudsW<Cr1Spec> {
        MrudsW::new(self, 11)
    }
    #[doc = "Bit 13 - ADCDC1"]
    #[inline(always)]
    #[must_use]
    pub fn adcdc1(&mut self) -> Adcdc1W<Cr1Spec> {
        Adcdc1W::new(self, 13)
    }
    #[doc = "Bits 14:15 - Regulator voltage scaling output selection"]
    #[inline(always)]
    #[must_use]
    pub fn vos(&mut self) -> VosW<Cr1Spec> {
        VosW::new(self, 14)
    }
    #[doc = "Bit 16 - Over-drive enable"]
    #[inline(always)]
    #[must_use]
    pub fn oden(&mut self) -> OdenW<Cr1Spec> {
        OdenW::new(self, 16)
    }
    #[doc = "Bit 17 - Over-drive switching enabled"]
    #[inline(always)]
    #[must_use]
    pub fn odswen(&mut self) -> OdswenW<Cr1Spec> {
        OdswenW::new(self, 17)
    }
    #[doc = "Bits 18:19 - Under-drive enable in stop mode"]
    #[inline(always)]
    #[must_use]
    pub fn uden(&mut self) -> UdenW<Cr1Spec> {
        UdenW::new(self, 18)
    }
}
#[doc = "power control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cr1::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cr1::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Cr1Spec;
impl crate::RegisterSpec for Cr1Spec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cr1::R`](R) reader structure"]
impl crate::Readable for Cr1Spec {}
#[doc = "`write(|w| ..)` method takes [`cr1::W`](W) writer structure"]
impl crate::Writable for Cr1Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CR1 to value 0xc000"]
impl crate::Resettable for Cr1Spec {
    const RESET_VALUE: u32 = 0xc000;
}
