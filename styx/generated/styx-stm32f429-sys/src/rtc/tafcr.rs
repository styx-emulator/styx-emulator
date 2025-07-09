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
#[doc = "Register `TAFCR` reader"]
pub type R = crate::R<TafcrSpec>;
#[doc = "Register `TAFCR` writer"]
pub type W = crate::W<TafcrSpec>;
#[doc = "Field `TAMP1E` reader - Tamper 1 detection enable"]
pub type Tamp1eR = crate::BitReader;
#[doc = "Field `TAMP1E` writer - Tamper 1 detection enable"]
pub type Tamp1eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1TRG` reader - Active level for tamper 1"]
pub type Tamp1trgR = crate::BitReader;
#[doc = "Field `TAMP1TRG` writer - Active level for tamper 1"]
pub type Tamp1trgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPIE` reader - Tamper interrupt enable"]
pub type TampieR = crate::BitReader;
#[doc = "Field `TAMPIE` writer - Tamper interrupt enable"]
pub type TampieW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2E` reader - Tamper 2 detection enable"]
pub type Tamp2eR = crate::BitReader;
#[doc = "Field `TAMP2E` writer - Tamper 2 detection enable"]
pub type Tamp2eW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP2TRG` reader - Active level for tamper 2"]
pub type Tamp2trgR = crate::BitReader;
#[doc = "Field `TAMP2TRG` writer - Active level for tamper 2"]
pub type Tamp2trgW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPTS` reader - Activate timestamp on tamper detection event"]
pub type TamptsR = crate::BitReader;
#[doc = "Field `TAMPTS` writer - Activate timestamp on tamper detection event"]
pub type TamptsW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMPFREQ` reader - Tamper sampling frequency"]
pub type TampfreqR = crate::FieldReader;
#[doc = "Field `TAMPFREQ` writer - Tamper sampling frequency"]
pub type TampfreqW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
#[doc = "Field `TAMPFLT` reader - Tamper filter count"]
pub type TampfltR = crate::FieldReader;
#[doc = "Field `TAMPFLT` writer - Tamper filter count"]
pub type TampfltW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TAMPPRCH` reader - Tamper precharge duration"]
pub type TampprchR = crate::FieldReader;
#[doc = "Field `TAMPPRCH` writer - Tamper precharge duration"]
pub type TampprchW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
#[doc = "Field `TAMPPUDIS` reader - TAMPER pull-up disable"]
pub type TamppudisR = crate::BitReader;
#[doc = "Field `TAMPPUDIS` writer - TAMPER pull-up disable"]
pub type TamppudisW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TAMP1INSEL` reader - TAMPER1 mapping"]
pub type Tamp1inselR = crate::BitReader;
#[doc = "Field `TAMP1INSEL` writer - TAMPER1 mapping"]
pub type Tamp1inselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TSINSEL` reader - TIMESTAMP mapping"]
pub type TsinselR = crate::BitReader;
#[doc = "Field `TSINSEL` writer - TIMESTAMP mapping"]
pub type TsinselW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ALARMOUTTYPE` reader - AFO_ALARM output type"]
pub type AlarmouttypeR = crate::BitReader;
#[doc = "Field `ALARMOUTTYPE` writer - AFO_ALARM output type"]
pub type AlarmouttypeW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Tamper 1 detection enable"]
    #[inline(always)]
    pub fn tamp1e(&self) -> Tamp1eR {
        Tamp1eR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Active level for tamper 1"]
    #[inline(always)]
    pub fn tamp1trg(&self) -> Tamp1trgR {
        Tamp1trgR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Tamper interrupt enable"]
    #[inline(always)]
    pub fn tampie(&self) -> TampieR {
        TampieR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Tamper 2 detection enable"]
    #[inline(always)]
    pub fn tamp2e(&self) -> Tamp2eR {
        Tamp2eR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Active level for tamper 2"]
    #[inline(always)]
    pub fn tamp2trg(&self) -> Tamp2trgR {
        Tamp2trgR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 7 - Activate timestamp on tamper detection event"]
    #[inline(always)]
    pub fn tampts(&self) -> TamptsR {
        TamptsR::new(((self.bits >> 7) & 1) != 0)
    }
    #[doc = "Bits 8:10 - Tamper sampling frequency"]
    #[inline(always)]
    pub fn tampfreq(&self) -> TampfreqR {
        TampfreqR::new(((self.bits >> 8) & 7) as u8)
    }
    #[doc = "Bits 11:12 - Tamper filter count"]
    #[inline(always)]
    pub fn tampflt(&self) -> TampfltR {
        TampfltR::new(((self.bits >> 11) & 3) as u8)
    }
    #[doc = "Bits 13:14 - Tamper precharge duration"]
    #[inline(always)]
    pub fn tampprch(&self) -> TampprchR {
        TampprchR::new(((self.bits >> 13) & 3) as u8)
    }
    #[doc = "Bit 15 - TAMPER pull-up disable"]
    #[inline(always)]
    pub fn tamppudis(&self) -> TamppudisR {
        TamppudisR::new(((self.bits >> 15) & 1) != 0)
    }
    #[doc = "Bit 16 - TAMPER1 mapping"]
    #[inline(always)]
    pub fn tamp1insel(&self) -> Tamp1inselR {
        Tamp1inselR::new(((self.bits >> 16) & 1) != 0)
    }
    #[doc = "Bit 17 - TIMESTAMP mapping"]
    #[inline(always)]
    pub fn tsinsel(&self) -> TsinselR {
        TsinselR::new(((self.bits >> 17) & 1) != 0)
    }
    #[doc = "Bit 18 - AFO_ALARM output type"]
    #[inline(always)]
    pub fn alarmouttype(&self) -> AlarmouttypeR {
        AlarmouttypeR::new(((self.bits >> 18) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Tamper 1 detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1e(&mut self) -> Tamp1eW<TafcrSpec> {
        Tamp1eW::new(self, 0)
    }
    #[doc = "Bit 1 - Active level for tamper 1"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1trg(&mut self) -> Tamp1trgW<TafcrSpec> {
        Tamp1trgW::new(self, 1)
    }
    #[doc = "Bit 2 - Tamper interrupt enable"]
    #[inline(always)]
    #[must_use]
    pub fn tampie(&mut self) -> TampieW<TafcrSpec> {
        TampieW::new(self, 2)
    }
    #[doc = "Bit 3 - Tamper 2 detection enable"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2e(&mut self) -> Tamp2eW<TafcrSpec> {
        Tamp2eW::new(self, 3)
    }
    #[doc = "Bit 4 - Active level for tamper 2"]
    #[inline(always)]
    #[must_use]
    pub fn tamp2trg(&mut self) -> Tamp2trgW<TafcrSpec> {
        Tamp2trgW::new(self, 4)
    }
    #[doc = "Bit 7 - Activate timestamp on tamper detection event"]
    #[inline(always)]
    #[must_use]
    pub fn tampts(&mut self) -> TamptsW<TafcrSpec> {
        TamptsW::new(self, 7)
    }
    #[doc = "Bits 8:10 - Tamper sampling frequency"]
    #[inline(always)]
    #[must_use]
    pub fn tampfreq(&mut self) -> TampfreqW<TafcrSpec> {
        TampfreqW::new(self, 8)
    }
    #[doc = "Bits 11:12 - Tamper filter count"]
    #[inline(always)]
    #[must_use]
    pub fn tampflt(&mut self) -> TampfltW<TafcrSpec> {
        TampfltW::new(self, 11)
    }
    #[doc = "Bits 13:14 - Tamper precharge duration"]
    #[inline(always)]
    #[must_use]
    pub fn tampprch(&mut self) -> TampprchW<TafcrSpec> {
        TampprchW::new(self, 13)
    }
    #[doc = "Bit 15 - TAMPER pull-up disable"]
    #[inline(always)]
    #[must_use]
    pub fn tamppudis(&mut self) -> TamppudisW<TafcrSpec> {
        TamppudisW::new(self, 15)
    }
    #[doc = "Bit 16 - TAMPER1 mapping"]
    #[inline(always)]
    #[must_use]
    pub fn tamp1insel(&mut self) -> Tamp1inselW<TafcrSpec> {
        Tamp1inselW::new(self, 16)
    }
    #[doc = "Bit 17 - TIMESTAMP mapping"]
    #[inline(always)]
    #[must_use]
    pub fn tsinsel(&mut self) -> TsinselW<TafcrSpec> {
        TsinselW::new(self, 17)
    }
    #[doc = "Bit 18 - AFO_ALARM output type"]
    #[inline(always)]
    #[must_use]
    pub fn alarmouttype(&mut self) -> AlarmouttypeW<TafcrSpec> {
        AlarmouttypeW::new(self, 18)
    }
}
#[doc = "tamper and alternate function configuration register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`tafcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`tafcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct TafcrSpec;
impl crate::RegisterSpec for TafcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`tafcr::R`](R) reader structure"]
impl crate::Readable for TafcrSpec {}
#[doc = "`write(|w| ..)` method takes [`tafcr::W`](W) writer structure"]
impl crate::Writable for TafcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets TAFCR to value 0"]
impl crate::Resettable for TafcrSpec {
    const RESET_VALUE: u32 = 0;
}
