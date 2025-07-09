// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ISR` reader"]
pub type R = crate::R<IsrSpec>;
#[doc = "Register `ISR` writer"]
pub type W = crate::W<IsrSpec>;
#[doc = "Field `CMPM` reader - Compare match"]
pub type CmpmR = crate::BitReader;
#[doc = "Field `CMPM` writer - Compare match"]
pub type CmpmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARRM` reader - Autoreload match"]
pub type ArrmR = crate::BitReader;
#[doc = "Field `ARRM` writer - Autoreload match"]
pub type ArrmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `EXTTRIG` reader - External trigger edge event"]
pub type ExttrigR = crate::BitReader;
#[doc = "Field `EXTTRIG` writer - External trigger edge event"]
pub type ExttrigW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CMPOK` reader - Compare register update OK"]
pub type CmpokR = crate::BitReader;
#[doc = "Field `CMPOK` writer - Compare register update OK"]
pub type CmpokW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `ARROK` reader - Autoreload register update OK"]
pub type ArrokR = crate::BitReader;
#[doc = "Field `ARROK` writer - Autoreload register update OK"]
pub type ArrokW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `UP` reader - Counter direction change down to up"]
pub type UpR = crate::BitReader;
#[doc = "Field `UP` writer - Counter direction change down to up"]
pub type UpW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `DOWN` reader - Counter direction change up to down"]
pub type DownR = crate::BitReader;
#[doc = "Field `DOWN` writer - Counter direction change up to down"]
pub type DownW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Compare match"]
    #[inline(always)]
    pub fn cmpm(&self) -> CmpmR {
        CmpmR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Autoreload match"]
    #[inline(always)]
    pub fn arrm(&self) -> ArrmR {
        ArrmR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - External trigger edge event"]
    #[inline(always)]
    pub fn exttrig(&self) -> ExttrigR {
        ExttrigR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Compare register update OK"]
    #[inline(always)]
    pub fn cmpok(&self) -> CmpokR {
        CmpokR::new(((self.bits >> 3) & 1) != 0)
    }
    #[doc = "Bit 4 - Autoreload register update OK"]
    #[inline(always)]
    pub fn arrok(&self) -> ArrokR {
        ArrokR::new(((self.bits >> 4) & 1) != 0)
    }
    #[doc = "Bit 5 - Counter direction change down to up"]
    #[inline(always)]
    pub fn up(&self) -> UpR {
        UpR::new(((self.bits >> 5) & 1) != 0)
    }
    #[doc = "Bit 6 - Counter direction change up to down"]
    #[inline(always)]
    pub fn down(&self) -> DownR {
        DownR::new(((self.bits >> 6) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Compare match"]
    #[inline(always)]
    #[must_use]
    pub fn cmpm(&mut self) -> CmpmW<IsrSpec> {
        CmpmW::new(self, 0)
    }
    #[doc = "Bit 1 - Autoreload match"]
    #[inline(always)]
    #[must_use]
    pub fn arrm(&mut self) -> ArrmW<IsrSpec> {
        ArrmW::new(self, 1)
    }
    #[doc = "Bit 2 - External trigger edge event"]
    #[inline(always)]
    #[must_use]
    pub fn exttrig(&mut self) -> ExttrigW<IsrSpec> {
        ExttrigW::new(self, 2)
    }
    #[doc = "Bit 3 - Compare register update OK"]
    #[inline(always)]
    #[must_use]
    pub fn cmpok(&mut self) -> CmpokW<IsrSpec> {
        CmpokW::new(self, 3)
    }
    #[doc = "Bit 4 - Autoreload register update OK"]
    #[inline(always)]
    #[must_use]
    pub fn arrok(&mut self) -> ArrokW<IsrSpec> {
        ArrokW::new(self, 4)
    }
    #[doc = "Bit 5 - Counter direction change down to up"]
    #[inline(always)]
    #[must_use]
    pub fn up(&mut self) -> UpW<IsrSpec> {
        UpW::new(self, 5)
    }
    #[doc = "Bit 6 - Counter direction change up to down"]
    #[inline(always)]
    #[must_use]
    pub fn down(&mut self) -> DownW<IsrSpec> {
        DownW::new(self, 6)
    }
}
#[doc = "Interrupt and Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`reset()` method sets ISR to value 0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0;
}
