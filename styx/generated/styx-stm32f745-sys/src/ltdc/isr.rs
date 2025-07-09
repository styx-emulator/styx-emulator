// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ISR` reader"]
pub type R = crate::R<IsrSpec>;
#[doc = "Register `ISR` writer"]
pub type W = crate::W<IsrSpec>;
#[doc = "Field `LIF` reader - Line Interrupt flag"]
pub type LifR = crate::BitReader;
#[doc = "Field `LIF` writer - Line Interrupt flag"]
pub type LifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `FUIF` reader - FIFO Underrun Interrupt flag"]
pub type FuifR = crate::BitReader;
#[doc = "Field `FUIF` writer - FIFO Underrun Interrupt flag"]
pub type FuifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `TERRIF` reader - Transfer Error interrupt flag"]
pub type TerrifR = crate::BitReader;
#[doc = "Field `TERRIF` writer - Transfer Error interrupt flag"]
pub type TerrifW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RRIF` reader - Register Reload Interrupt Flag"]
pub type RrifR = crate::BitReader;
#[doc = "Field `RRIF` writer - Register Reload Interrupt Flag"]
pub type RrifW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Line Interrupt flag"]
    #[inline(always)]
    pub fn lif(&self) -> LifR {
        LifR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - FIFO Underrun Interrupt flag"]
    #[inline(always)]
    pub fn fuif(&self) -> FuifR {
        FuifR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Transfer Error interrupt flag"]
    #[inline(always)]
    pub fn terrif(&self) -> TerrifR {
        TerrifR::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Register Reload Interrupt Flag"]
    #[inline(always)]
    pub fn rrif(&self) -> RrifR {
        RrifR::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Line Interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn lif(&mut self) -> LifW<IsrSpec> {
        LifW::new(self, 0)
    }
    #[doc = "Bit 1 - FIFO Underrun Interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn fuif(&mut self) -> FuifW<IsrSpec> {
        FuifW::new(self, 1)
    }
    #[doc = "Bit 2 - Transfer Error interrupt flag"]
    #[inline(always)]
    #[must_use]
    pub fn terrif(&mut self) -> TerrifW<IsrSpec> {
        TerrifW::new(self, 2)
    }
    #[doc = "Bit 3 - Register Reload Interrupt Flag"]
    #[inline(always)]
    #[must_use]
    pub fn rrif(&mut self) -> RrifW<IsrSpec> {
        RrifW::new(self, 3)
    }
}
#[doc = "Interrupt Status Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`isr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IsrSpec;
impl crate::RegisterSpec for IsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 56u64;
}
#[doc = "`read()` method returns [`isr::R`](R) reader structure"]
impl crate::Readable for IsrSpec {}
#[doc = "`reset()` method sets ISR to value 0"]
impl crate::Resettable for IsrSpec {
    const RESET_VALUE: u32 = 0;
}
