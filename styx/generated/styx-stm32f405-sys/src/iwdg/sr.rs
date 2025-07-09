// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `SR` reader"]
pub type R = crate::R<SrSpec>;
#[doc = "Register `SR` writer"]
pub type W = crate::W<SrSpec>;
#[doc = "Field `PVU` reader - Watchdog prescaler value update"]
pub type PvuR = crate::BitReader;
#[doc = "Field `PVU` writer - Watchdog prescaler value update"]
pub type PvuW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `RVU` reader - Watchdog counter reload value update"]
pub type RvuR = crate::BitReader;
#[doc = "Field `RVU` writer - Watchdog counter reload value update"]
pub type RvuW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Watchdog prescaler value update"]
    #[inline(always)]
    pub fn pvu(&self) -> PvuR {
        PvuR::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Watchdog counter reload value update"]
    #[inline(always)]
    pub fn rvu(&self) -> RvuR {
        RvuR::new(((self.bits >> 1) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Watchdog prescaler value update"]
    #[inline(always)]
    #[must_use]
    pub fn pvu(&mut self) -> PvuW<SrSpec> {
        PvuW::new(self, 0)
    }
    #[doc = "Bit 1 - Watchdog counter reload value update"]
    #[inline(always)]
    #[must_use]
    pub fn rvu(&mut self) -> RvuW<SrSpec> {
        RvuW::new(self, 1)
    }
}
#[doc = "Status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sr::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SrSpec;
impl crate::RegisterSpec for SrSpec {
    type Ux = u32;
    const OFFSET: u64 = 12u64;
}
#[doc = "`read()` method returns [`sr::R`](R) reader structure"]
impl crate::Readable for SrSpec {}
#[doc = "`reset()` method sets SR to value 0"]
impl crate::Resettable for SrSpec {
    const RESET_VALUE: u32 = 0;
}
