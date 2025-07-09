// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_DEACHINTMSK` reader"]
pub type R = crate::R<OtgHsDeachintmskSpec>;
#[doc = "Register `OTG_HS_DEACHINTMSK` writer"]
pub type W = crate::W<OtgHsDeachintmskSpec>;
#[doc = "Field `IEP1INTM` reader - IN Endpoint 1 interrupt mask bit"]
pub type Iep1intmR = crate::BitReader;
#[doc = "Field `IEP1INTM` writer - IN Endpoint 1 interrupt mask bit"]
pub type Iep1intmW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `OEP1INTM` reader - OUT Endpoint 1 interrupt mask bit"]
pub type Oep1intmR = crate::BitReader;
#[doc = "Field `OEP1INTM` writer - OUT Endpoint 1 interrupt mask bit"]
pub type Oep1intmW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 1 - IN Endpoint 1 interrupt mask bit"]
    #[inline(always)]
    pub fn iep1intm(&self) -> Iep1intmR {
        Iep1intmR::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 17 - OUT Endpoint 1 interrupt mask bit"]
    #[inline(always)]
    pub fn oep1intm(&self) -> Oep1intmR {
        Oep1intmR::new(((self.bits >> 17) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 1 - IN Endpoint 1 interrupt mask bit"]
    #[inline(always)]
    #[must_use]
    pub fn iep1intm(&mut self) -> Iep1intmW<OtgHsDeachintmskSpec> {
        Iep1intmW::new(self, 1)
    }
    #[doc = "Bit 17 - OUT Endpoint 1 interrupt mask bit"]
    #[inline(always)]
    #[must_use]
    pub fn oep1intm(&mut self) -> Oep1intmW<OtgHsDeachintmskSpec> {
        Oep1intmW::new(self, 17)
    }
}
#[doc = "OTG_HS device each endpoint interrupt register mask\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_deachintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_deachintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsDeachintmskSpec;
impl crate::RegisterSpec for OtgHsDeachintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`otg_hs_deachintmsk::R`](R) reader structure"]
impl crate::Readable for OtgHsDeachintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_deachintmsk::W`](W) writer structure"]
impl crate::Writable for OtgHsDeachintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_DEACHINTMSK to value 0"]
impl crate::Resettable for OtgHsDeachintmskSpec {
    const RESET_VALUE: u32 = 0;
}
