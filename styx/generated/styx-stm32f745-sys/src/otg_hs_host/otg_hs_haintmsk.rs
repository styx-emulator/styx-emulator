// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OTG_HS_HAINTMSK` reader"]
pub type R = crate::R<OtgHsHaintmskSpec>;
#[doc = "Register `OTG_HS_HAINTMSK` writer"]
pub type W = crate::W<OtgHsHaintmskSpec>;
#[doc = "Field `HAINTM` reader - Channel interrupt mask"]
pub type HaintmR = crate::FieldReader<u16>;
#[doc = "Field `HAINTM` writer - Channel interrupt mask"]
pub type HaintmW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Channel interrupt mask"]
    #[inline(always)]
    pub fn haintm(&self) -> HaintmR {
        HaintmR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Channel interrupt mask"]
    #[inline(always)]
    #[must_use]
    pub fn haintm(&mut self) -> HaintmW<OtgHsHaintmskSpec> {
        HaintmW::new(self, 0)
    }
}
#[doc = "OTG_HS host all channels interrupt mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`otg_hs_haintmsk::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`otg_hs_haintmsk::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OtgHsHaintmskSpec;
impl crate::RegisterSpec for OtgHsHaintmskSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`otg_hs_haintmsk::R`](R) reader structure"]
impl crate::Readable for OtgHsHaintmskSpec {}
#[doc = "`write(|w| ..)` method takes [`otg_hs_haintmsk::W`](W) writer structure"]
impl crate::Writable for OtgHsHaintmskSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OTG_HS_HAINTMSK to value 0"]
impl crate::Resettable for OtgHsHaintmskSpec {
    const RESET_VALUE: u32 = 0;
}
