// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_stop_det` reader"]
pub type R = crate::R<IcClrStopDetSpec>;
#[doc = "Register `ic_clr_stop_det` writer"]
pub type W = crate::W<IcClrStopDetSpec>;
#[doc = "Field `clr_stop_det` reader - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
pub type ClrStopDetR = crate::BitReader;
#[doc = "Field `clr_stop_det` writer - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
pub type ClrStopDetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_stop_det(&self) -> ClrStopDetR {
        ClrStopDetR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the clr_stop_det interrupt (bit 9) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_stop_det(&mut self) -> ClrStopDetW<IcClrStopDetSpec> {
        ClrStopDetW::new(self, 0)
    }
}
#[doc = "Clear Interrupts.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_stop_det::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrStopDetSpec;
impl crate::RegisterSpec for IcClrStopDetSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`ic_clr_stop_det::R`](R) reader structure"]
impl crate::Readable for IcClrStopDetSpec {}
#[doc = "`reset()` method sets ic_clr_stop_det to value 0"]
impl crate::Resettable for IcClrStopDetSpec {
    const RESET_VALUE: u32 = 0;
}
