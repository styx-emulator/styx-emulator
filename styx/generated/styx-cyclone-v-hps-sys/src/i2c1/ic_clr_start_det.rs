// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_start_det` reader"]
pub type R = crate::R<IcClrStartDetSpec>;
#[doc = "Register `ic_clr_start_det` writer"]
pub type W = crate::W<IcClrStartDetSpec>;
#[doc = "Field `clr_start_det` reader - Read this register to clear the start_det interrupt (bit 10) of the ic_raw_intr_stat register."]
pub type ClrStartDetR = crate::BitReader;
#[doc = "Field `clr_start_det` writer - Read this register to clear the start_det interrupt (bit 10) of the ic_raw_intr_stat register."]
pub type ClrStartDetW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the start_det interrupt (bit 10) of the ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_start_det(&self) -> ClrStartDetR {
        ClrStartDetR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the start_det interrupt (bit 10) of the ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_start_det(&mut self) -> ClrStartDetW<IcClrStartDetSpec> {
        ClrStartDetW::new(self, 0)
    }
}
#[doc = "Clears START_DET Interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_start_det::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrStartDetSpec;
impl crate::RegisterSpec for IcClrStartDetSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`ic_clr_start_det::R`](R) reader structure"]
impl crate::Readable for IcClrStartDetSpec {}
#[doc = "`reset()` method sets ic_clr_start_det to value 0"]
impl crate::Resettable for IcClrStartDetSpec {
    const RESET_VALUE: u32 = 0;
}
