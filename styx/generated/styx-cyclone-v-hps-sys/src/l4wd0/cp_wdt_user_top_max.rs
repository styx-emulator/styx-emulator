// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `cp_wdt_user_top_max` reader"]
pub type R = crate::R<CpWdtUserTopMaxSpec>;
#[doc = "Register `cp_wdt_user_top_max` writer"]
pub type W = crate::W<CpWdtUserTopMaxSpec>;
#[doc = "Field `cp_wdt_user_top_max` reader - Upper limit of Timeout Period parameters."]
pub type CpWdtUserTopMaxR = crate::FieldReader<u32>;
#[doc = "Field `cp_wdt_user_top_max` writer - Upper limit of Timeout Period parameters."]
pub type CpWdtUserTopMaxW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Upper limit of Timeout Period parameters."]
    #[inline(always)]
    pub fn cp_wdt_user_top_max(&self) -> CpWdtUserTopMaxR {
        CpWdtUserTopMaxR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Upper limit of Timeout Period parameters."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_user_top_max(&mut self) -> CpWdtUserTopMaxW<CpWdtUserTopMaxSpec> {
        CpWdtUserTopMaxW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_user_top_max::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpWdtUserTopMaxSpec;
impl crate::RegisterSpec for CpWdtUserTopMaxSpec {
    type Ux = u32;
    const OFFSET: u64 = 228u64;
}
#[doc = "`read()` method returns [`cp_wdt_user_top_max::R`](R) reader structure"]
impl crate::Readable for CpWdtUserTopMaxSpec {}
#[doc = "`reset()` method sets cp_wdt_user_top_max to value 0"]
impl crate::Resettable for CpWdtUserTopMaxSpec {
    const RESET_VALUE: u32 = 0;
}
