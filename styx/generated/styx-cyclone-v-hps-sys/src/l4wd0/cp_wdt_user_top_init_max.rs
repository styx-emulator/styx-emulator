// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `cp_wdt_user_top_init_max` reader"]
pub type R = crate::R<CpWdtUserTopInitMaxSpec>;
#[doc = "Register `cp_wdt_user_top_init_max` writer"]
pub type W = crate::W<CpWdtUserTopInitMaxSpec>;
#[doc = "Field `cp_wdt_user_top_init_max` reader - Upper limit of Initial Timeout Period parameters."]
pub type CpWdtUserTopInitMaxR = crate::FieldReader<u32>;
#[doc = "Field `cp_wdt_user_top_init_max` writer - Upper limit of Initial Timeout Period parameters."]
pub type CpWdtUserTopInitMaxW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Upper limit of Initial Timeout Period parameters."]
    #[inline(always)]
    pub fn cp_wdt_user_top_init_max(&self) -> CpWdtUserTopInitMaxR {
        CpWdtUserTopInitMaxR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Upper limit of Initial Timeout Period parameters."]
    #[inline(always)]
    #[must_use]
    pub fn cp_wdt_user_top_init_max(&mut self) -> CpWdtUserTopInitMaxW<CpWdtUserTopInitMaxSpec> {
        CpWdtUserTopInitMaxW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cp_wdt_user_top_init_max::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpWdtUserTopInitMaxSpec;
impl crate::RegisterSpec for CpWdtUserTopInitMaxSpec {
    type Ux = u32;
    const OFFSET: u64 = 232u64;
}
#[doc = "`read()` method returns [`cp_wdt_user_top_init_max::R`](R) reader structure"]
impl crate::Readable for CpWdtUserTopInitMaxSpec {}
#[doc = "`reset()` method sets cp_wdt_user_top_init_max to value 0"]
impl crate::Resettable for CpWdtUserTopInitMaxSpec {
    const RESET_VALUE: u32 = 0;
}
