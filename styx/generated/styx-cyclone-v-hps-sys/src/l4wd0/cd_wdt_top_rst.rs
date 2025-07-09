// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `cd_wdt_top_rst` reader"]
pub type R = crate::R<CdWdtTopRstSpec>;
#[doc = "Register `cd_wdt_top_rst` writer"]
pub type W = crate::W<CdWdtTopRstSpec>;
#[doc = "Field `cd_wdt_top_rst` reader - Contains the reset value of the WDT_TORR register."]
pub type CdWdtTopRstR = crate::FieldReader<u32>;
#[doc = "Field `cd_wdt_top_rst` writer - Contains the reset value of the WDT_TORR register."]
pub type CdWdtTopRstW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Contains the reset value of the WDT_TORR register."]
    #[inline(always)]
    pub fn cd_wdt_top_rst(&self) -> CdWdtTopRstR {
        CdWdtTopRstR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Contains the reset value of the WDT_TORR register."]
    #[inline(always)]
    #[must_use]
    pub fn cd_wdt_top_rst(&mut self) -> CdWdtTopRstW<CdWdtTopRstSpec> {
        CdWdtTopRstW::new(self, 0)
    }
}
#[doc = "This is a constant read-only register that contains encoded information about the component's parameter settings.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cd_wdt_top_rst::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CdWdtTopRstSpec;
impl crate::RegisterSpec for CdWdtTopRstSpec {
    type Ux = u32;
    const OFFSET: u64 = 236u64;
}
#[doc = "`read()` method returns [`cd_wdt_top_rst::R`](R) reader structure"]
impl crate::Readable for CdWdtTopRstSpec {}
#[doc = "`reset()` method sets cd_wdt_top_rst to value 0xff"]
impl crate::Resettable for CdWdtTopRstSpec {
    const RESET_VALUE: u32 = 0xff;
}
