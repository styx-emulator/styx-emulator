// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ic_clr_gen_call` reader"]
pub type R = crate::R<IcClrGenCallSpec>;
#[doc = "Register `ic_clr_gen_call` writer"]
pub type W = crate::W<IcClrGenCallSpec>;
#[doc = "Field `clr_gen_call` reader - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
pub type ClrGenCallR = crate::BitReader;
#[doc = "Field `clr_gen_call` writer - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
pub type ClrGenCallW<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
    #[inline(always)]
    pub fn clr_gen_call(&self) -> ClrGenCallR {
        ClrGenCallR::new((self.bits & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Read this register to clear the GEN_CALL interrupt (bit 11) of ic_raw_intr_stat register."]
    #[inline(always)]
    #[must_use]
    pub fn clr_gen_call(&mut self) -> ClrGenCallW<IcClrGenCallSpec> {
        ClrGenCallW::new(self, 0)
    }
}
#[doc = "Clear GEN_CALL Interrupt Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ic_clr_gen_call::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IcClrGenCallSpec;
impl crate::RegisterSpec for IcClrGenCallSpec {
    type Ux = u32;
    const OFFSET: u64 = 104u64;
}
#[doc = "`read()` method returns [`ic_clr_gen_call::R`](R) reader structure"]
impl crate::Readable for IcClrGenCallSpec {}
#[doc = "`reset()` method sets ic_clr_gen_call to value 0"]
impl crate::Resettable for IcClrGenCallSpec {
    const RESET_VALUE: u32 = 0;
}
