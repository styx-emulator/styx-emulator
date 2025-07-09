// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CPACR` reader"]
pub type R = crate::R<CpacrSpec>;
#[doc = "Register `CPACR` writer"]
pub type W = crate::W<CpacrSpec>;
#[doc = "Field `CP` reader - CP"]
pub type CpR = crate::FieldReader;
#[doc = "Field `CP` writer - CP"]
pub type CpW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 20:23 - CP"]
    #[inline(always)]
    pub fn cp(&self) -> CpR {
        CpR::new(((self.bits >> 20) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 20:23 - CP"]
    #[inline(always)]
    #[must_use]
    pub fn cp(&mut self) -> CpW<CpacrSpec> {
        CpW::new(self, 20)
    }
}
#[doc = "Coprocessor access control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cpacr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cpacr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CpacrSpec;
impl crate::RegisterSpec for CpacrSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`cpacr::R`](R) reader structure"]
impl crate::Readable for CpacrSpec {}
#[doc = "`write(|w| ..)` method takes [`cpacr::W`](W) writer structure"]
impl crate::Writable for CpacrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CPACR to value 0"]
impl crate::Resettable for CpacrSpec {
    const RESET_VALUE: u32 = 0;
}
