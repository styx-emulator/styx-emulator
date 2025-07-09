// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `S5PAR` reader"]
pub type R = crate::R<S5parSpec>;
#[doc = "Register `S5PAR` writer"]
pub type W = crate::W<S5parSpec>;
#[doc = "Field `PA` reader - Peripheral address"]
pub type PaR = crate::FieldReader<u32>;
#[doc = "Field `PA` writer - Peripheral address"]
pub type PaW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Peripheral address"]
    #[inline(always)]
    pub fn pa(&self) -> PaR {
        PaR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Peripheral address"]
    #[inline(always)]
    #[must_use]
    pub fn pa(&mut self) -> PaW<S5parSpec> {
        PaW::new(self, 0)
    }
}
#[doc = "stream x peripheral address register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5par::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5par::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S5parSpec;
impl crate::RegisterSpec for S5parSpec {
    type Ux = u32;
    const OFFSET: u64 = 144u64;
}
#[doc = "`read()` method returns [`s5par::R`](R) reader structure"]
impl crate::Readable for S5parSpec {}
#[doc = "`write(|w| ..)` method takes [`s5par::W`](W) writer structure"]
impl crate::Writable for S5parSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S5PAR to value 0"]
impl crate::Resettable for S5parSpec {
    const RESET_VALUE: u32 = 0;
}
