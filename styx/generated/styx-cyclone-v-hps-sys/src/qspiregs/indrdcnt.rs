// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `indrdcnt` reader"]
pub type R = crate::R<IndrdcntSpec>;
#[doc = "Register `indrdcnt` writer"]
pub type W = crate::W<IndrdcntSpec>;
#[doc = "Field `value` reader - This is the number of bytes that the indirect access will consume. This can be bigger than the configured size of SRAM."]
pub type ValueR = crate::FieldReader<u32>;
#[doc = "Field `value` writer - This is the number of bytes that the indirect access will consume. This can be bigger than the configured size of SRAM."]
pub type ValueW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - This is the number of bytes that the indirect access will consume. This can be bigger than the configured size of SRAM."]
    #[inline(always)]
    pub fn value(&self) -> ValueR {
        ValueR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - This is the number of bytes that the indirect access will consume. This can be bigger than the configured size of SRAM."]
    #[inline(always)]
    #[must_use]
    pub fn value(&mut self) -> ValueW<IndrdcntSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indrdcnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indrdcnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndrdcntSpec;
impl crate::RegisterSpec for IndrdcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 108u64;
}
#[doc = "`read()` method returns [`indrdcnt::R`](R) reader structure"]
impl crate::Readable for IndrdcntSpec {}
#[doc = "`write(|w| ..)` method takes [`indrdcnt::W`](W) writer structure"]
impl crate::Writable for IndrdcntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets indrdcnt to value 0"]
impl crate::Resettable for IndrdcntSpec {
    const RESET_VALUE: u32 = 0;
}
