// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `indwrcnt` reader"]
pub type R = crate::R<IndwrcntSpec>;
#[doc = "Register `indwrcnt` writer"]
pub type W = crate::W<IndwrcntSpec>;
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
    pub fn value(&mut self) -> ValueW<IndwrcntSpec> {
        ValueW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`indwrcnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`indwrcnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IndwrcntSpec;
impl crate::RegisterSpec for IndwrcntSpec {
    type Ux = u32;
    const OFFSET: u64 = 124u64;
}
#[doc = "`read()` method returns [`indwrcnt::R`](R) reader structure"]
impl crate::Readable for IndwrcntSpec {}
#[doc = "`write(|w| ..)` method takes [`indwrcnt::W`](W) writer structure"]
impl crate::Writable for IndwrcntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets indwrcnt to value 0"]
impl crate::Resettable for IndwrcntSpec {
    const RESET_VALUE: u32 = 0;
}
