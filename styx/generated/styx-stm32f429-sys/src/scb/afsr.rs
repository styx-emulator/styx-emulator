// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `AFSR` reader"]
pub type R = crate::R<AfsrSpec>;
#[doc = "Register `AFSR` writer"]
pub type W = crate::W<AfsrSpec>;
#[doc = "Field `IMPDEF` reader - Implementation defined"]
pub type ImpdefR = crate::FieldReader<u32>;
#[doc = "Field `IMPDEF` writer - Implementation defined"]
pub type ImpdefW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Implementation defined"]
    #[inline(always)]
    pub fn impdef(&self) -> ImpdefR {
        ImpdefR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Implementation defined"]
    #[inline(always)]
    #[must_use]
    pub fn impdef(&mut self) -> ImpdefW<AfsrSpec> {
        ImpdefW::new(self, 0)
    }
}
#[doc = "Auxiliary fault status register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`afsr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`afsr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AfsrSpec;
impl crate::RegisterSpec for AfsrSpec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`afsr::R`](R) reader structure"]
impl crate::Readable for AfsrSpec {}
#[doc = "`write(|w| ..)` method takes [`afsr::W`](W) writer structure"]
impl crate::Writable for AfsrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets AFSR to value 0"]
impl crate::Resettable for AfsrSpec {
    const RESET_VALUE: u32 = 0;
}
