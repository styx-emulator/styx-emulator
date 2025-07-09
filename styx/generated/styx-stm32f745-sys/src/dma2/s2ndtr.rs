// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `S2NDTR` reader"]
pub type R = crate::R<S2ndtrSpec>;
#[doc = "Register `S2NDTR` writer"]
pub type W = crate::W<S2ndtrSpec>;
#[doc = "Field `NDT` reader - Number of data items to transfer"]
pub type NdtR = crate::FieldReader<u16>;
#[doc = "Field `NDT` writer - Number of data items to transfer"]
pub type NdtW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Number of data items to transfer"]
    #[inline(always)]
    pub fn ndt(&self) -> NdtR {
        NdtR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Number of data items to transfer"]
    #[inline(always)]
    #[must_use]
    pub fn ndt(&mut self) -> NdtW<S2ndtrSpec> {
        NdtW::new(self, 0)
    }
}
#[doc = "stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s2ndtr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s2ndtr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S2ndtrSpec;
impl crate::RegisterSpec for S2ndtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`s2ndtr::R`](R) reader structure"]
impl crate::Readable for S2ndtrSpec {}
#[doc = "`write(|w| ..)` method takes [`s2ndtr::W`](W) writer structure"]
impl crate::Writable for S2ndtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S2NDTR to value 0"]
impl crate::Resettable for S2ndtrSpec {
    const RESET_VALUE: u32 = 0;
}
