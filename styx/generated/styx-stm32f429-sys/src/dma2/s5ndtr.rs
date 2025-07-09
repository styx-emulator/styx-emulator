// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `S5NDTR` reader"]
pub type R = crate::R<S5ndtrSpec>;
#[doc = "Register `S5NDTR` writer"]
pub type W = crate::W<S5ndtrSpec>;
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
    pub fn ndt(&mut self) -> NdtW<S5ndtrSpec> {
        NdtW::new(self, 0)
    }
}
#[doc = "stream x number of data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`s5ndtr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`s5ndtr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct S5ndtrSpec;
impl crate::RegisterSpec for S5ndtrSpec {
    type Ux = u32;
    const OFFSET: u64 = 140u64;
}
#[doc = "`read()` method returns [`s5ndtr::R`](R) reader structure"]
impl crate::Readable for S5ndtrSpec {}
#[doc = "`write(|w| ..)` method takes [`s5ndtr::W`](W) writer structure"]
impl crate::Writable for S5ndtrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets S5NDTR to value 0"]
impl crate::Resettable for S5ndtrSpec {
    const RESET_VALUE: u32 = 0;
}
