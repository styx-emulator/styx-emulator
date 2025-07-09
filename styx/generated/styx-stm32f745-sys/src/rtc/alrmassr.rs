// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `ALRMASSR` reader"]
pub type R = crate::R<AlrmassrSpec>;
#[doc = "Register `ALRMASSR` writer"]
pub type W = crate::W<AlrmassrSpec>;
#[doc = "Field `SS` reader - Sub seconds value"]
pub type SsR = crate::FieldReader<u16>;
#[doc = "Field `SS` writer - Sub seconds value"]
pub type SsW<'a, REG> = crate::FieldWriter<'a, REG, 15, u16>;
#[doc = "Field `MASKSS` reader - Mask the most-significant bits starting at this bit"]
pub type MaskssR = crate::FieldReader;
#[doc = "Field `MASKSS` writer - Mask the most-significant bits starting at this bit"]
pub type MaskssW<'a, REG> = crate::FieldWriter<'a, REG, 4>;
impl R {
    #[doc = "Bits 0:14 - Sub seconds value"]
    #[inline(always)]
    pub fn ss(&self) -> SsR {
        SsR::new((self.bits & 0x7fff) as u16)
    }
    #[doc = "Bits 24:27 - Mask the most-significant bits starting at this bit"]
    #[inline(always)]
    pub fn maskss(&self) -> MaskssR {
        MaskssR::new(((self.bits >> 24) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:14 - Sub seconds value"]
    #[inline(always)]
    #[must_use]
    pub fn ss(&mut self) -> SsW<AlrmassrSpec> {
        SsW::new(self, 0)
    }
    #[doc = "Bits 24:27 - Mask the most-significant bits starting at this bit"]
    #[inline(always)]
    #[must_use]
    pub fn maskss(&mut self) -> MaskssW<AlrmassrSpec> {
        MaskssW::new(self, 24)
    }
}
#[doc = "alarm A sub second register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`alrmassr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`alrmassr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct AlrmassrSpec;
impl crate::RegisterSpec for AlrmassrSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`alrmassr::R`](R) reader structure"]
impl crate::Readable for AlrmassrSpec {}
#[doc = "`write(|w| ..)` method takes [`alrmassr::W`](W) writer structure"]
impl crate::Writable for AlrmassrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets ALRMASSR to value 0"]
impl crate::Resettable for AlrmassrSpec {
    const RESET_VALUE: u32 = 0;
}
