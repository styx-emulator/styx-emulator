// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `NLR` reader"]
pub type R = crate::R<NlrSpec>;
#[doc = "Register `NLR` writer"]
pub type W = crate::W<NlrSpec>;
#[doc = "Field `NL` reader - Number of lines"]
pub type NlR = crate::FieldReader<u16>;
#[doc = "Field `NL` writer - Number of lines"]
pub type NlW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `PL` reader - Pixel per lines"]
pub type PlR = crate::FieldReader<u16>;
#[doc = "Field `PL` writer - Pixel per lines"]
pub type PlW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:15 - Number of lines"]
    #[inline(always)]
    pub fn nl(&self) -> NlR {
        NlR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:29 - Pixel per lines"]
    #[inline(always)]
    pub fn pl(&self) -> PlR {
        PlR::new(((self.bits >> 16) & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Number of lines"]
    #[inline(always)]
    #[must_use]
    pub fn nl(&mut self) -> NlW<NlrSpec> {
        NlW::new(self, 0)
    }
    #[doc = "Bits 16:29 - Pixel per lines"]
    #[inline(always)]
    #[must_use]
    pub fn pl(&mut self) -> PlW<NlrSpec> {
        PlW::new(self, 16)
    }
}
#[doc = "number of line register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`nlr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`nlr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct NlrSpec;
impl crate::RegisterSpec for NlrSpec {
    type Ux = u32;
    const OFFSET: u64 = 68u64;
}
#[doc = "`read()` method returns [`nlr::R`](R) reader structure"]
impl crate::Readable for NlrSpec {}
#[doc = "`write(|w| ..)` method takes [`nlr::W`](W) writer structure"]
impl crate::Writable for NlrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets NLR to value 0"]
impl crate::Resettable for NlrSpec {
    const RESET_VALUE: u32 = 0;
}
