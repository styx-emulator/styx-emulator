// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OPFCCR` reader"]
pub type R = crate::R<OpfccrSpec>;
#[doc = "Register `OPFCCR` writer"]
pub type W = crate::W<OpfccrSpec>;
#[doc = "Field `CM` reader - Color mode"]
pub type CmR = crate::FieldReader;
#[doc = "Field `CM` writer - Color mode"]
pub type CmW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:2 - Color mode"]
    #[inline(always)]
    pub fn cm(&self) -> CmR {
        CmR::new((self.bits & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - Color mode"]
    #[inline(always)]
    #[must_use]
    pub fn cm(&mut self) -> CmW<OpfccrSpec> {
        CmW::new(self, 0)
    }
}
#[doc = "output PFC control register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`opfccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`opfccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OpfccrSpec;
impl crate::RegisterSpec for OpfccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 52u64;
}
#[doc = "`read()` method returns [`opfccr::R`](R) reader structure"]
impl crate::Readable for OpfccrSpec {}
#[doc = "`write(|w| ..)` method takes [`opfccr::W`](W) writer structure"]
impl crate::Writable for OpfccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OPFCCR to value 0"]
impl crate::Resettable for OpfccrSpec {
    const RESET_VALUE: u32 = 0;
}
