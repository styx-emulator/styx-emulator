// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CMP` reader"]
pub type R = crate::R<CmpSpec>;
#[doc = "Register `CMP` writer"]
pub type W = crate::W<CmpSpec>;
#[doc = "Field `CMP` reader - Compare value"]
pub type CmpR = crate::FieldReader<u16>;
#[doc = "Field `CMP` writer - Compare value"]
pub type CmpW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Compare value"]
    #[inline(always)]
    pub fn cmp(&self) -> CmpR {
        CmpR::new((self.bits & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Compare value"]
    #[inline(always)]
    #[must_use]
    pub fn cmp(&mut self) -> CmpW<CmpSpec> {
        CmpW::new(self, 0)
    }
}
#[doc = "Compare Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cmp::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cmp::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CmpSpec;
impl crate::RegisterSpec for CmpSpec {
    type Ux = u32;
    const OFFSET: u64 = 20u64;
}
#[doc = "`read()` method returns [`cmp::R`](R) reader structure"]
impl crate::Readable for CmpSpec {}
#[doc = "`write(|w| ..)` method takes [`cmp::W`](W) writer structure"]
impl crate::Writable for CmpSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CMP to value 0"]
impl crate::Resettable for CmpSpec {
    const RESET_VALUE: u32 = 0;
}
