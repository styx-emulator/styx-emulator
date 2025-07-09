// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `OOR` reader"]
pub type R = crate::R<OorSpec>;
#[doc = "Register `OOR` writer"]
pub type W = crate::W<OorSpec>;
#[doc = "Field `LO` reader - Line Offset"]
pub type LoR = crate::FieldReader<u16>;
#[doc = "Field `LO` writer - Line Offset"]
pub type LoW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:13 - Line Offset"]
    #[inline(always)]
    pub fn lo(&self) -> LoR {
        LoR::new((self.bits & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:13 - Line Offset"]
    #[inline(always)]
    #[must_use]
    pub fn lo(&mut self) -> LoW<OorSpec> {
        LoW::new(self, 0)
    }
}
#[doc = "output offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`oor::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`oor::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct OorSpec;
impl crate::RegisterSpec for OorSpec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`oor::R`](R) reader structure"]
impl crate::Readable for OorSpec {}
#[doc = "`write(|w| ..)` method takes [`oor::W`](W) writer structure"]
impl crate::Writable for OorSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets OOR to value 0"]
impl crate::Resettable for OorSpec {
    const RESET_VALUE: u32 = 0;
}
