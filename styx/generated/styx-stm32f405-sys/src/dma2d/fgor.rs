// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FGOR` reader"]
pub type R = crate::R<FgorSpec>;
#[doc = "Register `FGOR` writer"]
pub type W = crate::W<FgorSpec>;
#[doc = "Field `LO` reader - Line offset"]
pub type LoR = crate::FieldReader<u16>;
#[doc = "Field `LO` writer - Line offset"]
pub type LoW<'a, REG> = crate::FieldWriter<'a, REG, 14, u16>;
impl R {
    #[doc = "Bits 0:13 - Line offset"]
    #[inline(always)]
    pub fn lo(&self) -> LoR {
        LoR::new((self.bits & 0x3fff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:13 - Line offset"]
    #[inline(always)]
    #[must_use]
    pub fn lo(&mut self) -> LoW<FgorSpec> {
        LoW::new(self, 0)
    }
}
#[doc = "foreground offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fgor::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fgor::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FgorSpec;
impl crate::RegisterSpec for FgorSpec {
    type Ux = u32;
    const OFFSET: u64 = 16u64;
}
#[doc = "`read()` method returns [`fgor::R`](R) reader structure"]
impl crate::Readable for FgorSpec {}
#[doc = "`write(|w| ..)` method takes [`fgor::W`](W) writer structure"]
impl crate::Writable for FgorSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FGOR to value 0"]
impl crate::Resettable for FgorSpec {
    const RESET_VALUE: u32 = 0;
}
