// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BGOR` reader"]
pub type R = crate::R<BgorSpec>;
#[doc = "Register `BGOR` writer"]
pub type W = crate::W<BgorSpec>;
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
    pub fn lo(&mut self) -> LoW<BgorSpec> {
        LoW::new(self, 0)
    }
}
#[doc = "background offset register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bgor::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bgor::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BgorSpec;
impl crate::RegisterSpec for BgorSpec {
    type Ux = u32;
    const OFFSET: u64 = 24u64;
}
#[doc = "`read()` method returns [`bgor::R`](R) reader structure"]
impl crate::Readable for BgorSpec {}
#[doc = "`write(|w| ..)` method takes [`bgor::W`](W) writer structure"]
impl crate::Writable for BgorSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BGOR to value 0"]
impl crate::Resettable for BgorSpec {
    const RESET_VALUE: u32 = 0;
}
