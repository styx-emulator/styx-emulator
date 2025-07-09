// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `L1PFCR` reader"]
pub type R = crate::R<L1pfcrSpec>;
#[doc = "Register `L1PFCR` writer"]
pub type W = crate::W<L1pfcrSpec>;
#[doc = "Field `PF` reader - Pixel Format"]
pub type PfR = crate::FieldReader;
#[doc = "Field `PF` writer - Pixel Format"]
pub type PfW<'a, REG> = crate::FieldWriter<'a, REG, 3>;
impl R {
    #[doc = "Bits 0:2 - Pixel Format"]
    #[inline(always)]
    pub fn pf(&self) -> PfR {
        PfR::new((self.bits & 7) as u8)
    }
}
impl W {
    #[doc = "Bits 0:2 - Pixel Format"]
    #[inline(always)]
    #[must_use]
    pub fn pf(&mut self) -> PfW<L1pfcrSpec> {
        PfW::new(self, 0)
    }
}
#[doc = "Layerx Pixel Format Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`l1pfcr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`l1pfcr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct L1pfcrSpec;
impl crate::RegisterSpec for L1pfcrSpec {
    type Ux = u32;
    const OFFSET: u64 = 148u64;
}
#[doc = "`read()` method returns [`l1pfcr::R`](R) reader structure"]
impl crate::Readable for L1pfcrSpec {}
#[doc = "`write(|w| ..)` method takes [`l1pfcr::W`](W) writer structure"]
impl crate::Writable for L1pfcrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets L1PFCR to value 0"]
impl crate::Resettable for L1pfcrSpec {
    const RESET_VALUE: u32 = 0;
}
