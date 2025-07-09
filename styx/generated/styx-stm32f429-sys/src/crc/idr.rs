// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `IDR` reader"]
pub type R = crate::R<IdrSpec>;
#[doc = "Register `IDR` writer"]
pub type W = crate::W<IdrSpec>;
#[doc = "Field `IDR` reader - Independent Data register"]
pub type IdrR = crate::FieldReader;
#[doc = "Field `IDR` writer - Independent Data register"]
pub type IdrW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - Independent Data register"]
    #[inline(always)]
    pub fn idr(&self) -> IdrR {
        IdrR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - Independent Data register"]
    #[inline(always)]
    #[must_use]
    pub fn idr(&mut self) -> IdrW<IdrSpec> {
        IdrW::new(self, 0)
    }
}
#[doc = "Independent Data register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`idr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`idr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct IdrSpec;
impl crate::RegisterSpec for IdrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`idr::R`](R) reader structure"]
impl crate::Readable for IdrSpec {}
#[doc = "`write(|w| ..)` method takes [`idr::W`](W) writer structure"]
impl crate::Writable for IdrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets IDR to value 0"]
impl crate::Resettable for IdrSpec {
    const RESET_VALUE: u32 = 0;
}
