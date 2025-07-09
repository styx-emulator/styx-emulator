// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `BCCR` reader"]
pub type R = crate::R<BccrSpec>;
#[doc = "Register `BCCR` writer"]
pub type W = crate::W<BccrSpec>;
#[doc = "Field `BC` reader - Background Color Red value"]
pub type BcR = crate::FieldReader<u32>;
#[doc = "Field `BC` writer - Background Color Red value"]
pub type BcW<'a, REG> = crate::FieldWriter<'a, REG, 24, u32>;
impl R {
    #[doc = "Bits 0:23 - Background Color Red value"]
    #[inline(always)]
    pub fn bc(&self) -> BcR {
        BcR::new(self.bits & 0x00ff_ffff)
    }
}
impl W {
    #[doc = "Bits 0:23 - Background Color Red value"]
    #[inline(always)]
    #[must_use]
    pub fn bc(&mut self) -> BcW<BccrSpec> {
        BcW::new(self, 0)
    }
}
#[doc = "Background Color Configuration Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`bccr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`bccr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct BccrSpec;
impl crate::RegisterSpec for BccrSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`bccr::R`](R) reader structure"]
impl crate::Readable for BccrSpec {}
#[doc = "`write(|w| ..)` method takes [`bccr::W`](W) writer structure"]
impl crate::Writable for BccrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets BCCR to value 0"]
impl crate::Resettable for BccrSpec {
    const RESET_VALUE: u32 = 0;
}
