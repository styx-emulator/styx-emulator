// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `sramfill` reader"]
pub type R = crate::R<SramfillSpec>;
#[doc = "Register `sramfill` writer"]
pub type W = crate::W<SramfillSpec>;
#[doc = "Field `indrdpart` reader - "]
pub type IndrdpartR = crate::FieldReader<u16>;
#[doc = "Field `indrdpart` writer - "]
pub type IndrdpartW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `indwrpart` reader - "]
pub type IndwrpartR = crate::FieldReader<u16>;
#[doc = "Field `indwrpart` writer - "]
pub type IndwrpartW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15"]
    #[inline(always)]
    pub fn indrdpart(&self) -> IndrdpartR {
        IndrdpartR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31"]
    #[inline(always)]
    pub fn indwrpart(&self) -> IndwrpartR {
        IndwrpartR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15"]
    #[inline(always)]
    #[must_use]
    pub fn indrdpart(&mut self) -> IndrdpartW<SramfillSpec> {
        IndrdpartW::new(self, 0)
    }
    #[doc = "Bits 16:31"]
    #[inline(always)]
    #[must_use]
    pub fn indwrpart(&mut self) -> IndwrpartW<SramfillSpec> {
        IndwrpartW::new(self, 16)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`sramfill::R`](R).  See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct SramfillSpec;
impl crate::RegisterSpec for SramfillSpec {
    type Ux = u32;
    const OFFSET: u64 = 44u64;
}
#[doc = "`read()` method returns [`sramfill::R`](R) reader structure"]
impl crate::Readable for SramfillSpec {}
#[doc = "`reset()` method sets sramfill to value 0"]
impl crate::Resettable for SramfillSpec {
    const RESET_VALUE: u32 = 0;
}
