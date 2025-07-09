// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCR4` reader"]
pub type R = crate::R<Ccr4Spec>;
#[doc = "Register `CCR4` writer"]
pub type W = crate::W<Ccr4Spec>;
#[doc = "Field `CCR4_L` reader - Low Capture/Compare value"]
pub type Ccr4LR = crate::FieldReader<u16>;
#[doc = "Field `CCR4_L` writer - Low Capture/Compare value"]
pub type Ccr4LW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `CCR4_H` reader - High Capture/Compare value"]
pub type Ccr4HR = crate::FieldReader<u16>;
#[doc = "Field `CCR4_H` writer - High Capture/Compare value"]
pub type Ccr4HW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Low Capture/Compare value"]
    #[inline(always)]
    pub fn ccr4_l(&self) -> Ccr4LR {
        Ccr4LR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - High Capture/Compare value"]
    #[inline(always)]
    pub fn ccr4_h(&self) -> Ccr4HR {
        Ccr4HR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Low Capture/Compare value"]
    #[inline(always)]
    #[must_use]
    pub fn ccr4_l(&mut self) -> Ccr4LW<Ccr4Spec> {
        Ccr4LW::new(self, 0)
    }
    #[doc = "Bits 16:31 - High Capture/Compare value"]
    #[inline(always)]
    #[must_use]
    pub fn ccr4_h(&mut self) -> Ccr4HW<Ccr4Spec> {
        Ccr4HW::new(self, 16)
    }
}
#[doc = "capture/compare register 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccr4::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccr4::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ccr4Spec;
impl crate::RegisterSpec for Ccr4Spec {
    type Ux = u32;
    const OFFSET: u64 = 64u64;
}
#[doc = "`read()` method returns [`ccr4::R`](R) reader structure"]
impl crate::Readable for Ccr4Spec {}
#[doc = "`write(|w| ..)` method takes [`ccr4::W`](W) writer structure"]
impl crate::Writable for Ccr4Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCR4 to value 0"]
impl crate::Resettable for Ccr4Spec {
    const RESET_VALUE: u32 = 0;
}
