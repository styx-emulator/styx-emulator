// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CCR3` reader"]
pub type R = crate::R<Ccr3Spec>;
#[doc = "Register `CCR3` writer"]
pub type W = crate::W<Ccr3Spec>;
#[doc = "Field `CCR3_L` reader - Low Capture/Compare value"]
pub type Ccr3LR = crate::FieldReader<u16>;
#[doc = "Field `CCR3_L` writer - Low Capture/Compare value"]
pub type Ccr3LW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `CCR3_H` reader - High Capture/Compare value"]
pub type Ccr3HR = crate::FieldReader<u16>;
#[doc = "Field `CCR3_H` writer - High Capture/Compare value"]
pub type Ccr3HW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Low Capture/Compare value"]
    #[inline(always)]
    pub fn ccr3_l(&self) -> Ccr3LR {
        Ccr3LR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - High Capture/Compare value"]
    #[inline(always)]
    pub fn ccr3_h(&self) -> Ccr3HR {
        Ccr3HR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Low Capture/Compare value"]
    #[inline(always)]
    #[must_use]
    pub fn ccr3_l(&mut self) -> Ccr3LW<Ccr3Spec> {
        Ccr3LW::new(self, 0)
    }
    #[doc = "Bits 16:31 - High Capture/Compare value"]
    #[inline(always)]
    #[must_use]
    pub fn ccr3_h(&mut self) -> Ccr3HW<Ccr3Spec> {
        Ccr3HW::new(self, 16)
    }
}
#[doc = "capture/compare register 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`ccr3::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`ccr3::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct Ccr3Spec;
impl crate::RegisterSpec for Ccr3Spec {
    type Ux = u32;
    const OFFSET: u64 = 60u64;
}
#[doc = "`read()` method returns [`ccr3::R`](R) reader structure"]
impl crate::Readable for Ccr3Spec {}
#[doc = "`write(|w| ..)` method takes [`ccr3::W`](W) writer structure"]
impl crate::Writable for Ccr3Spec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CCR3 to value 0"]
impl crate::Resettable for Ccr3Spec {
    const RESET_VALUE: u32 = 0;
}
