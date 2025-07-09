// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `CNT` reader"]
pub type R = crate::R<CntSpec>;
#[doc = "Register `CNT` writer"]
pub type W = crate::W<CntSpec>;
#[doc = "Field `CNT_L` reader - Low counter value"]
pub type CntLR = crate::FieldReader<u16>;
#[doc = "Field `CNT_L` writer - Low counter value"]
pub type CntLW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
#[doc = "Field `CNT_H` reader - High counter value"]
pub type CntHR = crate::FieldReader<u16>;
#[doc = "Field `CNT_H` writer - High counter value"]
pub type CntHW<'a, REG> = crate::FieldWriter<'a, REG, 16, u16>;
impl R {
    #[doc = "Bits 0:15 - Low counter value"]
    #[inline(always)]
    pub fn cnt_l(&self) -> CntLR {
        CntLR::new((self.bits & 0xffff) as u16)
    }
    #[doc = "Bits 16:31 - High counter value"]
    #[inline(always)]
    pub fn cnt_h(&self) -> CntHR {
        CntHR::new(((self.bits >> 16) & 0xffff) as u16)
    }
}
impl W {
    #[doc = "Bits 0:15 - Low counter value"]
    #[inline(always)]
    #[must_use]
    pub fn cnt_l(&mut self) -> CntLW<CntSpec> {
        CntLW::new(self, 0)
    }
    #[doc = "Bits 16:31 - High counter value"]
    #[inline(always)]
    #[must_use]
    pub fn cnt_h(&mut self) -> CntHW<CntSpec> {
        CntHW::new(self, 16)
    }
}
#[doc = "counter\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`cnt::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`cnt::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct CntSpec;
impl crate::RegisterSpec for CntSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`cnt::R`](R) reader structure"]
impl crate::Readable for CntSpec {}
#[doc = "`write(|w| ..)` method takes [`cnt::W`](W) writer structure"]
impl crate::Writable for CntSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets CNT to value 0"]
impl crate::Resettable for CntSpec {
    const RESET_VALUE: u32 = 0;
}
