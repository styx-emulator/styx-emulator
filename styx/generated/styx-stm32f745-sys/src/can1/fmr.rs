// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `FMR` reader"]
pub type R = crate::R<FmrSpec>;
#[doc = "Register `FMR` writer"]
pub type W = crate::W<FmrSpec>;
#[doc = "Field `FINIT` reader - FINIT"]
pub type FinitR = crate::BitReader;
#[doc = "Field `FINIT` writer - FINIT"]
pub type FinitW<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `CAN2SB` reader - CAN2SB"]
pub type Can2sbR = crate::FieldReader;
#[doc = "Field `CAN2SB` writer - CAN2SB"]
pub type Can2sbW<'a, REG> = crate::FieldWriter<'a, REG, 6>;
impl R {
    #[doc = "Bit 0 - FINIT"]
    #[inline(always)]
    pub fn finit(&self) -> FinitR {
        FinitR::new((self.bits & 1) != 0)
    }
    #[doc = "Bits 8:13 - CAN2SB"]
    #[inline(always)]
    pub fn can2sb(&self) -> Can2sbR {
        Can2sbR::new(((self.bits >> 8) & 0x3f) as u8)
    }
}
impl W {
    #[doc = "Bit 0 - FINIT"]
    #[inline(always)]
    #[must_use]
    pub fn finit(&mut self) -> FinitW<FmrSpec> {
        FinitW::new(self, 0)
    }
    #[doc = "Bits 8:13 - CAN2SB"]
    #[inline(always)]
    #[must_use]
    pub fn can2sb(&mut self) -> Can2sbW<FmrSpec> {
        Can2sbW::new(self, 8)
    }
}
#[doc = "filter master register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`fmr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`fmr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct FmrSpec;
impl crate::RegisterSpec for FmrSpec {
    type Ux = u32;
    const OFFSET: u64 = 512u64;
}
#[doc = "`read()` method returns [`fmr::R`](R) reader structure"]
impl crate::Readable for FmrSpec {}
#[doc = "`write(|w| ..)` method takes [`fmr::W`](W) writer structure"]
impl crate::Writable for FmrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets FMR to value 0x2a1c_0e01"]
impl crate::Resettable for FmrSpec {
    const RESET_VALUE: u32 = 0x2a1c_0e01;
}
