// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `PSMKR` reader"]
pub type R = crate::R<PsmkrSpec>;
#[doc = "Register `PSMKR` writer"]
pub type W = crate::W<PsmkrSpec>;
#[doc = "Field `MASK` reader - Status mask"]
pub type MaskR = crate::FieldReader<u32>;
#[doc = "Field `MASK` writer - Status mask"]
pub type MaskW<'a, REG> = crate::FieldWriter<'a, REG, 32, u32>;
impl R {
    #[doc = "Bits 0:31 - Status mask"]
    #[inline(always)]
    pub fn mask(&self) -> MaskR {
        MaskR::new(self.bits)
    }
}
impl W {
    #[doc = "Bits 0:31 - Status mask"]
    #[inline(always)]
    #[must_use]
    pub fn mask(&mut self) -> MaskW<PsmkrSpec> {
        MaskW::new(self, 0)
    }
}
#[doc = "polling status mask register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`psmkr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`psmkr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct PsmkrSpec;
impl crate::RegisterSpec for PsmkrSpec {
    type Ux = u32;
    const OFFSET: u64 = 36u64;
}
#[doc = "`read()` method returns [`psmkr::R`](R) reader structure"]
impl crate::Readable for PsmkrSpec {}
#[doc = "`write(|w| ..)` method takes [`psmkr::W`](W) writer structure"]
impl crate::Writable for PsmkrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets PSMKR to value 0"]
impl crate::Resettable for PsmkrSpec {
    const RESET_VALUE: u32 = 0;
}
