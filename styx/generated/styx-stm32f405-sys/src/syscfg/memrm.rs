// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MEMRM` reader"]
pub type R = crate::R<MemrmSpec>;
#[doc = "Register `MEMRM` writer"]
pub type W = crate::W<MemrmSpec>;
#[doc = "Field `MEM_MODE` reader - MEM_MODE"]
pub type MemModeR = crate::FieldReader;
#[doc = "Field `MEM_MODE` writer - MEM_MODE"]
pub type MemModeW<'a, REG> = crate::FieldWriter<'a, REG, 2>;
impl R {
    #[doc = "Bits 0:1 - MEM_MODE"]
    #[inline(always)]
    pub fn mem_mode(&self) -> MemModeR {
        MemModeR::new((self.bits & 3) as u8)
    }
}
impl W {
    #[doc = "Bits 0:1 - MEM_MODE"]
    #[inline(always)]
    #[must_use]
    pub fn mem_mode(&mut self) -> MemModeW<MemrmSpec> {
        MemModeW::new(self, 0)
    }
}
#[doc = "memory remap register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`memrm::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`memrm::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MemrmSpec;
impl crate::RegisterSpec for MemrmSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`memrm::R`](R) reader structure"]
impl crate::Readable for MemrmSpec {}
#[doc = "`write(|w| ..)` method takes [`memrm::W`](W) writer structure"]
impl crate::Writable for MemrmSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MEMRM to value 0"]
impl crate::Resettable for MemrmSpec {
    const RESET_VALUE: u32 = 0;
}
